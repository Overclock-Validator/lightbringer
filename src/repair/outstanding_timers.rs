use std::{
    cell::RefCell,
    collections::BTreeMap,
    net::IpAddr,
    rc::Rc,
    time::{Duration, Instant},
};

use glommio::{
    channels::local_channel::{LocalReceiver, LocalSender},
    enclose,
    timer::TimerActionOnce,
};
use kanal::AsyncSender;
use solana_ledger::shred::Nonce;

use crate::{
    overlay::repair::{PeerSample, RepairPeerSource, RepairRoute, RepairTarget},
    repair::{peer_manager::RepairRequestMapper, socket::RepairSocketRequestBatch},
};

use super::OutstandingRequestKind;

const REPAIR_REQUEST_TIMEOUT: Duration = Duration::from_millis(200);

// slot(8) | nonce(4) | route tag(1) | ip(16) | port(2) or pubkey(32)
type RepairKeyRaw = [u8; 45];

/// Correlation key for an outstanding request: the route is what the
/// response side can actually observe — a UDP source address, or the
/// overlay peer identity the stream ran to.
fn repair_key(slot: u64, nonce: u32, route: RepairRoute) -> RepairKeyRaw {
    let mut bytes = [0u8; 45];
    // Big-endian so lexicographic key ordering matches numeric slot ordering,
    // which is required for prefix range queries in contains()/remove_slot().
    bytes[..8].copy_from_slice(&slot.to_be_bytes());
    bytes[8..12].copy_from_slice(&nonce.to_le_bytes());

    match route {
        RepairRoute::Addr(socket) => {
            bytes[12] = 0;
            let mut ip_bytes = [0u8; 16];
            match socket.ip() {
                IpAddr::V4(ipv4) => {
                    ip_bytes[..4].copy_from_slice(&ipv4.octets());
                }
                IpAddr::V6(ipv6) => {
                    ip_bytes.copy_from_slice(&ipv6.octets());
                }
            }
            bytes[13..29].copy_from_slice(&ip_bytes);
            bytes[29..31].copy_from_slice(&socket.port().to_le_bytes());
        }
        RepairRoute::Peer(pubkey) => {
            bytes[12] = 1;
            bytes[13..45].copy_from_slice(pubkey.as_ref());
        }
    }

    bytes
}

pub struct OutstandingRequest {
    pub kind: OutstandingRequestKind,
    pub nonce: Nonce,
    pub slot: u64,
    pub shred: u32,
    pub target: RepairTarget,
    pub sent_at: Instant,
}

pub enum OutstandingRequestMsg {
    New(OutstandingRequest),
    Timeout(OutstandingRequest),
}

#[derive(Default)]
pub struct OutstandingTimerStore(
    BTreeMap<RepairKeyRaw, (OutstandingRequestKind, u32, TimerActionOnce<()>, Instant, RepairTarget)>,
);

struct OutstandingTimer {
    kind: OutstandingRequestKind,
    nonce: Nonce,
    slot: u64,
    shred_index: u32,
    target: RepairTarget,
    sent_at: Instant,
    timer: TimerActionOnce<()>,
}

impl OutstandingTimerStore {
    fn insert(&mut self, request: OutstandingTimer) {
        self.0.insert(
            repair_key(request.slot, request.nonce, request.target.route()),
            (
                request.kind,
                request.shred_index,
                request.timer,
                request.sent_at,
                request.target,
            ),
        );
    }

    /// Removes an outstanding timer.
    /// Returns the request kind, shred index, send time, and target.
    pub fn remove(
        &mut self,
        slot: u64,
        nonce: Nonce,
        route: RepairRoute,
    ) -> Option<(OutstandingRequestKind, u32, Instant, RepairTarget)> {
        let (kind, shred_index, timer, sent_at, target) =
            self.0.remove(&repair_key(slot, nonce, route))?;
        timer.destroy();

        Some((kind, shred_index, sent_at, target))
    }

    pub fn contains(&self, slot: u64) -> bool {
        let mut prefix_key = [0u8; 45];
        prefix_key[..8].copy_from_slice(&slot.to_be_bytes());
        let mut prefix_key_limit = [0u8; 45];
        prefix_key_limit[..8].copy_from_slice(&slot.saturating_add(1).to_be_bytes());
        self.0.range(prefix_key..prefix_key_limit).count() != 0
    }

    pub fn remove_slot(&mut self, slot: u64) {
        let mut prefix_key = [0u8; 45];
        prefix_key[..8].copy_from_slice(&slot.to_be_bytes());
        let mut prefix_key_limit = [0u8; 45];
        prefix_key_limit[..8].copy_from_slice(&slot.saturating_add(1).to_be_bytes());
        let drain_iter = self.0.extract_if(prefix_key..prefix_key_limit, |_, _| true);
        for (_, (_, _, timer, _, _)) in drain_iter {
            timer.destroy();
        }
    }
}

pub async fn start_outstanding_requests_loop<S: RepairPeerSource>(
    mut mapper: RepairRequestMapper<S>,
    outstanding_timers: Rc<RefCell<OutstandingTimerStore>>,
    outstanding_tx: Rc<LocalSender<OutstandingRequestMsg>>,
    outstanding_rx: LocalReceiver<OutstandingRequestMsg>,
    peer_sample: Rc<RefCell<PeerSample>>,
    send_socket: AsyncSender<RepairSocketRequestBatch>,
) {
    while let Some(msg) = outstanding_rx.recv().await {
        match msg {
            OutstandingRequestMsg::New(req) => {
                peer_sample.borrow_mut().record_request(req.target.pubkey());
                let sent_at = req.sent_at;
                let (slot, nonce, target, kind, shred) =
                    (req.slot, req.nonce, req.target, req.kind, req.shred);
                outstanding_timers.borrow_mut().insert(OutstandingTimer {
                    slot,
                    nonce,
                    target,
                    kind,
                    shred_index: shred,
                    timer: TimerActionOnce::do_in(
                        REPAIR_REQUEST_TIMEOUT,
                        enclose!((outstanding_tx) async move {
                            _ = outstanding_tx.try_send(OutstandingRequestMsg::Timeout(req));
                        }),
                    ),
                    sent_at,
                });
            }
            OutstandingRequestMsg::Timeout(mut req) => {
                let removed = outstanding_timers
                    .borrow_mut()
                    .remove(req.slot, req.nonce, req.target.route());
                if removed.is_none() {
                    // Already fulfilled by a response
                    continue;
                }
                peer_sample.borrow_mut().record_timeout(req.target.pubkey());

                let Some((target, nonce, raw_req)) = (match req.kind {
                    OutstandingRequestKind::WindowIndex => {
                        mapper.map_bounded_shred(req.slot, req.shred)
                    }
                    OutstandingRequestKind::HighestWindowIndex => {
                        mapper.map_unbounded_shred(req.slot, req.shred)
                    }
                }) else {
                    continue;
                };
                if send_socket.send(vec![(target, nonce, raw_req)]).await.is_err() {
                    continue;
                }
                req.nonce = nonce;
                req.target = target;
                req.sent_at = Instant::now();

                peer_sample.borrow_mut().record_request(target.pubkey());
                let sent_at = req.sent_at;
                let (slot, nonce, target, kind, shred) =
                    (req.slot, req.nonce, req.target, req.kind, req.shred);
                outstanding_timers.borrow_mut().insert(OutstandingTimer {
                    slot,
                    nonce,
                    target,
                    kind,
                    shred_index: shred,
                    timer: TimerActionOnce::do_in(
                        REPAIR_REQUEST_TIMEOUT,
                        enclose!((outstanding_tx) async move {
                            _ = outstanding_tx.try_send(OutstandingRequestMsg::Timeout(req));
                        }),
                    ),
                    sent_at,
                });
            }
        }
    }
}

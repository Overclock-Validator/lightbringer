use std::{
    cell::RefCell,
    collections::BTreeMap,
    net::SocketAddr,
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

use crate::repair::{peer_manager::RepairRequestMapper, socket::RepairSocketRequestBatch};

use super::{OutstandingRequestKind, peer_cache::PeerSample};

const REPAIR_REQUEST_TIMEOUT: Duration = Duration::from_millis(200);

type RepairKeyRaw = [u8; 30]; // slot(8) | nonce(4) | ip(16) | port(2)

fn repair_key(slot: u64, nonce: u32, socket: SocketAddr) -> RepairKeyRaw {
    let mut bytes = [0u8; 30];
    // Big-endian so lexicographic key ordering matches numeric slot ordering,
    // which is required for prefix range queries in contains()/remove_slot().
    bytes[..8].copy_from_slice(&slot.to_be_bytes());
    bytes[8..12].copy_from_slice(&nonce.to_le_bytes());

    let mut ip_bytes = [0u8; 16];
    match socket.ip() {
        std::net::IpAddr::V4(ipv4) => {
            ip_bytes[..4].copy_from_slice(&ipv4.octets());
        }
        std::net::IpAddr::V6(ipv6) => {
            ip_bytes.copy_from_slice(&ipv6.octets());
        }
    }
    bytes[12..28].copy_from_slice(&ip_bytes);
    bytes[28..30].copy_from_slice(&socket.port().to_le_bytes());

    bytes
}

pub struct OutstandingRequest {
    pub kind: OutstandingRequestKind,
    pub nonce: Nonce,
    pub slot: u64,
    pub shred: u32,
    pub socket: SocketAddr,
    pub sent_at: Instant,
}

pub enum OutstandingRequestMsg {
    New(OutstandingRequest),
    Timeout(OutstandingRequest),
}

#[derive(Default)]
pub struct OutstandingTimerStore(
    BTreeMap<RepairKeyRaw, (OutstandingRequestKind, u32, TimerActionOnce<()>, Instant)>,
);

impl OutstandingTimerStore {
    pub fn insert(
        &mut self,
        slot: u64,
        nonce: Nonce,
        socket: SocketAddr,
        req_type: OutstandingRequestKind,
        shred_index: u32,
        timer: TimerActionOnce<()>,
        sent_at: Instant,
    ) {
        self.0.insert(
            repair_key(slot, nonce, socket),
            (req_type, shred_index, timer, sent_at),
        );
    }

    /// remove an outstanding timer
    /// returning the request type and the time it was sent
    pub fn remove(
        &mut self,
        slot: u64,
        nonce: Nonce,
        socket: SocketAddr,
    ) -> Option<(OutstandingRequestKind, u32, Instant)> {
        let (kind, shred_index, timer, sent_at) =
            self.0.remove(&repair_key(slot, nonce, socket))?;
        timer.destroy();

        Some((kind, shred_index, sent_at))
    }

    pub fn contains(&self, slot: u64) -> bool {
        let mut prefix_key = [0u8; 30];
        prefix_key[..8].copy_from_slice(&slot.to_be_bytes());
        let mut prefix_key_limit = [0u8; 30];
        prefix_key_limit[..8].copy_from_slice(&slot.saturating_add(1).to_be_bytes());
        self.0.range(prefix_key..prefix_key_limit).count() != 0
    }

    pub fn remove_slot(&mut self, slot: u64) {
        let mut prefix_key = [0u8; 30];
        prefix_key[..8].copy_from_slice(&slot.to_be_bytes());
        let mut prefix_key_limit = [0u8; 30];
        prefix_key_limit[..8].copy_from_slice(&slot.saturating_add(1).to_be_bytes());
        let drain_iter = self.0.extract_if(prefix_key..prefix_key_limit, |_, _| true);
        for (_, (_, _, timer, _)) in drain_iter {
            timer.destroy();
        }
    }
}

pub async fn start_outstanding_requests_loop(
    mut mapper: RepairRequestMapper,
    outstanding_timers: Rc<RefCell<OutstandingTimerStore>>,
    outstanding_tx: Rc<LocalSender<OutstandingRequestMsg>>,
    outstanding_rx: LocalReceiver<OutstandingRequestMsg>,
    peer_sample: Rc<RefCell<PeerSample>>,
    send_socket: AsyncSender<RepairSocketRequestBatch>,
) {
    while let Some(msg) = outstanding_rx.recv().await {
        match msg {
            OutstandingRequestMsg::New(req) => {
                peer_sample.borrow_mut().record_request(req.socket);
                let sent_at = req.sent_at;
                let (slot, nonce, socket, kind, shred) =
                    (req.slot, req.nonce, req.socket, req.kind, req.shred);
                outstanding_timers.borrow_mut().insert(
                    slot,
                    nonce,
                    socket,
                    kind,
                    shred,
                    TimerActionOnce::do_in(
                        REPAIR_REQUEST_TIMEOUT,
                        enclose!((outstanding_tx) async move {
                            _ = outstanding_tx.try_send(OutstandingRequestMsg::Timeout(req));
                        }),
                    ),
                    sent_at,
                );
            }
            OutstandingRequestMsg::Timeout(mut req) => {
                let removed = outstanding_timers
                    .borrow_mut()
                    .remove(req.slot, req.nonce, req.socket);
                if removed.is_none() {
                    // Already fulfilled by a response
                    continue;
                }
                peer_sample.borrow_mut().record_timeout(req.socket);

                let Some((socket, nonce, raw_req)) = (match req.kind {
                    OutstandingRequestKind::WindowIndex => {
                        mapper.map_bounded_shred(req.slot, req.shred)
                    }
                    OutstandingRequestKind::HighestWindowIndex => {
                        mapper.map_unbounded_shred(req.slot, req.shred)
                    }
                }) else {
                    continue;
                };
                if send_socket.send(vec![(socket, raw_req)]).await.is_err() {
                    continue;
                }
                req.nonce = nonce;
                req.socket = socket;
                req.sent_at = Instant::now();

                peer_sample.borrow_mut().record_request(socket);
                let sent_at = req.sent_at;
                let (slot, nonce, socket, kind, shred) =
                    (req.slot, req.nonce, req.socket, req.kind, req.shred);
                outstanding_timers.borrow_mut().insert(
                    slot,
                    nonce,
                    socket,
                    kind,
                    shred,
                    TimerActionOnce::do_in(
                        REPAIR_REQUEST_TIMEOUT,
                        enclose!((outstanding_tx) async move {
                            _ = outstanding_tx.try_send(OutstandingRequestMsg::Timeout(req));
                        }),
                    ),
                    sent_at,
                );
            }
        }
    }
}

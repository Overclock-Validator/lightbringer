use std::{cell::RefCell, collections::BTreeMap, net::SocketAddr, rc::Rc, time::Duration};

use glommio::{
    channels::local_channel::{LocalReceiver, LocalSender},
    enclose,
    timer::TimerActionOnce,
};
use kanal::AsyncSender;
use solana_ledger::shred::Nonce;

use crate::repair::{peer_manager::RepairRequestMapper, socket::RepairSocketRequestBatch};

use super::OutstandingRequestKind;

const REPAIR_REQUEST_TIMEOUT: Duration = Duration::from_millis(100);

type RepairKeyRaw = [u8; 30]; // slot(8) | nonce(4) | ip(16) | port(2)

fn repair_key(slot: u64, nonce: u32, socket: SocketAddr) -> RepairKeyRaw {
    let mut bytes = [0u8; 30];
    bytes[..8].copy_from_slice(&slot.to_le_bytes());
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
}

pub enum OutstandingRequestMsg {
    New(OutstandingRequest),
    Timeout(OutstandingRequest),
}

#[derive(Default)]
pub struct OutstandingTimerStore(
    BTreeMap<RepairKeyRaw, (OutstandingRequestKind, u32, TimerActionOnce<()>)>,
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
    ) {
        self.0.insert(
            repair_key(slot, nonce, socket),
            (req_type, shred_index, timer),
        );
    }

    /// remove an outstanding timer
    /// returning the request type
    pub fn remove(
        &mut self,
        slot: u64,
        nonce: Nonce,
        socket: SocketAddr,
    ) -> Option<(OutstandingRequestKind, u32)> {
        let (kind, shred_index, timer) = self.0.remove(&repair_key(slot, nonce, socket))?;
        timer.destroy();

        Some((kind, shred_index))
    }

    pub fn contains(&self, slot: u64) -> bool {
        let mut prefix_key = [0u8; 30];
        prefix_key[..8].copy_from_slice(&slot.to_le_bytes());
        let mut prefix_key_limit = [0u8; 30];
        prefix_key_limit[..8].copy_from_slice(&(slot + 1).to_le_bytes());
        self.0.range(prefix_key..prefix_key_limit).count() != 0
    }

    pub fn remove_slot(&mut self, slot: u64) {
        let mut prefix_key = [0u8; 30];
        prefix_key[..8].copy_from_slice(&slot.to_le_bytes());
        let mut prefix_key_limit = [0u8; 30];
        prefix_key_limit[..8].copy_from_slice(&(slot + 1).to_le_bytes());
        let drain_iter = self.0.extract_if(prefix_key..prefix_key_limit, |_, _| true);
        for (_, (_, _, timer)) in drain_iter {
            timer.destroy();
        }
    }
}

pub async fn start_outstanding_requests_loop(
    mut mapper: RepairRequestMapper,
    outstanding_timers: Rc<RefCell<OutstandingTimerStore>>,
    outstanding_tx: Rc<LocalSender<OutstandingRequestMsg>>,
    outstanding_rx: LocalReceiver<OutstandingRequestMsg>,
    send_socket: AsyncSender<RepairSocketRequestBatch>,
) {
    while let Some(msg) = outstanding_rx.recv().await {
        match msg {
            OutstandingRequestMsg::New(req) => {
                let mut outstanding_timers = outstanding_timers.borrow_mut();
                outstanding_timers.insert(
                    req.slot,
                    req.nonce,
                    req.socket,
                    req.kind,
                    req.shred,
                    TimerActionOnce::do_in(
                        REPAIR_REQUEST_TIMEOUT,
                        enclose!((outstanding_tx) async move {
                            _ = outstanding_tx.try_send(OutstandingRequestMsg::Timeout(req));
                        }),
                    ),
                );
            }
            OutstandingRequestMsg::Timeout(mut req) => {
                outstanding_timers
                    .borrow_mut()
                    .remove(req.slot, req.nonce, req.socket);
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

                outstanding_timers.borrow_mut().insert(
                    req.slot,
                    req.nonce,
                    req.socket,
                    req.kind,
                    req.shred,
                    TimerActionOnce::do_in(
                        REPAIR_REQUEST_TIMEOUT,
                        enclose!((outstanding_tx) async move {
                            _ = outstanding_tx.try_send(OutstandingRequestMsg::Timeout(req));
                        }),
                    ),
                );
            }
        }
    }
}

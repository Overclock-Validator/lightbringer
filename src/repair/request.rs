use std::net::SocketAddr;

use glommio::spawn_local;
use kanal::{AsyncReceiver, AsyncSender};
use solana_ledger::shred::{self, ShredFlags, layout};

use crate::{
    repair::{
        outstanding_timers::{OutstandingRequestKind, OutstandingTimerStore, SlotRequestMap},
        peer_manager::RepairRequestMapper,
        repair_nonce,
        socket::RepairSocketRequestBatch,
    },
    thread_manager::CancelRx,
    types::PacketInfo,
};

pub enum RepairReq {
    MissingBoundedShreds {
        slot: u64,
        shreds: Vec<u32>,
    },
    MissingUnboundedShreds {
        slot: u64,
        shreds: Vec<u32>,
        max_exclusive_shred: u32,
    },
    CancelRepair {
        slot: u64,
    },
}

pub struct RepairManager {
    req_rx: AsyncReceiver<RepairReq>,
    send_socket: AsyncSender<RepairSocketRequestBatch>,
    recv_socket: AsyncReceiver<(SocketAddr, PacketInfo)>,
    filter_shred_tx: AsyncSender<PacketInfo>,
    outstanding_timers: OutstandingTimerStore,
    request_mapper: RepairRequestMapper,
}

impl RepairManager {
    pub fn new(
        req_rx: AsyncReceiver<RepairReq>,
        send_socket: AsyncSender<RepairSocketRequestBatch>,
        recv_socket: AsyncReceiver<(SocketAddr, PacketInfo)>,
        filter_shred_tx: AsyncSender<PacketInfo>,
        outstanding_timers: OutstandingTimerStore,
        request_mapper: RepairRequestMapper,
    ) -> Self {
        Self {
            req_rx,
            send_socket,
            recv_socket,
            filter_shred_tx,
            outstanding_timers,
            request_mapper,
        }
    }

    pub async fn start_repair_manager_loop(self, exit: CancelRx) {
        let outstanding_store = self.outstanding_timers;

        let mut mapper = self.request_mapper;

        let request_processor_task = spawn_local(Self::request_processor_loop(
            mapper.clone(),
            self.req_rx,
            outstanding_store.clone(),
            self.send_socket.clone(),
        ));

        let repair_recv_task = spawn_local(async move {
            while let Ok((socket_addr, packet)) = self.recv_socket.recv().await {
                let Some(nonce) = repair_nonce(&packet) else {
                    continue;
                };
                let Some(slot) = shred::layout::get_slot(&packet) else {
                    continue;
                };
                // TODO: add more filters e.g shred should sig verify
                let Some((req_kind, req_shred_index)) =
                    outstanding_store.remove(slot, nonce, socket_addr).await
                else {
                    continue;
                };

                if req_kind == OutstandingRequestKind::HighestWindowIndex {
                    let res = Self::handle_unbounded_packet_response(
                        &mut mapper,
                        &outstanding_store,
                        &self.send_socket,
                        &packet,
                        slot,
                        req_shred_index,
                    )
                    .await;
                    if res.is_none() {
                        log::info!("received invalid unbounded request");
                        continue;
                    }
                }

                _ = self.filter_shred_tx.send(packet).await;
            }
        });

        exit.await;
        repair_recv_task.cancel().await;
        request_processor_task.cancel().await;
    }

    // handle an unbounded packet response
    // returning None if packet is invalid
    async fn handle_unbounded_packet_response(
        mapper: &mut RepairRequestMapper,
        outstanding_timers: &OutstandingTimerStore,
        socket_tx: &AsyncSender<RepairSocketRequestBatch>,
        packet: &PacketInfo,
        slot: u64,
        req_shred_index: u32,
    ) -> Option<()> {
        let flags = layout::get_flags(packet).ok()?;
        let shred_index = layout::get_index(packet)?;
        let shred_slot = layout::get_slot(packet)?;

        let mut outstanding_reqs = SlotRequestMap::default();
        let mut last_shred_req = (!flags.contains(ShredFlags::LAST_SHRED_IN_SLOT))
            .then(|| {
                let (socket, nonce, shred) =
                    mapper.map_unbounded_shred(shred_slot, shred_index + 1)?;
                outstanding_reqs.insert(
                    (nonce, socket),
                    (OutstandingRequestKind::HighestWindowIndex, shred_index + 1),
                );

                Some((socket, shred))
            })
            .flatten();

        let range = if shred_index == req_shred_index {
            0..0
        } else {
            req_shred_index..shred_index
        };

        let reqs = range
            .filter_map(|shred_index| {
                let (socket, nonce, shred) = mapper.map_bounded_shred(shred_slot, shred_index)?;
                outstanding_reqs.insert(
                    (nonce, socket),
                    (OutstandingRequestKind::WindowIndex, shred_index),
                );
                Some((socket, shred))
            })
            .chain(std::iter::once_with(move || last_shred_req.take()).flatten())
            .collect::<Vec<_>>();

        outstanding_timers
            .extend_requests(slot, outstanding_reqs)
            .await;
        _ = socket_tx.send(reqs).await;

        Some(())
    }

    fn process_missing_shreds(
        mapper: &mut RepairRequestMapper,
        outstanding_reqs: &mut SlotRequestMap,
        slot: u64,
        shreds: Vec<u32>,
    ) -> impl Iterator<Item = (SocketAddr, Vec<u8>)> {
        shreds.into_iter().filter_map(move |shred| {
            let (socket, nonce, packet) = mapper.map_bounded_shred(slot, shred)?;
            outstanding_reqs.insert(
                (nonce, socket),
                (OutstandingRequestKind::WindowIndex, shred),
            );
            Some((socket, packet))
        })
    }

    async fn request_processor_loop(
        mut mapper: RepairRequestMapper,
        req_rx: AsyncReceiver<RepairReq>,
        outstanding_timers: OutstandingTimerStore,
        send_socket: AsyncSender<RepairSocketRequestBatch>,
    ) {
        while let Ok(req) = req_rx.recv().await {
            let mut outstanding_reqs = SlotRequestMap::default();
            let (slot, socket_reqs) = {
                match req {
                    RepairReq::MissingBoundedShreds { slot, shreds } => {
                        if outstanding_timers.contains(slot).await {
                            continue;
                        }
                        if shreds.is_empty() {
                            log::warn!(
                                "received empty bounded repair request for slot {slot}, ignoring"
                            );
                            continue;
                        }

                        let reqs = Self::process_missing_shreds(
                            &mut mapper,
                            &mut outstanding_reqs,
                            slot,
                            shreds,
                        )
                        .collect::<Vec<_>>();
                        (slot, reqs)
                    }
                    RepairReq::MissingUnboundedShreds {
                        slot,
                        shreds,
                        max_exclusive_shred,
                    } => {
                        if outstanding_timers.contains(slot).await {
                            continue;
                        }

                        let Some((req_socket, nonce, raw)) =
                            mapper.map_unbounded_shred(slot, max_exclusive_shred)
                        else {
                            continue;
                        };

                        let mut reqs = Self::process_missing_shreds(
                            &mut mapper,
                            &mut outstanding_reqs,
                            slot,
                            shreds,
                        )
                        .collect::<Vec<_>>();
                        reqs.push((req_socket, raw));
                        outstanding_reqs.insert(
                            (nonce, req_socket),
                            (
                                OutstandingRequestKind::HighestWindowIndex,
                                max_exclusive_shred,
                            ),
                        );

                        (slot, reqs)
                    }
                    RepairReq::CancelRepair { slot } => {
                        outstanding_timers.cancel_repair(slot).await;
                        continue;
                    }
                }
            };
            if !outstanding_timers.try_insert(slot, outstanding_reqs).await {
                continue;
            }
            _ = send_socket.send(socket_reqs).await;
        }
    }
}

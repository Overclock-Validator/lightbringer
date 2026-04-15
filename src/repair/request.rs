use std::{cell::RefCell, net::SocketAddr, rc::Rc};

use glommio::{
    Latency, Shares,
    channels::local_channel::{self, LocalSender},
    executor, spawn_local_into,
};
use kanal::{AsyncReceiver, AsyncSender};
use solana_ledger::shred::{self, ShredFlags, layout};

use crate::{
    metrics::{MetricsSender, points::SlotMeasurement},
    repair::{
        OutstandingRequestKind,
        outstanding_timers::{
            OutstandingRequest, OutstandingRequestMsg, OutstandingTimerStore,
            start_outstanding_requests_loop,
        },
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
        max_inclusive_shred: u32,
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
    request_mapper: RepairRequestMapper,
    metrics: MetricsSender,
}

impl RepairManager {
    pub fn new(
        req_rx: AsyncReceiver<RepairReq>,
        send_socket: AsyncSender<RepairSocketRequestBatch>,
        recv_socket: AsyncReceiver<(SocketAddr, PacketInfo)>,
        filter_shred_tx: AsyncSender<PacketInfo>,
        request_mapper: RepairRequestMapper,
        metrics: MetricsSender,
    ) -> Self {
        Self {
            req_rx,
            send_socket,
            recv_socket,
            filter_shred_tx,
            request_mapper,
            metrics,
        }
    }

    pub async fn start_repair_manager_loop(self, exit: CancelRx) {
        let mut mapper = self.request_mapper;

        let exec = executor();
        let main_task_tq = exec.create_task_queue(
            Shares::Static(70),
            Latency::NotImportant,
            "repair_manager_main",
        );
        let outstanding_task_tq = exec.create_task_queue(
            Shares::Static(30),
            Latency::NotImportant,
            "repair_manager_outstanding",
        );

        let outstanding_store = Rc::new(RefCell::new(OutstandingTimerStore::default()));
        let (outstanding_request_tx, outstanding_request_rx) = local_channel::new_unbounded();
        let outstanding_request_tx = Rc::new(outstanding_request_tx);

        let outstanding_requests_task = spawn_local_into(
            start_outstanding_requests_loop(
                mapper.clone(),
                outstanding_store.clone(),
                outstanding_request_tx.clone(),
                outstanding_request_rx,
                self.send_socket.clone(),
            ),
            outstanding_task_tq,
        )
        .unwrap();

        let request_processor_task = spawn_local_into(
            Self::request_processor_loop(
                mapper.clone(),
                self.req_rx,
                outstanding_store.clone(),
                outstanding_request_tx.clone(),
                self.send_socket.clone(),
                self.metrics,
            ),
            main_task_tq,
        )
        .unwrap();

        let repair_recv_task = spawn_local_into(
            async move {
                while let Ok((socket_addr, packet)) = self.recv_socket.recv().await {
                    let Some(nonce) = repair_nonce(&packet) else {
                        continue;
                    };
                    let Some(slot) = shred::layout::get_slot(&packet) else {
                        continue;
                    };
                    // TODO: add more filters e.g shred should sig verify
                    let Some((req_kind, req_shred_index)) =
                        outstanding_store
                            .borrow_mut()
                            .remove(slot, nonce, socket_addr)
                    else {
                        continue;
                    };

                    if req_kind == OutstandingRequestKind::HighestWindowIndex {
                        let res = Self::handle_unbounded_packet_response(
                            &mut mapper,
                            &outstanding_request_tx,
                            &self.send_socket,
                            &packet,
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
            },
            main_task_tq,
        )
        .unwrap();

        exit.await;
        repair_recv_task.cancel().await;
        outstanding_requests_task.cancel().await;
        request_processor_task.cancel().await;
    }

    // handle an unbounded packet response
    // returning None if packet is invalid
    async fn handle_unbounded_packet_response(
        mapper: &mut RepairRequestMapper,
        outstanding_tx: &LocalSender<OutstandingRequestMsg>,
        socket_tx: &AsyncSender<RepairSocketRequestBatch>,
        packet: &PacketInfo,
        req_shred_index: u32,
    ) -> Option<()> {
        let flags = layout::get_flags(packet).ok()?;
        let shred_index = layout::get_index(packet)?;
        let shred_slot = layout::get_slot(packet)?;

        let mut last_shred_req = (!flags.contains(ShredFlags::LAST_SHRED_IN_SLOT))
            .then(|| mapper.map_unbounded_shred(shred_slot, shred_index + 1))
            .flatten();

        let range = if shred_index == req_shred_index {
            0..0
        } else {
            req_shred_index..shred_index
        };
        let reqs = range
            .filter_map(move |shred_index| {
                let (socket, nonce, shred) = mapper.map_bounded_shred(shred_slot, shred_index)?;
                _ = outstanding_tx.try_send(OutstandingRequestMsg::New(OutstandingRequest {
                    kind: OutstandingRequestKind::WindowIndex,
                    nonce,
                    slot: shred_slot,
                    shred: shred_index,
                    socket,
                }));
                Some((socket, shred))
            })
            .chain(
                std::iter::once_with(move || {
                    let (socket, nonce, shred) = last_shred_req.take()?;
                    _ = outstanding_tx.try_send(OutstandingRequestMsg::New(OutstandingRequest {
                        kind: OutstandingRequestKind::HighestWindowIndex,
                        nonce,
                        slot: shred_slot,
                        shred: shred_index,
                        socket,
                    }));

                    Some((socket, shred))
                })
                .flatten(),
            )
            .collect::<Vec<_>>();

        _ = socket_tx.send(reqs).await;

        Some(())
    }

    fn process_missing_shreds(
        mapper: &mut RepairRequestMapper,
        outstanding_tx: &LocalSender<OutstandingRequestMsg>,
        slot: u64,
        shreds: Vec<u32>,
    ) -> impl Iterator<Item = (SocketAddr, Vec<u8>)> {
        shreds.into_iter().filter_map(move |shred| {
            let (socket, nonce, packet) = mapper.map_bounded_shred(slot, shred)?;
            _ = outstanding_tx.try_send(OutstandingRequestMsg::New(OutstandingRequest {
                kind: OutstandingRequestKind::WindowIndex,
                nonce,
                slot,
                shred,
                socket,
            }));
            Some((socket, packet))
        })
    }

    async fn request_processor_loop(
        mut mapper: RepairRequestMapper,
        req_rx: AsyncReceiver<RepairReq>,
        store: Rc<RefCell<OutstandingTimerStore>>,
        outstanding_tx: Rc<LocalSender<OutstandingRequestMsg>>,
        send_socket: AsyncSender<RepairSocketRequestBatch>,
        metrics: MetricsSender,
    ) {
        while let Ok(req) = req_rx.recv().await {
            let socket_reqs = {
                match req {
                    RepairReq::MissingBoundedShreds { slot, shreds } => {
                        if store.borrow().contains(slot) {
                            continue;
                        }
                        if shreds.is_empty() {
                            log::warn!(
                                "received empty bounded repair request for slot {slot}, ignoring"
                            );
                            continue;
                        }

                        metrics.measure(SlotMeasurement::repair(slot));

                        Self::process_missing_shreds(&mut mapper, &outstanding_tx, slot, shreds)
                            .collect::<Vec<_>>()
                    }
                    RepairReq::MissingUnboundedShreds {
                        slot,
                        shreds,
                        max_inclusive_shred,
                    } => {
                        if store.borrow().contains(slot) {
                            continue;
                        }

                        let Some((req_socket, nonce, raw)) =
                            mapper.map_unbounded_shred(slot, max_inclusive_shred)
                        else {
                            continue;
                        };

                        metrics.measure(SlotMeasurement::repair(slot));

                        let mut reqs = Self::process_missing_shreds(
                            &mut mapper,
                            &outstanding_tx,
                            slot,
                            shreds,
                        )
                        .collect::<Vec<_>>();
                        reqs.push((req_socket, raw));
                        _ = outstanding_tx.try_send(OutstandingRequestMsg::New(
                            OutstandingRequest {
                                kind: OutstandingRequestKind::HighestWindowIndex,
                                nonce,
                                slot,
                                shred: max_inclusive_shred,
                                socket: req_socket,
                            },
                        ));

                        reqs
                    }
                    RepairReq::CancelRepair { slot } => {
                        store.borrow_mut().remove_slot(slot);
                        continue;
                    }
                }
            };

            _ = send_socket.send(socket_reqs).await;
        }
    }
}

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr},
    ops::Index,
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use futures::StreamExt;
use glommio::{
    Latency, Shares, TaskQueueHandle,
    channels::local_channel::{self, LocalReceiver, LocalSender},
    executor, spawn_local_into,
    timer::TimerActionOnce,
};
use indexmap::IndexMap;
use kanal::{AsyncReceiver, AsyncSender};
use rand::{Rng, SeedableRng, rngs::SmallRng, seq::IndexedRandom};
use solana_core::repair::serve_repair::{RepairProtocol, RepairRequestHeader, ServeRepair};
use solana_gossip::{cluster_info::ClusterInfo, contact_info::Protocol};
use solana_ledger::shred::{self, Nonce, ShredFlags, layout};
use solana_sdk::{pubkey::Pubkey, signature::Keypair, timing::timestamp};

use crate::{
    repair::{repair_nonce, socket::RepairSocketRequestBatch},
    thread_manager::CancelRx,
    types::PacketInfo,
};

const REFRESH_INTERVAL: Duration = Duration::from_secs(10);
const STALE_THRESHOLD: Duration = Duration::from_secs(300);
const REPAIR_SLOT_TIMEOUT: Duration = Duration::from_millis(200);

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
}

#[derive(Clone, Copy, PartialEq)]
enum OutstandingRequestKind {
    WindowIndex,
    HighestWindowIndex,
}

type SlotRequestMap = BTreeMap<(Nonce, SocketAddr), (OutstandingRequestKind, u32)>;

struct OutstandingRequestTimeout(u64);

#[derive(Clone)]
struct OutstandingTimerStoreV2 {
    inner: Rc<RefCell<HashMap<u64, (SlotRequestMap, Instant)>>>
}

impl OutstandingTimerStoreV2 {
    pub fn new(_tx: Rc<LocalSender<OutstandingRequestTimeout>>, _tq: TaskQueueHandle) -> Self {
        Self {
            inner: Default::default(),
        }
    }

    pub fn remove(
        &self,
        slot: u64,
        nonce: Nonce,
        socket: SocketAddr,
    ) -> Option<(OutstandingRequestKind, u32)> {
        let mut inner = self.inner.borrow_mut();
        let (reqs, _) = inner.get_mut(&slot)?;
        let res = reqs.remove(&(nonce, socket))?;
        if reqs.is_empty() {
            inner.remove(&slot);
        }
        Some(res)
    }

    pub fn insert(&self, slot: u64, reqs: SlotRequestMap) {
        self.inner.borrow_mut().insert(
            slot,
            (
                reqs,
                Instant::now() + REPAIR_SLOT_TIMEOUT,
            ),
        );
    }
}

#[derive(Clone)]
struct OutstandingTimerStore {
    inner: Rc<RefCell<HashMap<u64, (SlotRequestMap, TimerActionOnce<()>)>>>,
    tx: Rc<LocalSender<OutstandingRequestTimeout>>,
    tq: TaskQueueHandle,
}

impl OutstandingTimerStore {
    pub fn new(tx: Rc<LocalSender<OutstandingRequestTimeout>>, tq: TaskQueueHandle) -> Self {
        Self {
            inner: Default::default(),
            tx,
            tq,
        }
    }

    pub fn remove(
        &self,
        slot: u64,
        nonce: Nonce,
        socket: SocketAddr,
    ) -> Option<(OutstandingRequestKind, u32)> {
        let mut inner = self.inner.borrow_mut();
        let (reqs, timer) = inner.get_mut(&slot)?;
        let res = reqs.remove(&(nonce, socket))?;
        if reqs.is_empty() {
            timer.destroy();
            inner.remove(&slot).unwrap();
        }

        Some(res)
    }

    pub fn insert(&self, slot: u64, reqs: SlotRequestMap) {
        let tx = self.tx.clone();
        self.inner.borrow_mut().insert(
            slot,
            (
                reqs,
                TimerActionOnce::do_in_into(
                    REPAIR_SLOT_TIMEOUT,
                    async move {
                        _ = tx.try_send(OutstandingRequestTimeout(slot));
                    },
                    self.tq,
                )
                .unwrap(),
            ),
        );
    }
}

#[derive(Default)]
struct RepairPeers(IndexMap<IpAddr, RepairPeerInfo>);

impl Index<usize> for RepairPeers {
    type Output = RepairPeerInfo;

    fn index(&self, index: usize) -> &Self::Output {
        self.0.index(index)
    }
}

impl IndexedRandom for RepairPeers {
    fn len(&self) -> usize {
        self.0.len()
    }
}

struct RepairPeerInfo {
    socket_addr: SocketAddr,
    pubkey: Pubkey,
    last_seen: SystemTime,
}

#[derive(Clone)]
struct RepairRequestMapper {
    peers: Rc<RefCell<RepairPeers>>,
    id: Pubkey,
    keypair: Arc<Keypair>,
    rng: Rc<RefCell<SmallRng>>,
}

impl RepairRequestMapper {
    pub fn new(peers: Rc<RefCell<RepairPeers>>, id: Pubkey, keypair: Arc<Keypair>) -> Self {
        Self {
            peers,
            id,
            keypair,
            rng: Rc::new(RefCell::new(SmallRng::from_rng(&mut rand::rng()))),
        }
    }

    fn random_peer(&mut self) -> Option<(Pubkey, SocketAddr)> {
        if let Some(req_node) = self.peers.borrow().choose(&mut self.rng.borrow_mut()) {
            Some((req_node.pubkey, req_node.socket_addr))
        } else {
            log::error!("no repair peers available, unable to send repair request");
            None
        }
    }

    fn create_header(&mut self, req_pk: Pubkey) -> (Nonce, RepairRequestHeader) {
        let nonce = self.rng.borrow_mut().random();
        (
            nonce,
            RepairRequestHeader::new(self.id, req_pk, timestamp(), nonce),
        )
    }

    fn repair_proto_to_bytes(&self, req: &RepairProtocol) -> Vec<u8> {
        ServeRepair::repair_proto_to_bytes(req, &self.keypair)
            .expect("failed to sign repair request?!")
    }

    pub fn map_bounded_shred(
        &mut self,
        slot: u64,
        shred: u32,
    ) -> Option<(SocketAddr, Nonce, Vec<u8>)> {
        let (req_pk, req_socket) = self.random_peer()?;
        let (nonce, header) = self.create_header(req_pk);
        let req = RepairProtocol::WindowIndex {
            header,
            slot,
            shred_index: shred.into(),
        };

        let raw = self.repair_proto_to_bytes(&req);
        Some((req_socket, nonce, raw))
    }

    pub fn map_unbounded_shred(
        &mut self,
        slot: u64,
        max_exclusive_shred: u32,
    ) -> Option<(SocketAddr, Nonce, Vec<u8>)> {
        let (req_pk, req_socket) = self.random_peer()?;
        let (nonce, header) = self.create_header(req_pk);
        let req = RepairProtocol::HighestWindowIndex {
            header,
            slot,
            shred_index: max_exclusive_shred.into(),
        };
        let raw = self.repair_proto_to_bytes(&req);
        Some((req_socket, nonce, raw))
    }
}

pub struct RepairManager {
    peers: Rc<RefCell<RepairPeers>>,
    cluster_info: Arc<ClusterInfo>,
    req_rx: AsyncReceiver<RepairReq>,
    keypair: Arc<Keypair>,
    send_socket: AsyncSender<RepairSocketRequestBatch>,
    recv_socket: AsyncReceiver<(SocketAddr, PacketInfo)>,
    filter_shred_tx: AsyncSender<PacketInfo>,
}

impl RepairManager {
    pub fn new(
        cluster_info: Arc<ClusterInfo>,
        req_rx: AsyncReceiver<RepairReq>,
        keypair: Arc<Keypair>,
        send_socket: AsyncSender<RepairSocketRequestBatch>,
        recv_socket: AsyncReceiver<(SocketAddr, PacketInfo)>,
        filter_shred_tx: AsyncSender<PacketInfo>,
    ) -> Self {
        let peers = Rc::new(RefCell::new(RepairPeers::default()));
        Self {
            peers,
            cluster_info,
            req_rx,
            keypair,
            send_socket,
            recv_socket,
            filter_shred_tx,
        }
    }

    pub async fn start_repair_manager_loop(self, exit: CancelRx) {
        let me = self.cluster_info.id();

        let executor = executor();
        let main_task_tq = executor.create_task_queue(
            Shares::Static(50),
            Latency::NotImportant,
            "repair_manager_main",
        );
        let outstanding_task_tq = executor.create_task_queue(
            Shares::Static(50),
            Latency::NotImportant,
            "repair_manager_outstanding",
        );
        let peer_manager_task_tq = executor.create_task_queue(
            Shares::Static(10),
            Latency::NotImportant,
            "repair_manager_peers",
        );

        let repair_peers_insert = self.peers.clone();
        let peer_manager_task = spawn_local_into(
            Self::start_peer_manager_loop(repair_peers_insert, self.cluster_info),
            peer_manager_task_tq,
        )
        .unwrap();

        let (outstanding_timeout_tx, outstanding_timeout_rx) = local_channel::new_unbounded();
        let outstanding_request_tx = Rc::new(outstanding_timeout_tx);
        let outstanding_store =
            OutstandingTimerStoreV2::new(outstanding_request_tx.clone(), outstanding_task_tq);

        let mut mapper = RepairRequestMapper::new(self.peers, me, self.keypair);
        let outstanding_requests_task = spawn_local_into(
            Self::start_outstanding_requests_loop(
                mapper.clone(),
                outstanding_store.clone(),
                outstanding_timeout_rx,
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
                self.send_socket.clone(),
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
                        outstanding_store.remove(slot, nonce, socket_addr)
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
            },
            main_task_tq,
        )
        .unwrap();

        exit.await;
        repair_recv_task.cancel().await;
        outstanding_requests_task.cancel().await;
        request_processor_task.cancel().await;
        peer_manager_task.cancel().await;
    }

    // handle an unbounded packet response
    // returning None if packet is invalid
    async fn handle_unbounded_packet_response(
        mapper: &mut RepairRequestMapper,
        outstanding_timers: &OutstandingTimerStoreV2,
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

        outstanding_timers.insert(slot, outstanding_reqs);
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
        outstanding_timers: OutstandingTimerStoreV2,
        send_socket: AsyncSender<RepairSocketRequestBatch>,
    ) {
        while let Ok(req) = req_rx.recv().await {
            let mut outstanding_reqs = SlotRequestMap::default();
            let (slot, socket_reqs) = {
                match req {
                    RepairReq::MissingBoundedShreds { slot, shreds } => {
                        if outstanding_timers.inner.borrow().contains_key(&slot) {
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
                        if outstanding_timers.inner.borrow().contains_key(&slot) {
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
                }
            };
            outstanding_timers.insert(slot, outstanding_reqs);
            _ = send_socket.send(socket_reqs).await;
        }
    }

    async fn start_outstanding_requests_loop(
        mut mapper: RepairRequestMapper,
        outstanding_timers: OutstandingTimerStoreV2,
        _outstanding_rx: LocalReceiver<OutstandingRequestTimeout>,
        send_socket: AsyncSender<RepairSocketRequestBatch>,
    ) {
        loop {
            glommio::timer::sleep(Duration::from_millis(500)).await;
            let mut socket_reqs = Vec::new();
            for (slot, (reqs, deadline)) in outstanding_timers.inner.borrow_mut().iter_mut() {
                if *deadline > Instant::now() {
                    continue;
                }
                log::info!("slot {slot}, repair time out");

                let mut new_reqs = SlotRequestMap::default();
                socket_reqs.extend(reqs.values().filter_map(|&(kind, shred)| {
                    let (socket, nonce, repair_raw) = match kind {
                        OutstandingRequestKind::WindowIndex => {
                            mapper.map_bounded_shred(*slot, shred)
                        }
                        OutstandingRequestKind::HighestWindowIndex => {
                            mapper.map_unbounded_shred(*slot, shred)
                        }
                    }?;
                    new_reqs.insert((nonce, socket), (kind, shred));

                    Some((socket, repair_raw))
                }));

                *reqs = new_reqs;
                *deadline = Instant::now() + REPAIR_SLOT_TIMEOUT;
            }
            if let Err(e) = send_socket.send(socket_reqs).await {
                log::warn!("repair socket rx died?! {e}");
            }
        }
        // let mut rx = outstanding_rx.stream().ready_chunks(500);
        // while let Some(slots) = rx.next().await {
        //     let mut socket_reqs = Vec::new();
        //     for OutstandingRequestTimeout(slot) in slots {
        //         let mut store = outstanding_timers.inner.borrow_mut();
        //         let Some((reqs, timer)) = store.get_mut(&slot) else {
        //             log::error!("timed out for complete slot?! {slot}");
        //             continue;
        //         };
        //         log::info!("slot {slot} timed out for repair");
        //         let mut new_reqs = SlotRequestMap::default();
        //         socket_reqs.extend(reqs.values().filter_map(|&(kind, shred)| {
        //             let (socket, nonce, repair_raw) = match kind {
        //                 OutstandingRequestKind::WindowIndex => {
        //                     mapper.map_bounded_shred(slot, shred)
        //                 }
        //                 OutstandingRequestKind::HighestWindowIndex => {
        //                     mapper.map_unbounded_shred(slot, shred)
        //                 }
        //             }?;
        //             new_reqs.insert((nonce, socket), (kind, shred));

        //             Some((socket, repair_raw))
        //         }));

        //         *reqs = new_reqs;
        //         timer.rearm_in(REPAIR_SLOT_TIMEOUT);
        //         std::mem::drop(store);
        //     }
        //     if send_socket.send(socket_reqs).await.is_err() {
        //         continue;
        //     }
        // }
    }

    async fn start_peer_manager_loop(
        repair_peers: Rc<RefCell<RepairPeers>>,
        cluster_info: Arc<ClusterInfo>,
    ) -> ! {
        loop {
            let now = SystemTime::now();
            let peers = cluster_info.all_peers();

            {
                let mut repair_peers = repair_peers.borrow_mut();

                repair_peers.0.retain(|_, info| {
                    if let Ok(duration) = now.duration_since(info.last_seen) {
                        duration < STALE_THRESHOLD
                    } else {
                        true
                    }
                });

                for (peer, _) in peers {
                    let Some(peer_repair_addr) = peer.serve_repair(Protocol::UDP) else {
                        continue;
                    };
                    let ip = peer_repair_addr.ip();
                    repair_peers.0.insert(
                        ip,
                        RepairPeerInfo {
                            socket_addr: peer_repair_addr,
                            pubkey: *peer.pubkey(),
                            last_seen: now,
                        },
                    );
                }

                log::info!(
                    "Refreshed repair peers. Current count: {}",
                    repair_peers.0.len()
                );

                #[cfg(feature = "debug")]
                {
                    for (ip, info) in repair_peers.0.iter() {
                        let duration = SystemTime::now()
                            .duration_since(info.last_seen)
                            .unwrap_or(Duration::from_secs(0));
                        log::debug!(
                            "Repair Peer, IP: {}, Address: {:?}, Last seen: {} seconds ago",
                            ip,
                            info.socket_addr,
                            duration.as_secs()
                        );
                    }
                }
            }

            glommio::timer::sleep(REFRESH_INTERVAL).await;
        }
    }
}

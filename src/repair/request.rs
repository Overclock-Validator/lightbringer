use std::{
    cell::RefCell,
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    ops::Index,
    rc::Rc,
    sync::Arc,
    time::{Duration, SystemTime},
};

use futures::StreamExt;
use glommio::{
    channels::local_channel::{self, LocalReceiver, LocalSender},
    enclose, spawn_local,
    timer::TimerActionOnce,
};
use indexmap::IndexMap;
use kanal::{AsyncReceiver, AsyncSender};
use rand::{Rng, SeedableRng, rngs::SmallRng, seq::IndexedRandom};
use solana_core::repair::serve_repair::{RepairProtocol, RepairRequestHeader, ServeRepair};
use solana_gossip::{cluster_info::ClusterInfo, contact_info::Protocol};
use solana_ledger::shred::Nonce;
use solana_sdk::{pubkey::Pubkey, signature::Keypair, timing::timestamp};

use crate::{
    repair::socket::RepairSocketRequestBatch,
    thread_manager::CancelRx,
    types::{PacketInfo, PacketView},
};

const REFRESH_INTERVAL: Duration = Duration::from_secs(10);
const STALE_THRESHOLD: Duration = Duration::from_secs(300);
const REPAIR_REQUEST_TIMEOUT: Duration = Duration::from_millis(100);

pub enum RepairReq {
    MissingBoundedShreds { slot: u64, shreds: Vec<u32> },
    MissingUnboundedShreds { slot: u64, max_exclusive_shred: u32 },
}

enum OutstandingRequestKind {
    WindowIndex,
    HighestWindowIndex,
}

struct OutstandingRequest {
    kind: OutstandingRequestKind,
    nonce: Nonce,
    slot: u64,
    shred: u32,
    socket: SocketAddr,
}

enum OutstandingRequestMsg {
    New(OutstandingRequest),
    Timeout(OutstandingRequest),
}

#[derive(Default)]
struct OutstandingTimerStore(HashMap<(Nonce, SocketAddr), TimerActionOnce<()>>);

impl OutstandingTimerStore {
    pub fn insert(&mut self, key: (Nonce, SocketAddr), timer: TimerActionOnce<()>) {
        self.0.insert(key, timer);
    }

    /// remove an outstanding timer
    /// returning true if it was removed
    pub fn remove(&mut self, key: &(Nonce, SocketAddr)) -> bool {
        let Some(timer) = self.0.remove(key) else {
            return false;
        };

        timer.destroy();
        true
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

    fn repair_nonce(packet: &PacketView) -> Option<Nonce> {
        let nonce_offset = packet.len().checked_sub(4)?;
        let nonce_raw_le = <[u8; 4]>::try_from(packet.get(nonce_offset..)?).ok()?;
        Some(Nonce::from_le_bytes(nonce_raw_le))
    }

    pub async fn start_repair_manager_loop(self, exit: CancelRx) {
        let me = self.cluster_info.id();

        let repair_peers_insert = self.peers.clone();
        let peer_manager_task = spawn_local(Self::start_peer_manager_loop(
            repair_peers_insert,
            self.cluster_info,
        ));

        let outstanding_store = Rc::new(RefCell::new(OutstandingTimerStore::default()));
        let (outstanding_request_tx, outstanding_request_rx) = local_channel::new_unbounded();
        let outstanding_request_tx = Rc::new(outstanding_request_tx);
        let mapper = RepairRequestMapper::new(self.peers, me, self.keypair);
        let outstanding_requests_task = spawn_local(Self::start_outstanding_requests_loop(
            mapper.clone(),
            outstanding_store.clone(),
            outstanding_request_tx.clone(),
            outstanding_request_rx,
            self.send_socket.clone(),
        ));

        let request_processor_task = spawn_local(Self::request_processor_loop(
            mapper,
            self.req_rx,
            outstanding_request_tx.clone(),
            self.send_socket.clone(),
        ));

        let repair_recv_task = spawn_local(async move {
            while let Ok((socket_addr, packet)) = self.recv_socket.recv().await {
                let Some(nonce) = Self::repair_nonce(&packet) else {
                    continue;
                };
                // TODO: add more filters e.g shred should sig verify
                if outstanding_store.borrow_mut().remove(&(nonce, socket_addr)) {
                    _ = self.filter_shred_tx.send(packet).await;
                }
            }
        });

        exit.await;
        repair_recv_task.cancel().await;
        outstanding_requests_task.cancel().await;
        request_processor_task.cancel().await;
        peer_manager_task.cancel().await;
    }

    async fn request_processor_loop(
        mut mapper: RepairRequestMapper,
        req_rx: AsyncReceiver<RepairReq>,
        outstanding_tx: Rc<LocalSender<OutstandingRequestMsg>>,
        send_socket: AsyncSender<RepairSocketRequestBatch>,
    ) {
        while let Ok(req) = req_rx.recv().await {
            let socket_reqs = {
                match req {
                    RepairReq::MissingBoundedShreds { slot, shreds } => shreds
                        .into_iter()
                        .filter_map(|shred| {
                            let (socket, nonce, packet) = mapper.map_bounded_shred(slot, shred)?;
                            _ = outstanding_tx.try_send(OutstandingRequestMsg::New(
                                OutstandingRequest {
                                    kind: OutstandingRequestKind::WindowIndex,
                                    nonce,
                                    slot,
                                    shred,
                                    socket,
                                },
                            ));
                            Some((socket, packet))
                        })
                        .collect::<Vec<_>>(),
                    RepairReq::MissingUnboundedShreds {
                        slot,
                        max_exclusive_shred,
                    } => {
                        log::warn!(
                            "slot {slot} did not observe the last shred, repairing it uses a slow path"
                        );
                        let Some((req_socket, nonce, raw)) =
                            mapper.map_unbounded_shred(slot, max_exclusive_shred)
                        else {
                            continue;
                        };
                        _ = outstanding_tx.try_send(OutstandingRequestMsg::New(
                            OutstandingRequest {
                                kind: OutstandingRequestKind::HighestWindowIndex,
                                nonce,
                                slot,
                                shred: max_exclusive_shred,
                                socket: req_socket,
                            },
                        ));
                        vec![(req_socket, raw)]
                    }
                }
            };
            _ = send_socket.send(socket_reqs).await;
        }
    }

    async fn start_outstanding_requests_loop(
        mut mapper: RepairRequestMapper,
        outstanding_timers: Rc<RefCell<OutstandingTimerStore>>,
        outstanding_tx: Rc<LocalSender<OutstandingRequestMsg>>,
        outstanding_rx: LocalReceiver<OutstandingRequestMsg>,
        send_socket: AsyncSender<RepairSocketRequestBatch>,
    ) {
        while let Some(msg) = outstanding_rx.recv().await {
            match msg {
                OutstandingRequestMsg::New(req) => {
                    outstanding_timers.borrow_mut().insert(
                        (req.nonce, req.socket),
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
                        .remove(&(req.nonce, req.socket));
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
                        (req.nonce, req.socket),
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

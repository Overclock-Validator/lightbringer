use std::{
    cell::RefCell,
    net::{IpAddr, SocketAddr},
    ops::Index,
    rc::Rc,
    sync::Arc,
    time::{Duration, SystemTime},
};

use futures::StreamExt;
use glommio::spawn_local;
use indexmap::IndexMap;
use kanal::{AsyncReceiver, AsyncSender};
use rand::{Rng, SeedableRng, rngs::SmallRng, seq::IndexedRandom};
use solana_core::repair::serve_repair::{RepairProtocol, RepairRequestHeader, ServeRepair};
use solana_gossip::{cluster_info::ClusterInfo, contact_info::Protocol};
use solana_sdk::{pubkey::Pubkey, signature::Keypair, timing::timestamp};

use crate::{repair::socket::RepairSocketRequestBatch, thread_manager::CancelRx};

const REFRESH_INTERVAL: Duration = Duration::from_secs(10);
const STALE_THRESHOLD: Duration = Duration::from_secs(300);

pub enum RepairReq {
    MissingBoundedShreds { slot: u64, shreds: Vec<u32> },
    MissingUnboundedShreds { slot: u64, max_exclusive_shred: u32 },
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

struct RepairRequestMapper<'a> {
    peers: &'a RepairPeers,
    id: &'a Pubkey,
    keypair: &'a Keypair,
    rng: &'a mut SmallRng,
}

impl<'a> RepairRequestMapper<'a> {
    pub fn new(
        peers: &'a RepairPeers,
        id: &'a Pubkey,
        keypair: &'a Keypair,
        rng: &'a mut SmallRng,
    ) -> Self {
        Self {
            peers,
            id,
            keypair,
            rng,
        }
    }

    fn random_peer(&mut self) -> Option<(Pubkey, SocketAddr)> {
        if let Some(req_node) = self.peers.choose(self.rng) {
            Some((req_node.pubkey, req_node.socket_addr))
        } else {
            log::error!("no repair peers available, unable to send repair request");
            None
        }
    }

    fn create_header(&mut self, req_pk: Pubkey) -> RepairRequestHeader {
        RepairRequestHeader::new(*self.id, req_pk, timestamp(), self.rng.random())
    }

    fn repair_proto_to_bytes(&self, req: &RepairProtocol) -> Vec<u8> {
        ServeRepair::repair_proto_to_bytes(req, self.keypair)
            .expect("failed to sign repair request?!")
    }

    pub fn map_bounded_shred(&mut self, slot: u64, shred: u32) -> Option<(SocketAddr, Vec<u8>)> {
        let (req_pk, req_socket) = self.random_peer()?;
        let header = self.create_header(req_pk);
        let req = RepairProtocol::WindowIndex {
            header,
            slot,
            shred_index: shred.into(),
        };

        let raw = self.repair_proto_to_bytes(&req);
        Some((req_socket, raw))
    }

    pub fn map_unbounded_shred(
        &mut self,
        slot: u64,
        max_exclusive_shred: u32,
    ) -> Option<(SocketAddr, Vec<u8>)> {
        let (req_pk, req_socket) = self.random_peer()?;
        let header = self.create_header(req_pk);
        let req = RepairProtocol::HighestWindowIndex {
            header,
            slot,
            shred_index: max_exclusive_shred.into(),
        };
        let raw = self.repair_proto_to_bytes(&req);
        Some((req_socket, raw))
    }
}

pub struct RepairRequestManager {
    peers: Rc<RefCell<RepairPeers>>,
    cluster_info: Arc<ClusterInfo>,
    req_rx: AsyncReceiver<RepairReq>,
    keypair: Arc<Keypair>,
    send_socket: AsyncSender<RepairSocketRequestBatch>,
}

impl RepairRequestManager {
    pub fn new(
        cluster_info: Arc<ClusterInfo>,
        req_rx: AsyncReceiver<RepairReq>,
        keypair: Arc<Keypair>,
        send_socket: AsyncSender<RepairSocketRequestBatch>,
    ) -> Self {
        let peers = Rc::new(RefCell::new(RepairPeers::default()));
        Self {
            peers,
            cluster_info,
            req_rx,
            keypair,
            send_socket,
        }
    }

    pub async fn start_repair_manager_loop(self, exit: CancelRx) {
        let me = self.cluster_info.id();

        let repair_peers_insert = self.peers.clone();
        let peer_manager_task = spawn_local(Self::start_peer_manager_loop(
            repair_peers_insert,
            self.cluster_info,
        ));

        exit.await;
        peer_manager_task.cancel().await;
    }

    async fn request_processor_loop(
        peers: Rc<RefCell<RepairPeers>>,
        req_rx: AsyncReceiver<RepairReq>,
        id: Pubkey,
        keypair: Keypair,
        send_socket: AsyncSender<RepairSocketRequestBatch>,
    ) {
        let mut rng = SmallRng::from_rng(&mut rand::rng());
        while let Ok(req) = req_rx.recv().await {
            let socket_reqs = {
                let peers = peers.borrow();
                let mut mapper = RepairRequestMapper::new(&peers, &id, &keypair, &mut rng);
                match req {
                    RepairReq::MissingBoundedShreds { slot, shreds } => shreds
                        .into_iter()
                        .filter_map(|shred| mapper.map_bounded_shred(slot, shred))
                        .collect::<Vec<_>>(),
                    RepairReq::MissingUnboundedShreds {
                        slot,
                        max_exclusive_shred,
                    } => {
                        log::warn!(
                            "slot {slot} did not observe the last shred, repairing it uses a slow path"
                        );
                        let Some((req_socket, raw)) =
                            mapper.map_unbounded_shred(slot, max_exclusive_shred)
                        else {
                            continue;
                        };
                        vec![(req_socket, raw)]
                    }
                }
            };
            _ = send_socket.send(socket_reqs).await;
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

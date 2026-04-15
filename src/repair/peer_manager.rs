use std::{cell::RefCell, net::SocketAddr, rc::Rc, sync::Arc};

use rand::{Rng, SeedableRng, rngs::SmallRng};
use solana_core::repair::serve_repair::{RepairProtocol, RepairRequestHeader, ServeRepair};
use solana_gossip::{cluster_info::ClusterInfo, contact_info::Protocol};
use solana_ledger::shred::Nonce;
use solana_sdk::{
    clock::Slot, pubkey::Pubkey, signature::Keypair, signer::Signer, timing::timestamp,
};
use uluru::LRUCache;

use super::peer_cache::PeerSample;

struct RepairPeers {
    cache: LRUCache<(Slot, Vec<(SocketAddr, Pubkey)>), 200>,
    cluster_info: Arc<ClusterInfo>,
}

impl RepairPeers {
    fn new(cluster_info: Arc<ClusterInfo>) -> Self {
        Self {
            cache: LRUCache::new(),
            cluster_info,
        }
    }

    fn random_peer(
        &mut self,
        rng: &mut impl Rng,
        slot: Slot,
        peer_sample: &mut PeerSample,
    ) -> Option<(SocketAddr, Pubkey)> {
        let cached = self.cache.find(|(lru_slot, _)| *lru_slot == slot);
        if let Some((_, cached)) = cached {
            for &(addr, _) in cached.iter() {
                peer_sample.observe(addr);
            }
            return peer_sample.select_weighted(cached, rng);
        }
        let peers = self
            .cluster_info
            .repair_peers(slot)
            .into_iter()
            .filter_map(|ci| {
                let socket = ci.serve_repair(Protocol::UDP)?;
                Some((socket, *ci.pubkey()))
            })
            .collect::<Vec<_>>();
        for &(addr, _) in peers.iter() {
            peer_sample.observe(addr);
        }
        let selected = peer_sample.select_weighted(&peers, rng);
        self.cache.insert((slot, peers));

        selected
    }
}

pub struct RepairRequestMapper {
    peers: RepairPeers,
    keypair: Arc<Keypair>,
    rng: SmallRng,
    peer_sample: Rc<RefCell<PeerSample>>,
}

impl RepairRequestMapper {
    pub fn new(
        cluster_info: Arc<ClusterInfo>,
        keypair: Arc<Keypair>,
        peer_sample: Rc<RefCell<PeerSample>>,
    ) -> Self {
        Self {
            peers: RepairPeers::new(cluster_info),
            keypair,
            rng: SmallRng::from_rng(&mut rand::rng()),
            peer_sample,
        }
    }

    fn random_peer(&mut self, slot: u64) -> Option<(SocketAddr, Pubkey)> {
        if let Some(req_node) =
            self.peers
                .random_peer(&mut self.rng, slot, &mut self.peer_sample.borrow_mut())
        {
            Some(req_node)
        } else {
            log::error!("no repair peers available, unable to send repair request");
            None
        }
    }

    fn create_header(&mut self, req_pk: Pubkey) -> (Nonce, RepairRequestHeader) {
        let nonce = self.rng.random();
        (
            nonce,
            RepairRequestHeader::new(self.keypair.pubkey(), req_pk, timestamp(), nonce),
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
        let (req_socket, req_pk) = self.random_peer(slot)?;
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
        let (req_socket, req_pk) = self.random_peer(slot)?;
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

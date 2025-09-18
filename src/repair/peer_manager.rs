use std::{net::SocketAddr, sync::Arc};

use lru::LruCache;
use rand::{Rng, SeedableRng, rngs::SmallRng, seq::IndexedRandom};
use solana_core::repair::serve_repair::{RepairProtocol, RepairRequestHeader, ServeRepair};
use solana_gossip::{cluster_info::ClusterInfo, contact_info::Protocol};
use solana_ledger::shred::Nonce;
use solana_sdk::{
    clock::Slot, pubkey::Pubkey, signature::Keypair, signer::Signer, timing::timestamp,
};

#[derive(Clone)]
pub struct RepairPeers {
    cache: LruCache<Slot, Vec<(SocketAddr, Pubkey)>>,
    cluster_info: Arc<ClusterInfo>,
}

impl RepairPeers {
    pub fn new(cluster_info: Arc<ClusterInfo>) -> Self {
        Self {
            cache: LruCache::new(200.try_into().unwrap()),
            cluster_info,
        }
    }

    fn random_peer(&mut self, rng: &mut impl Rng, slot: Slot) -> Option<(SocketAddr, Pubkey)> {
        let cached = self.cache.get(&slot);
        if let Some(cached) = cached {
            return cached.choose(rng).cloned();
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
        let peer = peers.choose(rng).cloned()?;
        self.cache.put(slot, peers);

        Some(peer)
    }
}

#[derive(Clone)]
pub struct RepairRequestMapper {
    peers: RepairPeers,
    keypair: Arc<Keypair>,
    rng: SmallRng,
}

impl RepairRequestMapper {
    pub fn new(peers: RepairPeers, keypair: Arc<Keypair>) -> Self {
        Self {
            peers,
            keypair,
            rng: SmallRng::from_rng(&mut rand::rng()),
        }
    }

    fn random_peer(&mut self, slot: u64) -> Option<(SocketAddr, Pubkey)> {
        if let Some(req_node) = self.peers.random_peer(&mut self.rng, slot) {
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

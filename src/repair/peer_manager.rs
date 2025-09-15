use std::{
    net::{IpAddr, SocketAddr},
    ops::Index,
    sync::Arc,
    time::SystemTime,
};

use indexmap::IndexMap;
use rand::{Rng, SeedableRng, rngs::SmallRng, seq::IndexedRandom};
use solana_core::repair::serve_repair::{RepairProtocol, RepairRequestHeader, ServeRepair};
use solana_ledger::shred::Nonce;
use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer, timing::timestamp};

#[derive(Clone, Default)]
pub struct RepairPeers(Arc<IndexMap<IpAddr, RepairPeerInfo>>);

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

pub struct RepairPeerInfo {
    socket_addr: SocketAddr,
    pubkey: Pubkey,
    last_seen: SystemTime,
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

    fn random_peer(&mut self) -> Option<(Pubkey, SocketAddr)> {
        if let Some(req_node) = self.peers.choose(&mut self.rng) {
            Some((req_node.pubkey, req_node.socket_addr))
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

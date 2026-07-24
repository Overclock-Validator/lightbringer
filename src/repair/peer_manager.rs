use std::{cell::RefCell, net::SocketAddr, rc::Rc, sync::Arc};

use rand::{Rng, SeedableRng, rngs::SmallRng};
use solana_core::repair::serve_repair::{RepairProtocol, RepairRequestHeader, ServeRepair};
use solana_gossip::{cluster_info::ClusterInfo, contact_info::Protocol};
use solana_ledger::shred::Nonce;
use solana_sdk::{
    clock::Slot, pubkey::Pubkey, signature::Keypair, signer::Signer, timing::timestamp,
};
use uluru::LRUCache;

use crate::overlay::repair::{
    PeerSample, RepairPeerSource, RepairTarget, encode_request,
    RepairReq as OverlayRepairReq,
};

/// `RepairPeerSource` over Solana cluster gossip — `ClusterInfo::repair_peers`
/// verbatim, with the per-slot peer list cached and selection
/// latency-weighted through the shared `PeerSample`.
pub struct SolanaRepairPeers {
    cache: LRUCache<(Slot, Vec<(SocketAddr, Pubkey)>), 200>,
    cluster_info: Arc<ClusterInfo>,
    peer_sample: Rc<RefCell<PeerSample>>,
    rng: SmallRng,
}

impl SolanaRepairPeers {
    pub fn new(cluster_info: Arc<ClusterInfo>, peer_sample: Rc<RefCell<PeerSample>>) -> Self {
        Self {
            cache: LRUCache::new(),
            cluster_info,
            peer_sample,
            rng: SmallRng::from_rng(&mut rand::rng()),
        }
    }
}

impl Clone for SolanaRepairPeers {
    fn clone(&self) -> Self {
        Self::new(self.cluster_info.clone(), self.peer_sample.clone())
    }
}

impl RepairPeerSource for SolanaRepairPeers {
    fn sample_peer(&mut self, slot: Slot) -> Option<RepairTarget> {
        let mut peer_sample = self.peer_sample.borrow_mut();
        let as_targets = |peers: &[(SocketAddr, Pubkey)]| -> Vec<RepairTarget> {
            peers
                .iter()
                .map(|&(socket, pubkey)| RepairTarget::Udp(socket, pubkey))
                .collect()
        };
        let targets = match self.cache.find(|(lru_slot, _)| *lru_slot == slot) {
            Some((_, cached)) => as_targets(cached),
            None => {
                let peers = self
                    .cluster_info
                    .repair_peers(slot)
                    .into_iter()
                    .filter_map(|ci| {
                        let socket = ci.serve_repair(Protocol::UDP)?;
                        Some((socket, *ci.pubkey()))
                    })
                    .collect::<Vec<_>>();
                let targets = as_targets(&peers);
                self.cache.insert((slot, peers));
                targets
            }
        };
        for target in &targets {
            peer_sample.observe(target.pubkey());
        }
        peer_sample.select_weighted(&targets, &mut self.rng)
    }
}

pub struct RepairRequestMapper<S> {
    source: S,
    keypair: Arc<Keypair>,
    rng: SmallRng,
}

impl<S: RepairPeerSource> RepairRequestMapper<S> {
    pub fn new(source: S, keypair: Arc<Keypair>) -> Self {
        Self {
            source,
            keypair,
            rng: SmallRng::from_rng(&mut rand::rng()),
        }
    }

    fn random_peer(&mut self, slot: u64) -> Option<RepairTarget> {
        if let Some(target) = self.source.sample_peer(slot) {
            Some(target)
        } else {
            log::error!("no repair peers available, unable to send repair request");
            None
        }
    }

    fn create_header(&mut self, nonce: Nonce, req_pk: Pubkey) -> RepairRequestHeader {
        RepairRequestHeader::new(self.keypair.pubkey(), req_pk, timestamp(), nonce)
    }

    fn repair_proto_to_bytes(&self, req: &RepairProtocol) -> Vec<u8> {
        ServeRepair::repair_proto_to_bytes(req, &self.keypair)
            .expect("failed to sign repair request?!")
    }

    /// Wire bytes for `target`: the signed Solana `RepairProtocol` packet
    /// toward `Udp` endpoints, the overlay §6.4 request toward `Overlay`
    /// peers (streams self-correlate, so the nonce stays local there).
    fn map_shred(
        &mut self,
        slot: u64,
        shred_index: u32,
        highest: bool,
    ) -> Option<(RepairTarget, Nonce, Vec<u8>)> {
        let target = self.random_peer(slot)?;
        let nonce: Nonce = self.rng.random();
        let raw = match target {
            RepairTarget::Udp(_, req_pk) => {
                let header = self.create_header(nonce, req_pk);
                let req = if highest {
                    RepairProtocol::HighestWindowIndex {
                        header,
                        slot,
                        shred_index: shred_index.into(),
                    }
                } else {
                    RepairProtocol::WindowIndex {
                        header,
                        slot,
                        shred_index: shred_index.into(),
                    }
                };
                self.repair_proto_to_bytes(&req)
            }
            RepairTarget::Overlay(_) => {
                let req = if highest {
                    OverlayRepairReq::HighestWindowIndex { slot, shred_index }
                } else {
                    OverlayRepairReq::WindowIndex { slot, shred_index }
                };
                encode_request(&req)
            }
        };
        Some((target, nonce, raw))
    }

    pub fn map_bounded_shred(
        &mut self,
        slot: u64,
        shred: u32,
    ) -> Option<(RepairTarget, Nonce, Vec<u8>)> {
        self.map_shred(slot, shred, false)
    }

    pub fn map_unbounded_shred(
        &mut self,
        slot: u64,
        max_exclusive_shred: u32,
    ) -> Option<(RepairTarget, Nonce, Vec<u8>)> {
        self.map_shred(slot, max_exclusive_shred, true)
    }
}

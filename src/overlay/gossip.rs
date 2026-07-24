use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use anyhow::Result;
use arrayvec::ArrayVec;
use lrumap::{LruBTreeMap, LruMap};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    signer::Signer,
};

/// Address entries an advert may carry (bounded by construction: bincode
/// refuses to decode longer sequences into the `ArrayVec`s).
pub const MAX_ADVERT_ADDRS: usize = 4;
pub const MAX_ADVERT_VIA: usize = 4;
/// Gossip table bound (nat-traversal.md §6.1: the v1 address-keyed map was
/// unbounded, a real risk once anyone can join from home).
const MAX_GOSSIP_PEERS: usize = 4096;

/// A NAT mapping tagged with the observing peer's inbound port — §6.2:
/// untagged aggregation misclassifies port-dependent-mapping NATs. Punch
/// aiming hints, never blind-dial targets. Populated from P3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortTaggedAddr {
    pub observer_port: u16,
    pub mapping: SocketAddr,
}

/// How a peer may be reached (nat-traversal.md §6.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reachability {
    /// Dial me here (public IP, port-mapped, or confirmed-punchable).
    Direct(ArrayVec<SocketAddr, MAX_ADVERT_ADDRS>),
    /// I cannot accept unsolicited dials: reach me through an existing
    /// connection, or (from P5) coordinate a punch via `via`.
    Coordinated {
        observed: ArrayVec<PortTaggedAddr, MAX_ADVERT_ADDRS>,
        via: ArrayVec<Pubkey, MAX_ADVERT_VIA>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepairEndpoint {
    /// Solana repair protocol at this UDP socket (public peers).
    Udp(SocketAddr),
    /// Repair served over the overlay connection (P2).
    InConnection,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerAdvert {
    pub pubkey: Pubkey,
    /// Monotonic per identity; prevents replay of stale reachability.
    pub advert_seq: u64,
    /// How long the advert may be cached; receivers clamp to their own TTL.
    pub ttl_ms: u32,
    pub reachability: Reachability,
    pub repair: RepairEndpoint,
}

impl PeerAdvert {
    pub fn direct_addrs(&self) -> &[SocketAddr] {
        match &self.reachability {
            Reachability::Direct(addrs) => addrs,
            Reachability::Coordinated { .. } => &[],
        }
    }
}

/// `sig = ed25519(bincode(advert))` under `advert.pubkey` — an advert is
/// only meaningful with a valid signature; flood-forwarding must verify
/// before accepting or forwarding (fixes F8).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedPeerAdvert {
    pub advert: PeerAdvert,
    pub signature: Signature,
}

impl SignedPeerAdvert {
    pub fn sign(advert: PeerAdvert, keypair: &Keypair) -> Result<Self> {
        let message = bincode::serialize(&advert)?;
        Ok(Self {
            signature: keypair.sign_message(&message),
            advert,
        })
    }

    pub fn verify(&self) -> bool {
        bincode::serialize(&self.advert)
            .map(|message| {
                self.signature
                    .verify(self.advert.pubkey.as_ref(), &message)
            })
            .unwrap_or(false)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdvertOutcome {
    /// New peer or superseding sequence — accept and flood-forward.
    Accepted,
    /// Same sequence re-observed — refresh liveness, do not forward.
    Refreshed,
    /// Older than what we hold — replay or stale flood residue; drop.
    Stale,
}

#[derive(Clone, Debug)]
struct PeerEntry {
    advert: PeerAdvert,
    observed_at: Instant,
}

/// Identity-keyed advert store: one entry per pubkey no matter how many
/// addresses the node is seen at (fixes F3), bounded by LRU eviction.
/// Callers pass `now` explicitly (§6.9); expired entries are filtered on
/// read and reclaimed by LRU pressure.
pub struct LightbringerGossip {
    peers: LruBTreeMap<Pubkey, PeerEntry>,
    ttl: Duration,
}

impl LightbringerGossip {
    pub fn new(ttl: Duration) -> Self {
        Self {
            peers: LruBTreeMap::new(MAX_GOSSIP_PEERS),
            ttl,
        }
    }

    fn expired(&self, entry: &PeerEntry, now: Instant) -> bool {
        let ttl = self
            .ttl
            .min(Duration::from_millis(u64::from(entry.advert.ttl_ms)));
        now.saturating_duration_since(entry.observed_at) > ttl
    }

    /// Apply the §6.1 supersession rule for a signature-verified advert.
    /// Callers must have verified the signature; this only orders sequences.
    pub fn upsert(&mut self, advert: PeerAdvert, now: Instant) -> AdvertOutcome {
        let outcome = match self.peers.get_without_update(&advert.pubkey) {
            Some(entry) if !self.expired(entry, now) => {
                if advert.advert_seq < entry.advert.advert_seq {
                    return AdvertOutcome::Stale;
                } else if advert.advert_seq == entry.advert.advert_seq {
                    AdvertOutcome::Refreshed
                } else {
                    AdvertOutcome::Accepted
                }
            }
            _ => AdvertOutcome::Accepted,
        };
        self.peers.push(
            advert.pubkey,
            PeerEntry {
                advert,
                observed_at: now,
            },
        );
        outcome
    }

    pub fn get(&mut self, pubkey: &Pubkey, now: Instant) -> Option<&PeerAdvert> {
        let live = self
            .peers
            .get_without_update(pubkey)
            .is_some_and(|entry| !self.expired(entry, now));
        if !live {
            return None;
        }
        self.peers.get(pubkey).map(|entry| &entry.advert)
    }

    /// All live adverts. Consumed by the simulator oracles and (from P2)
    /// repair peer sampling.
    #[allow(dead_code)]
    pub fn peers(&self, now: Instant) -> Vec<PeerAdvert> {
        self.peers
            .iter()
            .filter(|(_, entry)| !self.expired(entry, now))
            .map(|(_, entry)| entry.advert.clone())
            .collect()
    }

    /// Peers that may be dialed on demand, with their first dial address.
    pub fn direct_peers(&self, now: Instant) -> Vec<(Pubkey, SocketAddr)> {
        self.peers
            .iter()
            .filter(|(_, entry)| !self.expired(entry, now))
            .filter_map(|(pubkey, entry)| {
                entry
                    .advert
                    .direct_addrs()
                    .first()
                    .map(|addr| (*pubkey, *addr))
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn advert(keypair: &Keypair, seq: u64, ttl_ms: u32) -> PeerAdvert {
        let mut addrs = ArrayVec::new();
        addrs.push("203.0.113.9:65410".parse().unwrap());
        PeerAdvert {
            pubkey: keypair.pubkey(),
            advert_seq: seq,
            ttl_ms,
            reachability: Reachability::Direct(addrs),
            repair: RepairEndpoint::InConnection,
        }
    }

    #[test]
    fn signature_roundtrip_and_tamper_rejection() {
        let keypair = Keypair::new();
        let signed = SignedPeerAdvert::sign(advert(&keypair, 1, 30_000), &keypair).unwrap();
        assert!(signed.verify());

        let mut tampered = signed.clone();
        tampered.advert.advert_seq = 2;
        assert!(!tampered.verify());

        let mut stolen = signed;
        stolen.advert.pubkey = Keypair::new().pubkey();
        assert!(!stolen.verify());
    }

    #[test]
    fn seq_supersession_rules() {
        let keypair = Keypair::new();
        let now = Instant::now();
        let mut gossip = LightbringerGossip::new(Duration::from_secs(30));
        assert_eq!(gossip.upsert(advert(&keypair, 5, 30_000), now), AdvertOutcome::Accepted);
        assert_eq!(gossip.upsert(advert(&keypair, 4, 30_000), now), AdvertOutcome::Stale);
        assert_eq!(gossip.upsert(advert(&keypair, 5, 30_000), now), AdvertOutcome::Refreshed);
        assert_eq!(gossip.upsert(advert(&keypair, 6, 30_000), now), AdvertOutcome::Accepted);
        assert_eq!(gossip.len(), 1);
    }

    #[test]
    fn expiry_clamps_to_advertised_ttl_and_reopens_seq() {
        let keypair = Keypair::new();
        let now = Instant::now();
        let mut gossip = LightbringerGossip::new(Duration::from_secs(30));
        gossip.upsert(advert(&keypair, 9, 1_000), now);
        assert_eq!(gossip.peers(now + Duration::from_millis(900)).len(), 1);
        assert!(gossip.peers(now + Duration::from_millis(1_100)).is_empty());
        // After expiry any sequence is acceptable again (restart recovery).
        let later = now + Duration::from_secs(2);
        assert_eq!(gossip.upsert(advert(&keypair, 1, 1_000), later), AdvertOutcome::Accepted);
    }

    #[test]
    fn one_entry_per_pubkey_and_direct_listing() {
        let keypair = Keypair::new();
        let now = Instant::now();
        let mut gossip = LightbringerGossip::new(Duration::from_secs(30));
        gossip.upsert(advert(&keypair, 1, 30_000), now);
        let coordinated = PeerAdvert {
            reachability: Reachability::Coordinated {
                observed: ArrayVec::new(),
                via: ArrayVec::new(),
            },
            ..advert(&keypair, 2, 30_000)
        };
        gossip.upsert(coordinated, now);
        assert_eq!(gossip.len(), 1);
        assert!(gossip.direct_peers(now).is_empty());
    }
}

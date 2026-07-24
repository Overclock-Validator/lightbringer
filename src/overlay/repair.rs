//! Overlay repair sub-protocol (nat-traversal.md §6.4): one request per
//! client-opened bidirectional stream, FIN-delimited in both directions.
//!
//! Deliberately NOT Solana's `RepairProtocol`: no header, no signature, no
//! nonce, no ping/pong — those authenticate identities and addresses over a
//! connectionless socket, and the QUIC connection already gives both ends
//! mutual Ed25519 authentication and a return path. Responses ride streams
//! and therefore never fight the 1242-byte datagram budget.

use std::{
    cell::RefCell,
    collections::HashMap,
    net::SocketAddr,
    rc::Rc,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use anyhow::Result;
use bincode::Options;
use circular_buffer::CircularBuffer;
use lrumap::{LruBTreeMap, LruMap};
use rand::{Rng, SeedableRng, rngs::SmallRng, seq::IndexedRandom};
use serde::{Deserialize, Serialize};
use solana_sdk::{clock::Slot, pubkey::Pubkey};

use super::gossip::RepairEndpoint;

/// Wire ceiling for an encoded request (the enum is a handful of bytes;
/// anything larger is garbage).
pub const MAX_REPAIR_REQ_WIRE: usize = 64;
/// Wire ceiling for an encoded response: a max shred (1228 B) plus enum and
/// length framing.
pub const MAX_REPAIR_RESP_WIRE: usize = 2048;
/// Per-pubkey serve cap, same order as `repair_delivery`'s UDP limit. Keyed
/// by identity, not address — a NATed peer's address is not stable.
pub const MAX_REPAIR_REQUESTS_PER_SECOND: u32 = 100;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(1);
/// Rate-limiter table bound; the connection cap (1024) bounds the live peer
/// set, the slack absorbs churn between LRU touches.
const MAX_RATE_LIMIT_PEERS: usize = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepairReq {
    WindowIndex { slot: u64, shred_index: u32 },
    HighestWindowIndex { slot: u64, shred_index: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepairResp {
    Shred(Vec<u8>),
    NotFound,
}

fn wire_options(limit: usize) -> impl Options {
    bincode::options()
        .with_limit(limit as u64)
        .reject_trailing_bytes()
}

pub fn encode_request(request: &RepairReq) -> Vec<u8> {
    wire_options(MAX_REPAIR_REQ_WIRE)
        .serialize(request)
        .expect("repair request always fits its wire ceiling")
}

pub fn decode_request(raw: &[u8]) -> Result<RepairReq> {
    Ok(wire_options(MAX_REPAIR_REQ_WIRE).deserialize(raw)?)
}

pub fn encode_response(response: &RepairResp) -> Result<Vec<u8>> {
    Ok(wire_options(MAX_REPAIR_RESP_WIRE).serialize(response)?)
}

pub fn decode_response(raw: &[u8]) -> Result<RepairResp> {
    Ok(wire_options(MAX_REPAIR_RESP_WIRE).deserialize(raw)?)
}

/// The narrow store-lookup seam of §6.4's serving side: the same two
/// queries `repair_delivery` answers over UDP, returning raw shred
/// payloads. The production driver backs this with the (blocking, fjall)
/// `ShredStore`; the simulator with an in-memory map. The overlay core
/// never touches it — lookups stay in drivers.
pub trait RepairStore {
    fn lookup(&self, request: &RepairReq) -> Option<Vec<u8>>;
}

/// One row of the repair peer view a requester samples (§6.4): every live
/// gossip identity with its advertised repair endpoint and whether an
/// overlay connection currently exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepairPeerEntry {
    pub pubkey: Pubkey,
    pub repair: RepairEndpoint,
    pub connected: bool,
}

/// Where a repair request goes (§6.4): the Solana wire format over UDP, or
/// the overlay sub-protocol on a stream over the existing connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepairTarget {
    Udp(SocketAddr, Pubkey),
    Overlay(Pubkey),
}

/// How a response finds its request: UDP responses are known only by their
/// source address, stream responses only by the peer identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepairRoute {
    Addr(SocketAddr),
    Peer(Pubkey),
}

impl RepairTarget {
    pub fn route(&self) -> RepairRoute {
        match self {
            Self::Udp(addr, _) => RepairRoute::Addr(*addr),
            Self::Overlay(pubkey) => RepairRoute::Peer(*pubkey),
        }
    }

    /// Scoring identity — pubkey in both worlds (a NATed peer's address is
    /// not stable; its identity is).
    pub fn pubkey(&self) -> Pubkey {
        match self {
            Self::Udp(_, pubkey) | Self::Overlay(pubkey) => *pubkey,
        }
    }
}

/// Peer sampling behind the repair requester (§6.4), so the RepairManager
/// loop runs unchanged in both worlds: Solana mode keeps
/// `ClusterInfo::repair_peers`, overlay mode samples the gossip view.
pub trait RepairPeerSource {
    fn sample_peer(&mut self, slot: Slot) -> Option<RepairTarget>;
}

/// Repair targets an overlay node may use, per §6.4: `Udp` endpoints are
/// always requestable (request/response over one 4-tuple traverses any NAT
/// on the requester's side); `InConnection` peers only over an existing
/// connection.
pub fn overlay_repair_targets(view: &[RepairPeerEntry]) -> Vec<RepairTarget> {
    view.iter()
        .filter_map(|entry| match entry.repair {
            RepairEndpoint::Udp(addr) => Some(RepairTarget::Udp(addr, entry.pubkey)),
            RepairEndpoint::InConnection if entry.connected => {
                Some(RepairTarget::Overlay(entry.pubkey))
            }
            RepairEndpoint::InConnection => None,
        })
        .collect()
}

/// The repair peer view the overlay driver republishes for the repair
/// manager thread (the driver owns the core; the manager only reads).
pub type SharedRepairView = Arc<RwLock<Vec<RepairPeerEntry>>>;

/// A repair request the sink demux hands to the overlay driver: open a
/// stream to `peer`, send `request`, and tag the eventual response with
/// `nonce` so the manager's outstanding store can match it.
#[derive(Clone, Debug)]
pub struct OverlayRepairCommand {
    pub peer: Pubkey,
    pub nonce: u32,
    pub request: RepairReq,
}

/// `RepairPeerSource` over the overlay gossip view: latency-weighted
/// selection (PeerSample) across Udp and in-connection targets.
pub struct OverlayRepairPeerSource {
    view: SharedRepairView,
    peer_sample: Rc<RefCell<PeerSample>>,
    rng: SmallRng,
}

impl OverlayRepairPeerSource {
    pub fn new(view: SharedRepairView, peer_sample: Rc<RefCell<PeerSample>>) -> Self {
        Self {
            view,
            peer_sample,
            rng: SmallRng::from_rng(&mut rand::rng()),
        }
    }
}

impl Clone for OverlayRepairPeerSource {
    fn clone(&self) -> Self {
        Self {
            view: self.view.clone(),
            peer_sample: self.peer_sample.clone(),
            rng: SmallRng::from_rng(&mut rand::rng()),
        }
    }
}

impl RepairPeerSource for OverlayRepairPeerSource {
    fn sample_peer(&mut self, _slot: Slot) -> Option<RepairTarget> {
        let targets = {
            let view = self.view.read().ok()?;
            overlay_repair_targets(&view)
        };
        let mut sample = self.peer_sample.borrow_mut();
        for target in &targets {
            sample.observe(target.pubkey());
        }
        sample.select_weighted(&targets, &mut self.rng)
    }
}

const MAX_SAMPLE_PEERS: usize = 6000;
const LATENCY_WINDOW: usize = 100;
const LOAD_WINDOW: u32 = 100;
const TIMEOUT_ASSUMED_LATENCY_MS: f64 = 300.0;
const REFERENCE_LATENCY_MS: f64 = 100.0;
const MAX_COMPUTED_SCORE: f64 = 92.0;
const BASELINE_SCORE: f64 = 50.0;
const HARD_FILTER_FLOOR: f64 = 1.0;
const HARD_FILTER_MIN_SAMPLES: u32 = 10;

/// Rolling window statistics using Welford's online algorithm.
struct RollingStats {
    samples: CircularBuffer<LATENCY_WINDOW, f64>,
    mean: f64,
    m2: f64,
}

impl RollingStats {
    fn new() -> Self {
        Self {
            samples: CircularBuffer::new(),
            mean: 0.0,
            m2: 0.0,
        }
    }

    fn push(&mut self, value: f64) {
        if self.samples.is_full() {
            let old = self.samples[0];
            self.samples.push_back(value);
            let n = LATENCY_WINDOW as f64;
            let old_mean = self.mean;
            self.mean = old_mean + (value - old) / n;
            self.m2 += (value - old) * (value - self.mean + old - old_mean);
            self.m2 = self.m2.max(0.0);
        } else {
            self.samples.push_back(value);
            let n = self.samples.len() as f64;
            let delta = value - self.mean;
            self.mean += delta / n;
            let delta2 = value - self.mean;
            self.m2 += delta * delta2;
        }
    }

    fn count(&self) -> usize {
        self.samples.len()
    }

    fn mean(&self) -> f64 {
        self.mean
    }

    fn cv(&self) -> f64 {
        if self.mean <= 0.0 || self.samples.len() < 2 {
            return 0.0;
        }
        let variance = self.m2 / (self.samples.len() - 1) as f64;
        variance.sqrt() / self.mean
    }
}

struct PeerStats {
    latency: RollingStats,
    requests_sent: u32,
    requests_timed_out: u32,
    score: f64,
}

impl PeerStats {
    fn new() -> Self {
        Self {
            latency: RollingStats::new(),
            requests_sent: 0,
            requests_timed_out: 0,
            score: BASELINE_SCORE,
        }
    }

    /// `score = 50 * speed_factor * consistency_factor * load_factor`
    ///
    /// Clamped to `[0, 92]`; 100 is reserved as "always select".
    fn update_score(&mut self) {
        if self.requests_sent >= HARD_FILTER_MIN_SAMPLES
            && self.requests_timed_out as f64 / self.requests_sent as f64 > 0.5
        {
            // Floor at 1.0 instead of 0.0 so the peer can still be selected
            // occasionally and eventually recover when the window resets.
            self.score = HARD_FILTER_FLOOR;
            return;
        }

        let speed_factor = if self.latency.count() == 0 {
            1.0
        } else {
            (REFERENCE_LATENCY_MS / self.latency.mean().max(1.0)).clamp(0.1, 2.0)
        };

        let consistency_factor = if self.latency.count() < 2 {
            1.0
        } else {
            let cv = self.latency.cv();
            1.0 / (1.0 + cv * cv)
        };

        let load_ratio = self.requests_sent as f64 / LOAD_WINDOW as f64;
        let load_factor = (-load_ratio * load_ratio).exp();

        self.score =
            (50.0 * speed_factor * consistency_factor * load_factor).clamp(0.0, MAX_COMPUTED_SCORE);
    }
}

/// Fixed-size repair peer score cache — the latency-weighted selection
/// behind every `RepairPeerSource`, keyed by pubkey per §6.4 (ported from
/// the address-keyed Solana-side original). When full, evicts the
/// lowest-scoring peer to make room for new observations.
pub struct PeerSample {
    peers: HashMap<Pubkey, PeerStats>,
}

impl PeerSample {
    pub fn new() -> Self {
        Self {
            peers: HashMap::with_capacity(MAX_SAMPLE_PEERS),
        }
    }

    /// Insert a new peer at baseline score 50. No-op if already tracked.
    /// When at capacity, evicts the lowest-scoring peer — but only if its
    /// score is below the baseline (otherwise the new unknown peer isn't
    /// worth displacing a proven one).
    pub fn observe(&mut self, pubkey: Pubkey) {
        if self.peers.contains_key(&pubkey) {
            return;
        }
        if self.peers.len() >= MAX_SAMPLE_PEERS {
            let worst = self
                .peers
                .iter()
                .min_by(|a, b| {
                    a.1.score
                        .partial_cmp(&b.1.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|(pubkey, stats)| (*pubkey, stats.score));
            if let Some((worst_pubkey, worst_score)) = worst {
                if worst_score < BASELINE_SCORE {
                    self.peers.remove(&worst_pubkey);
                } else {
                    return;
                }
            }
        }
        self.peers.insert(pubkey, PeerStats::new());
    }

    pub fn record_request(&mut self, pubkey: Pubkey) {
        if let Some(stats) = self.peers.get_mut(&pubkey) {
            stats.requests_sent += 1;
            if stats.requests_sent >= LOAD_WINDOW {
                stats.requests_sent = 0;
                stats.requests_timed_out = 0;
            }
            stats.update_score();
        }
    }

    pub fn record_response(&mut self, pubkey: Pubkey, latency_ms: f64) {
        if let Some(stats) = self.peers.get_mut(&pubkey) {
            stats.latency.push(latency_ms);
            stats.update_score();
        }
    }

    pub fn record_timeout(&mut self, pubkey: Pubkey) {
        if let Some(stats) = self.peers.get_mut(&pubkey) {
            stats.latency.push(TIMEOUT_ASSUMED_LATENCY_MS);
            stats.requests_timed_out += 1;
            stats.update_score();
        }
    }

    fn score(&self, pubkey: &Pubkey) -> f64 {
        self.peers
            .get(pubkey)
            .map(|s| s.score)
            .unwrap_or(BASELINE_SCORE)
    }

    /// Select a target using weighted random sampling.
    /// Falls back to uniform random if all scores are zero.
    pub fn select_weighted(
        &self,
        targets: &[RepairTarget],
        rng: &mut impl Rng,
    ) -> Option<RepairTarget> {
        targets
            .choose_weighted(rng, |target| self.score(&target.pubkey()))
            .ok()
            .or_else(|| targets.choose(rng))
            .copied()
    }
}

#[derive(Clone, Copy)]
struct RateWindow {
    window_start: Instant,
    count: u32,
}

/// Sliding-window serve-repair rate limiter keyed by pubkey. Sans-IO:
/// callers pass `now`. LRU-bounded so identity churn cannot grow it.
pub struct RepairRateLimiter {
    peers: LruBTreeMap<Pubkey, RateWindow>,
    max_per_window: u32,
}

impl RepairRateLimiter {
    pub fn new(max_per_window: u32) -> Self {
        Self {
            peers: LruBTreeMap::new(MAX_RATE_LIMIT_PEERS),
            max_per_window,
        }
    }

    /// Whether `peer` may be served another request at `now`.
    pub fn check_and_increment(&mut self, peer: Pubkey, now: Instant) -> bool {
        let mut window = self
            .peers
            .get(&peer)
            .copied()
            .unwrap_or(RateWindow {
                window_start: now,
                count: 0,
            });
        if now.saturating_duration_since(window.window_start) >= RATE_LIMIT_WINDOW {
            window.window_start = now;
            window.count = 0;
        }
        if window.count >= self.max_per_window {
            self.peers.push(peer, window);
            return false;
        }
        window.count += 1;
        self.peers.push(peer, window);
        true
    }

    #[allow(dead_code)] // oracle surface: boundedness assertions
    pub fn len(&self) -> usize {
        self.peers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip_and_bounds() {
        for request in [
            RepairReq::WindowIndex { slot: u64::MAX, shred_index: u32::MAX },
            RepairReq::HighestWindowIndex { slot: 42, shred_index: 7 },
        ] {
            let raw = encode_request(&request);
            assert!(raw.len() <= MAX_REPAIR_REQ_WIRE);
            assert_eq!(decode_request(&raw).unwrap(), request);
        }
    }

    #[test]
    fn response_roundtrip_and_bounds() {
        let shred = vec![7u8; 1228];
        let raw = encode_response(&RepairResp::Shred(shred.clone())).unwrap();
        assert!(raw.len() <= MAX_REPAIR_RESP_WIRE);
        assert_eq!(decode_response(&raw).unwrap(), RepairResp::Shred(shred));
        let raw = encode_response(&RepairResp::NotFound).unwrap();
        assert_eq!(decode_response(&raw).unwrap(), RepairResp::NotFound);
    }

    #[test]
    fn malformed_wire_is_rejected() {
        assert!(decode_request(&[]).is_err());
        assert!(decode_request(&[9, 9, 9]).is_err());
        // Trailing garbage after a valid message is rejected.
        let mut raw = encode_request(&RepairReq::WindowIndex { slot: 1, shred_index: 2 });
        raw.push(0);
        assert!(decode_request(&raw).is_err());
        // A response claiming a giant shred dies at the wire limit.
        assert!(decode_response(&vec![0u8; MAX_REPAIR_RESP_WIRE + 1]).is_err());
        assert!(decode_response(&[]).is_err());
    }

    #[test]
    fn rate_limiter_caps_per_pubkey_and_stays_bounded() {
        use solana_sdk::signer::{Signer, keypair::Keypair};
        let mut limiter = RepairRateLimiter::new(3);
        let now = Instant::now();
        let peer = Keypair::new().pubkey();
        for _ in 0..3 {
            assert!(limiter.check_and_increment(peer, now));
        }
        assert!(!limiter.check_and_increment(peer, now));
        // A different identity is unaffected.
        assert!(limiter.check_and_increment(Keypair::new().pubkey(), now));
        // The window reopens after a second.
        assert!(limiter.check_and_increment(peer, now + Duration::from_secs(1)));
        // Identity churn cannot grow the table past its LRU bound.
        for _ in 0..(2 * MAX_RATE_LIMIT_PEERS) {
            limiter.check_and_increment(Keypair::new().pubkey(), now);
        }
        assert!(limiter.len() <= MAX_RATE_LIMIT_PEERS);
    }
}

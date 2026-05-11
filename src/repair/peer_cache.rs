use std::{collections::HashMap, net::SocketAddr};

use circular_buffer::CircularBuffer;
use rand::{Rng, seq::IndexedRandom};
use solana_sdk::pubkey::Pubkey;

const MAX_PEERS: usize = 6000;
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

/// Fixed-size peer score cache. When full, evicts the lowest-scoring peer
/// to make room for new observations.
pub struct PeerSample {
    peers: HashMap<SocketAddr, PeerStats>,
}

impl PeerSample {
    pub fn new() -> Self {
        Self {
            peers: HashMap::with_capacity(MAX_PEERS),
        }
    }

    /// Insert a new peer at baseline score 50. No-op if already tracked.
    /// When at capacity, evicts the lowest-scoring peer — but only if its
    /// score is below the baseline (otherwise the new unknown peer isn't
    /// worth displacing a proven one).
    pub fn observe(&mut self, addr: SocketAddr) {
        if self.peers.contains_key(&addr) {
            return;
        }
        if self.peers.len() >= MAX_PEERS {
            let worst = self
                .peers
                .iter()
                .min_by(|a, b| {
                    a.1.score
                        .partial_cmp(&b.1.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|(addr, stats)| (*addr, stats.score));
            if let Some((worst_addr, worst_score)) = worst {
                if worst_score < BASELINE_SCORE {
                    self.peers.remove(&worst_addr);
                } else {
                    return;
                }
            }
        }
        self.peers.insert(addr, PeerStats::new());
    }

    pub fn record_request(&mut self, addr: SocketAddr) {
        if let Some(stats) = self.peers.get_mut(&addr) {
            stats.requests_sent += 1;
            if stats.requests_sent >= LOAD_WINDOW {
                stats.requests_sent = 0;
                stats.requests_timed_out = 0;
            }
            stats.update_score();
        }
    }

    pub fn record_response(&mut self, addr: SocketAddr, latency_ms: f64) {
        if let Some(stats) = self.peers.get_mut(&addr) {
            stats.latency.push(latency_ms);
            stats.update_score();
        }
    }

    pub fn record_timeout(&mut self, addr: SocketAddr) {
        if let Some(stats) = self.peers.get_mut(&addr) {
            stats.latency.push(TIMEOUT_ASSUMED_LATENCY_MS);
            stats.requests_timed_out += 1;
            stats.update_score();
        }
    }

    fn score(&self, addr: &SocketAddr) -> f64 {
        self.peers
            .get(addr)
            .map(|s| s.score)
            .unwrap_or(BASELINE_SCORE)
    }

    /// Select a peer using weighted random sampling.
    /// Falls back to uniform random if all scores are zero.
    pub fn select_weighted(
        &self,
        peers: &[(SocketAddr, Pubkey)],
        rng: &mut impl Rng,
    ) -> Option<(SocketAddr, Pubkey)> {
        peers
            .choose_weighted(rng, |&(addr, _)| self.score(&addr))
            .ok()
            .or_else(|| peers.choose(rng))
            .copied()
    }
}

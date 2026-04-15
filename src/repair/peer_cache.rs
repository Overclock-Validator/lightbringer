use std::net::SocketAddr;

use circular_buffer::CircularBuffer;
use rand::{Rng, seq::IndexedRandom};
use solana_sdk::pubkey::Pubkey;
use uluru::LRUCache;

const MAX_PEERS: usize = 2000;
const LATENCY_WINDOW: usize = 100;
const LOAD_WINDOW: u32 = 100;
const TIMEOUT_ASSUMED_LATENCY_MS: f64 = 300.0;
const REFERENCE_LATENCY_MS: f64 = 100.0;
const MAX_COMPUTED_SCORE: f64 = 92.0;

/// Rolling window statistics using Welford's online algorithm.
///
/// Uses a fixed-capacity circular buffer. When the buffer is full,
/// `push_back` evicts the oldest sample and returns it, allowing
/// an incremental mean/M2 update without recomputation.
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
            // Rolling: grab oldest before overwrite, window size unchanged
            let old = self.samples[0];
            self.samples.push_back(value);
            let n = LATENCY_WINDOW as f64;
            let old_mean = self.mean;
            self.mean = old_mean + (value - old) / n;
            self.m2 += (value - old) * (value - self.mean + old - old_mean);
            self.m2 = self.m2.max(0.0);
        } else {
            // Growing: standard Welford's add
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
            score: 50.0,
        }
    }

    /// Recompute and store the score from current stats.
    ///
    /// `score = 50 * speed_factor * consistency_factor * load_factor`
    ///
    /// - **Speed**: `clamp(100ms / avg_latency, 0.1, 2.0)`
    /// - **Consistency**: `1 / (1 + cv²)`
    /// - **Load**: `exp(-(sent/N)²)`
    /// - **Hard filter**: 0 if timeout ratio > 50%
    ///
    /// Clamped to `[0, 92]`; 100 is reserved as "always select".
    fn update_score(&mut self) {
        if self.requests_sent > 0
            && self.requests_timed_out as f64 / self.requests_sent as f64 > 0.5
        {
            self.score = 0.0;
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

    fn record_request(&mut self) {
        self.requests_sent += 1;
        if self.requests_sent >= LOAD_WINDOW {
            self.requests_sent = 0;
            self.requests_timed_out = 0;
        }
        self.update_score();
    }

    fn record_response(&mut self, latency_ms: f64) {
        self.latency.push(latency_ms);
        self.update_score();
    }

    fn record_timeout(&mut self) {
        self.latency.push(TIMEOUT_ASSUMED_LATENCY_MS);
        self.requests_timed_out += 1;
        self.update_score();
    }
}

pub struct PeerSample {
    cache: LRUCache<(SocketAddr, PeerStats), MAX_PEERS>,
}

impl PeerSample {
    pub fn new() -> Self {
        Self {
            cache: LRUCache::new(),
        }
    }

    pub fn observe(&mut self, addr: SocketAddr) {
        if self.cache.find(|(a, _)| *a == addr).is_some() {
            return;
        }
        self.cache.insert((addr, PeerStats::new()));
    }

    pub fn record_request(&mut self, addr: SocketAddr) {
        if let Some((_, stats)) = self.cache.find(|(a, _)| *a == addr) {
            stats.record_request();
        }
    }

    pub fn record_response(&mut self, addr: SocketAddr, latency_ms: f64) {
        if let Some((_, stats)) = self.cache.find(|(a, _)| *a == addr) {
            stats.record_response(latency_ms);
        }
    }

    pub fn record_timeout(&mut self, addr: SocketAddr) {
        if let Some((_, stats)) = self.cache.find(|(a, _)| *a == addr) {
            stats.record_timeout();
        }
    }

    fn score(&self, addr: &SocketAddr) -> f64 {
        self.cache
            .iter()
            .find(|(a, _)| a == addr)
            .map(|(_, stats)| stats.score)
            .unwrap_or(50.0)
    }

    pub fn select_weighted(
        &self,
        peers: &[(SocketAddr, Pubkey)],
        rng: &mut impl Rng,
    ) -> Option<(SocketAddr, Pubkey)> {
        peers
            .choose_weighted(rng, |&(addr, _)| self.score(&addr))
            .ok()
            .copied()
    }
}

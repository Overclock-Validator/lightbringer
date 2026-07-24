//! Per-link network fault model (nat-traversal.md §6.9): delay
//! distributions, drop/duplication probabilities, MTU clamps, and
//! partitions. Reordering emerges from randomized delays.

use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub struct LinkParams {
    pub delay_min: Duration,
    pub delay_max: Duration,
    pub drop_probability: f64,
    pub duplicate_probability: f64,
    /// Probability that a datagram escapes the link's FIFO ordering and may
    /// arrive before earlier traffic. Links are FIFO by default: real
    /// single paths rarely reorder within a flow, and unconstrained random
    /// delays trip QUIC's packet-threshold loss detector into spurious
    /// congestion collapse.
    pub reorder_probability: f64,
    /// Datagrams larger than this are dropped (the ~1280-MTU shred-datagram
    /// regression from nat-traversal.md §8 is expressible as a clamp here).
    pub mtu: Option<usize>,
    /// `false` partitions the link.
    pub up: bool,
}

impl Default for LinkParams {
    fn default() -> Self {
        Self {
            delay_min: Duration::from_millis(1),
            delay_max: Duration::from_millis(2),
            drop_probability: 0.0,
            duplicate_probability: 0.0,
            reorder_probability: 0.0,
            mtu: None,
            up: true,
        }
    }
}

impl LinkParams {
    pub fn delay(mut self, min: Duration, max: Duration) -> Self {
        self.delay_min = min;
        self.delay_max = max.max(min);
        self
    }

    pub fn drop_probability(mut self, p: f64) -> Self {
        self.drop_probability = p;
        self
    }

    pub fn duplicate_probability(mut self, p: f64) -> Self {
        self.duplicate_probability = p;
        self
    }

    pub fn reorder_probability(mut self, p: f64) -> Self {
        self.reorder_probability = p;
        self
    }

    pub fn mtu(mut self, mtu: usize) -> Self {
        self.mtu = Some(mtu);
        self
    }

    pub fn partitioned(mut self) -> Self {
        self.up = false;
        self
    }
}

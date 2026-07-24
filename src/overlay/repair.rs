//! Overlay repair sub-protocol (nat-traversal.md §6.4): one request per
//! client-opened bidirectional stream, FIN-delimited in both directions.
//!
//! Deliberately NOT Solana's `RepairProtocol`: no header, no signature, no
//! nonce, no ping/pong — those authenticate identities and addresses over a
//! connectionless socket, and the QUIC connection already gives both ends
//! mutual Ed25519 authentication and a return path. Responses ride streams
//! and therefore never fight the 1242-byte datagram budget.

use std::time::{Duration, Instant};

use anyhow::Result;
use bincode::Options;
use lrumap::{LruBTreeMap, LruMap};
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;

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

#[allow(dead_code)] // requester wiring lands in P2 step 3
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
#[allow(dead_code)] // constructed by the requester wiring (P2 step 3) and sim oracles
pub struct RepairPeerEntry {
    pub pubkey: Pubkey,
    pub repair: RepairEndpoint,
    pub connected: bool,
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

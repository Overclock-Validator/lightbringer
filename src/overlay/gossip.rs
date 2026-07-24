use std::{
    collections::BTreeMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayPeer {
    pub overlay_addr: SocketAddr,
    pub repair_addr: Option<SocketAddr>,
}

#[derive(Clone, Debug)]
struct PeerEntry {
    peer: OverlayPeer,
    observed_at: Instant,
}

/// Sans-IO peer table: callers pass `now` explicitly (nat-traversal.md §6.9)
/// and the map iterates in address order so peer walks are deterministic
/// under simulation.
#[derive(Clone, Debug)]
pub struct LightbringerGossip {
    peers: BTreeMap<SocketAddr, PeerEntry>,
    ttl: Duration,
}

impl LightbringerGossip {
    pub fn new(ttl: Duration) -> Self {
        Self {
            peers: BTreeMap::new(),
            ttl,
        }
    }

    pub fn observe(&mut self, peer: OverlayPeer, now: Instant) {
        self.peers.insert(
            peer.overlay_addr,
            PeerEntry {
                peer,
                observed_at: now,
            },
        );
    }

    pub fn observe_repair(&mut self, overlay_addr: SocketAddr, repair_addr: SocketAddr, now: Instant) {
        self.observe(
            OverlayPeer {
                overlay_addr,
                repair_addr: Some(repair_addr),
            },
            now,
        );
    }

    pub fn prune_expired(&mut self, now: Instant) {
        let ttl = self.ttl;
        self.peers
            .retain(|_, entry| now.saturating_duration_since(entry.observed_at) <= ttl);
    }

    pub fn peers(&mut self, now: Instant) -> Vec<OverlayPeer> {
        self.prune_expired(now);
        self.peers
            .values()
            .map(|entry| entry.peer.clone())
            .collect()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn repair_peers(&mut self, now: Instant) -> Vec<SocketAddr> {
        self.peers(now)
            .into_iter()
            .filter_map(|peer| peer.repair_addr)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repair_discovery_updates_existing_peer() {
        let overlay_addr = "127.0.0.1:10".parse().unwrap();
        let repair_addr = "127.0.0.1:11".parse().unwrap();
        let now = Instant::now();
        let mut gossip = LightbringerGossip::new(Duration::from_secs(10));
        gossip.observe(
            OverlayPeer {
                overlay_addr,
                repair_addr: None,
            },
            now,
        );
        gossip.observe_repair(overlay_addr, repair_addr, now);
        assert_eq!(gossip.repair_peers(now), vec![repair_addr]);
    }

    #[test]
    fn peers_expire_by_ttl_against_passed_now() {
        let overlay_addr = "127.0.0.1:10".parse().unwrap();
        let now = Instant::now();
        let mut gossip = LightbringerGossip::new(Duration::from_secs(10));
        gossip.observe(
            OverlayPeer {
                overlay_addr,
                repair_addr: None,
            },
            now,
        );
        assert_eq!(gossip.peers(now + Duration::from_secs(9)).len(), 1);
        assert!(gossip.peers(now + Duration::from_secs(11)).is_empty());
    }
}

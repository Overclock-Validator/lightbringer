use std::{
    collections::HashMap,
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

#[derive(Clone, Debug)]
pub struct LightbringerGossip {
    peers: HashMap<SocketAddr, PeerEntry>,
    ttl: Duration,
}

impl LightbringerGossip {
    pub fn new(ttl: Duration) -> Self {
        Self {
            peers: HashMap::new(),
            ttl,
        }
    }

    pub fn observe(&mut self, peer: OverlayPeer) {
        self.peers.insert(
            peer.overlay_addr,
            PeerEntry {
                peer,
                observed_at: Instant::now(),
            },
        );
    }

    pub fn observe_repair(&mut self, overlay_addr: SocketAddr, repair_addr: SocketAddr) {
        self.observe(OverlayPeer {
            overlay_addr,
            repair_addr: Some(repair_addr),
        });
    }

    pub fn prune_expired(&mut self) {
        let ttl = self.ttl;
        self.peers
            .retain(|_, entry| entry.observed_at.elapsed() <= ttl);
    }

    pub fn peers(&mut self) -> Vec<OverlayPeer> {
        self.prune_expired();
        self.peers
            .values()
            .map(|entry| entry.peer.clone())
            .collect()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn repair_peers(&mut self) -> Vec<SocketAddr> {
        self.peers()
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
        let mut gossip = LightbringerGossip::new(Duration::from_secs(10));
        gossip.observe(OverlayPeer {
            overlay_addr,
            repair_addr: None,
        });
        gossip.observe_repair(overlay_addr, repair_addr);
        assert_eq!(gossip.repair_peers(), vec![repair_addr]);
    }
}

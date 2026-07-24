//! Self-side address discovery (nat-traversal.md §6.2), phase P3.
//!
//! An overlay node learns its own public reachability from the address
//! observations its peers report (`OverlayFrame::AddressObservation`). This
//! module owns the bounded, port-tagged observation store and derives from it:
//! the §6.2 NAT class, the §6.2 allocator-discipline calibration (recorded for
//! P5 rung selection), and the `Coordinated{observed}` port-tagged hints per
//! the §12-Q3 flavor policy. The dial-back confirmation that promotes a class
//! to `Direct` lives in the core (`service.rs`); this module only supplies the
//! candidate and records the confirmed result.

use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
};

use arrayvec::ArrayVec;
use lrumap::{LruBTreeMap, LruMap};

use super::{
    gossip::{MAX_ADVERT_ADDRS, PortTaggedAddr},
    nat::{AllocatorProfile, NatClass, TaggedObservation, calibrate_allocator, classify_observations},
};
use solana_sdk::pubkey::Pubkey;

/// Observation store bound. One entry per observing peer; the live peer set is
/// connection-bounded, the slack absorbs churn between LRU touches.
const MAX_OBSERVERS: usize = 512;

/// What one peer reported about our public mapping, tagged with that peer's
/// address so the classifier can group by the observer's inbound port (§6.2).
#[derive(Clone, Copy, Debug)]
struct Observation {
    observer: SocketAddr,
    mapping: SocketAddr,
}

/// Bounded, port-tagged address-observation store and the §6.2 inferences
/// drawn from it. Sans-IO: pure bookkeeping, no clock or socket.
pub struct AddressDiscovery {
    /// Our bind address — the `local` reference the classifier compares
    /// against to distinguish Public from EIM.
    bind_addr: SocketAddr,
    /// One observation per observing identity, LRU-bounded.
    observations: LruBTreeMap<Pubkey, Observation>,
    /// Allocator calibration cached per NAT generation (the external IP the
    /// mappings share); recomputed when that IP changes (§6.2).
    calibration: Option<(IpAddr, Option<AllocatorProfile>)>,
}

impl AddressDiscovery {
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            observations: LruBTreeMap::new(MAX_OBSERVERS),
            calibration: None,
        }
    }

    /// Record peer `observer` (at `observer_addr`) reporting our mapping as
    /// `observed`. Supersedes that peer's previous report.
    pub fn record(&mut self, observer: Pubkey, observer_addr: SocketAddr, observed: SocketAddr) {
        // A changed external IP is a new NAT generation: drop the stale
        // calibration so it is recomputed against the current mapping.
        if let Some((generation, _)) = self.calibration
            && observed.ip() != generation
        {
            self.calibration = None;
        }
        self.observations.push(
            observer,
            Observation {
                observer: observer_addr,
                mapping: observed,
            },
        );
    }

    fn tagged(&self) -> Vec<TaggedObservation> {
        self.observations
            .iter()
            .map(|(_, obs)| TaggedObservation {
                observer: obs.observer,
                mapping: obs.mapping,
            })
            .collect()
    }

    /// The §6.2 NAT class, or `None` while observations cannot discriminate
    /// (fewer than two observer IPs).
    pub fn classify(&self) -> Option<NatClass> {
        classify_observations(self.bind_addr, &self.tagged())
    }

    /// The external IP shared by the current mappings (the NAT generation) —
    /// the most-reported mapping IP, or `None` with no observations.
    fn generation_ip(&self) -> Option<IpAddr> {
        let mut counts: BTreeMap<IpAddr, usize> = BTreeMap::new();
        for (_, obs) in self.observations.iter() {
            *counts.entry(obs.mapping.ip()).or_default() += 1;
        }
        counts
            .into_iter()
            .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)))
            .map(|(ip, _)| ip)
    }

    /// The external IP the current observations agree on. The §6.3
    /// port-mapped candidate is advertised at THIS IP (what the world
    /// routes to us), not the gateway's claimed external — behind CGN the
    /// two differ and the gateway's is unreachable.
    pub fn external_ip(&self) -> Option<IpAddr> {
        self.generation_ip()
    }

    /// The §6.2 allocator-discipline calibration for the current NAT
    /// generation, computed from the external ports observed toward distinct
    /// helper endpoints and cached until the external IP changes. `None` when
    /// there is not enough evidence (an endpoint-independent mapping presents
    /// one port and needs no calibration).
    pub fn calibrate(&mut self) -> Option<AllocatorProfile> {
        let generation = self.generation_ip()?;
        if let Some((cached_ip, profile)) = self.calibration
            && cached_ip == generation
        {
            return profile;
        }
        let external_ports: Vec<u16> = self
            .observations
            .iter()
            .filter(|(_, obs)| obs.mapping.ip() == generation)
            .map(|(_, obs)| obs.mapping.port())
            .collect();
        let profile = calibrate_allocator(self.bind_addr.port(), &external_ports);
        self.calibration = Some((generation, profile));
        profile
    }

    /// The single stable public mapping to advertise/dial-back for a
    /// `Public`/`EndpointIndependent` node (§6.2/§7). `None` for
    /// port-dependent or symmetric mappings, which have no single Direct
    /// candidate.
    pub fn consistent_mapping(&self) -> Option<SocketAddr> {
        if !self.classify()?.is_endpoint_independent() {
            return None;
        }
        self.observations.iter().next().map(|(_, obs)| obs.mapping)
    }

    /// Port-tagged `observed` hints for a `Coordinated` advert (§6.1/§12-Q3):
    /// one representative mapping per observer-port group, bounded to the
    /// advert capacity. Aiming hints only, never blind-dial targets.
    pub fn observed_hints(&self) -> ArrayVec<PortTaggedAddr, MAX_ADVERT_ADDRS> {
        let mut by_port: BTreeMap<u16, SocketAddr> = BTreeMap::new();
        for (_, obs) in self.observations.iter() {
            by_port.entry(obs.observer.port()).or_insert(obs.mapping);
        }
        by_port
            .into_iter()
            .take(MAX_ADVERT_ADDRS)
            .map(|(observer_port, mapping)| PortTaggedAddr {
                observer_port,
                mapping,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(n: u8) -> Pubkey {
        Pubkey::new_from_array([n; 32])
    }

    #[test]
    fn public_node_sees_its_bind_address() {
        let bind: SocketAddr = "203.0.113.1:65410".parse().unwrap();
        let mut disc = AddressDiscovery::new(bind);
        disc.record(pk(1), "203.0.113.9:65410".parse().unwrap(), bind);
        disc.record(pk(2), "203.0.113.8:65410".parse().unwrap(), bind);
        assert_eq!(disc.classify(), Some(NatClass::Public));
        assert_eq!(disc.consistent_mapping(), Some(bind));
    }

    #[test]
    fn eim_node_learns_stable_mapping() {
        let bind: SocketAddr = "10.0.0.2:65410".parse().unwrap();
        let mapping: SocketAddr = "198.51.100.7:40000".parse().unwrap();
        let mut disc = AddressDiscovery::new(bind);
        disc.record(pk(1), "203.0.113.9:3478".parse().unwrap(), mapping);
        disc.record(pk(2), "203.0.113.8:5000".parse().unwrap(), mapping);
        assert_eq!(disc.classify(), Some(NatClass::EndpointIndependent));
        assert_eq!(disc.consistent_mapping(), Some(mapping));
    }

    #[test]
    fn symmetric_node_has_no_direct_candidate_and_empty_stable_mapping() {
        let bind: SocketAddr = "10.0.0.2:65410".parse().unwrap();
        let mut disc = AddressDiscovery::new(bind);
        disc.record(pk(1), "203.0.113.9:3478".parse().unwrap(), "198.51.100.7:40000".parse().unwrap());
        disc.record(pk(2), "203.0.113.8:3478".parse().unwrap(), "198.51.100.7:40009".parse().unwrap());
        assert_eq!(disc.classify(), Some(NatClass::Symmetric));
        assert_eq!(disc.consistent_mapping(), None);
    }

    #[test]
    fn calibration_infers_sequential_and_recalibrates_on_ip_change() {
        let bind: SocketAddr = "10.0.0.2:51000".parse().unwrap();
        let mut disc = AddressDiscovery::new(bind);
        disc.record(pk(1), "203.0.113.9:3478".parse().unwrap(), "198.51.100.7:40000".parse().unwrap());
        disc.record(pk(2), "203.0.113.8:3478".parse().unwrap(), "198.51.100.7:40007".parse().unwrap());
        disc.record(pk(3), "203.0.113.7:3478".parse().unwrap(), "198.51.100.7:40014".parse().unwrap());
        assert_eq!(disc.calibrate(), Some(AllocatorProfile::Sequential { stride: 7 }));

        // External IP changes → new NAT generation → recalibrate against the
        // new mappings (now port-preserving, so the profile changes).
        disc.record(pk(1), "203.0.113.9:3478".parse().unwrap(), "198.51.100.8:51000".parse().unwrap());
        disc.record(pk(2), "203.0.113.8:3478".parse().unwrap(), "198.51.100.8:51000".parse().unwrap());
        disc.record(pk(3), "203.0.113.7:3478".parse().unwrap(), "198.51.100.8:51000".parse().unwrap());
        assert_eq!(disc.calibrate(), Some(AllocatorProfile::Preserving));
    }

    #[test]
    fn hints_are_one_per_observer_port_group() {
        let bind: SocketAddr = "10.0.0.2:65410".parse().unwrap();
        let mut disc = AddressDiscovery::new(bind);
        disc.record(pk(1), "203.0.113.9:3478".parse().unwrap(), "198.51.100.7:40000".parse().unwrap());
        disc.record(pk(2), "203.0.113.8:3478".parse().unwrap(), "198.51.100.7:40000".parse().unwrap());
        disc.record(pk(3), "203.0.113.7:443".parse().unwrap(), "198.51.100.7:40001".parse().unwrap());
        let hints = disc.observed_hints();
        assert_eq!(hints.len(), 2, "one hint per observer-port group");
    }
}

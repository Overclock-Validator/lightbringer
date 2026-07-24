//! NAT reachability classification and allocator calibration
//! (nat-traversal.md §6.2), shared by the overlay core and the simulator.
//!
//! These are the *inference* side of the §6.2 taxonomy: given address
//! observations reported by peers (port-tagged by the observer's inbound
//! port), decide the local NAT class and — for endpoint-dependent mappings —
//! the external-port allocation discipline. The simulator's `sim::nat::NatBox`
//! is the *ground-truth* datagram-rewriting machine these routines must
//! reproduce from observations alone; both live under `src/overlay/` so the
//! `overlay-sim` binary and the core share one implementation (never a fork).

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
};

use serde::{Deserialize, Serialize};

/// An address observation as §6.2 defines it: `mapping` is the public
/// endpoint the peer at `observer` reported seeing for us. Classification
/// groups observations by `observer.port()` (the observer's inbound port —
/// our destination port when we reached it), which is what makes the
/// port-dependent field-note NAT distinguishable from EIM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaggedObservation {
    pub observer: SocketAddr,
    pub mapping: SocketAddr,
}

/// The §6.2 reachability class inferred from port-tagged observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatClass {
    /// Every observer reports our own local address — no NAT.
    Public,
    /// Endpoint-independent mapping: one stable public mapping toward any
    /// destination. Punchable with plain hole punching.
    EndpointIndependent,
    /// Mapping consistent within each observer-port group but differing
    /// across groups — the field-note flavor (mapping keyed on destination
    /// port, ignoring destination IP).
    PortDependent,
    /// Mapping differs within a single observer-port group: a fresh mapping
    /// per destination (fully symmetric / EDM).
    Symmetric,
}

impl NatClass {
    /// Whether this class carries a single stable mapping usable as a
    /// `Direct` candidate (subject to dial-back confirmation, §6.2.3).
    /// `PortDependent`/`Symmetric` never do.
    pub fn is_endpoint_independent(self) -> bool {
        matches!(self, Self::Public | Self::EndpointIndependent)
    }
}

/// Port-tagged aggregation per nat-traversal.md §6.2: observations group by
/// the observer's inbound port; consistency within and across groups decides
/// the class. Returns `None` when the observations cannot discriminate
/// (fewer than two observer IPs, so no cross-destination evidence exists).
pub fn classify_observations(
    local: SocketAddr,
    observations: &[TaggedObservation],
) -> Option<NatClass> {
    let observer_ips: BTreeSet<IpAddr> = observations
        .iter()
        .map(|observation| observation.observer.ip())
        .collect();
    if observer_ips.len() < 2 {
        return None;
    }

    let mut groups: BTreeMap<u16, BTreeSet<SocketAddr>> = BTreeMap::new();
    for observation in observations {
        groups
            .entry(observation.observer.port())
            .or_default()
            .insert(observation.mapping);
    }

    // Differs within a single observer-port group ⇒ fully symmetric.
    if groups.values().any(|mappings| mappings.len() > 1) {
        return Some(NatClass::Symmetric);
    }

    // Consistent within groups; differing across groups ⇒ port-dependent.
    let distinct_across: BTreeSet<SocketAddr> = groups
        .values()
        .flat_map(|mappings| mappings.iter().copied())
        .collect();
    if distinct_across.len() > 1 {
        return Some(NatClass::PortDependent);
    }

    let mapping = distinct_across.into_iter().next()?;
    Some(if mapping == local {
        NatClass::Public
    } else {
        NatClass::EndpointIndependent
    })
}

/// External-port allocation discipline inferred for an endpoint-dependent
/// mapping (§6.2 allocator calibration). Recorded per NAT generation for P5
/// rung selection; nothing consumes it in P3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AllocatorProfile {
    /// External port == internal port toward every destination.
    Preserving,
    /// External ports walk the pool by a fixed stride.
    Sequential { stride: u16 },
    /// External ports scattered with no arithmetic structure.
    Random,
}

/// Minimum distinct helper endpoints a calibration burst needs (§6.2: "a
/// short burst of observations to ≥3 distinct helper endpoints").
pub const MIN_CALIBRATION_SAMPLES: usize = 3;

/// Infer the allocation discipline from the external ports observed toward a
/// set of *distinct* helper endpoints (§6.2). `internal_port` is the local
/// bind port. Requires observations from ≥[`MIN_CALIBRATION_SAMPLES`]
/// distinct external ports (endpoint-dependent mappings produce a distinct
/// mapping per destination); returns `None` otherwise — an
/// endpoint-independent mapping presents one port and cannot be calibrated
/// (nor does it need to be).
pub fn calibrate_allocator(internal_port: u16, external_ports: &[u16]) -> Option<AllocatorProfile> {
    // Port-preserving allocators present the internal port to every
    // destination — a single, constant external port equal to the bind port.
    // Recognize this before demanding distinct samples (an EDM+preserving NAT
    // looks like one port, exactly as an EIM node would).
    if !external_ports.is_empty() && external_ports.iter().all(|&port| port == internal_port) {
        return Some(AllocatorProfile::Preserving);
    }

    let distinct: BTreeSet<u16> = external_ports.iter().copied().collect();
    if distinct.len() < MIN_CALIBRATION_SAMPLES {
        return None;
    }

    // Sequential allocators walk the pool by a fixed stride: the sorted
    // distinct ports form an arithmetic progression.
    let sorted: Vec<u16> = distinct.iter().copied().collect();
    let stride = sorted[1].wrapping_sub(sorted[0]);
    if stride != 0
        && sorted
            .windows(2)
            .all(|pair| pair[1].wrapping_sub(pair[0]) == stride)
    {
        return Some(AllocatorProfile::Sequential { stride });
    }

    Some(AllocatorProfile::Random)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(observer: &str, mapping: &str) -> TaggedObservation {
        TaggedObservation {
            observer: observer.parse().unwrap(),
            mapping: mapping.parse().unwrap(),
        }
    }

    #[test]
    fn classifier_needs_two_observer_ips() {
        let local: SocketAddr = "203.0.113.1:51000".parse().unwrap();
        assert_eq!(classify_observations(local, &[]), None);
        // Two observations, one observer IP → indeterminate.
        let single_ip = [
            obs("9.9.9.9:3478", "203.0.113.1:51000"),
            obs("9.9.9.9:5000", "203.0.113.1:51000"),
        ];
        assert_eq!(classify_observations(local, &single_ip), None);
    }

    #[test]
    fn classifies_public_and_eim() {
        let local: SocketAddr = "203.0.113.1:51000".parse().unwrap();
        let public = [
            obs("9.9.9.9:3478", "203.0.113.1:51000"),
            obs("8.8.8.8:3478", "203.0.113.1:51000"),
        ];
        assert_eq!(classify_observations(local, &public), Some(NatClass::Public));

        let eim = [
            obs("9.9.9.9:3478", "198.51.100.7:40000"),
            obs("8.8.8.8:5000", "198.51.100.7:40000"),
        ];
        assert_eq!(
            classify_observations(local, &eim),
            Some(NatClass::EndpointIndependent),
        );
    }

    #[test]
    fn classifies_port_dependent_and_symmetric() {
        let local: SocketAddr = "10.0.0.2:51000".parse().unwrap();
        // Consistent within each port group, differing across ports.
        let port_dep = [
            obs("9.9.9.9:3478", "198.51.100.7:40000"),
            obs("8.8.8.8:3478", "198.51.100.7:40000"),
            obs("7.7.7.7:443", "198.51.100.7:40001"),
        ];
        assert_eq!(
            classify_observations(local, &port_dep),
            Some(NatClass::PortDependent),
        );

        // Differs within the same port group → symmetric.
        let symmetric = [
            obs("9.9.9.9:3478", "198.51.100.7:40000"),
            obs("8.8.8.8:3478", "198.51.100.7:40009"),
        ];
        assert_eq!(
            classify_observations(local, &symmetric),
            Some(NatClass::Symmetric),
        );
    }

    #[test]
    fn calibrates_allocator_disciplines() {
        assert_eq!(
            calibrate_allocator(45_000, &[45_000, 45_000, 45_000]),
            Some(AllocatorProfile::Preserving),
        );
        assert_eq!(
            calibrate_allocator(51_000, &[40_000, 40_007, 40_014]),
            Some(AllocatorProfile::Sequential { stride: 7 }),
        );
        // Scattered, non-arithmetic ports → random.
        assert_eq!(
            calibrate_allocator(51_000, &[40_000, 52_137, 43_902, 58_001]),
            Some(AllocatorProfile::Random),
        );
        // Too few distinct endpoints to calibrate a non-preserving allocator.
        assert_eq!(calibrate_allocator(51_000, &[40_000, 40_001]), None);
    }
}

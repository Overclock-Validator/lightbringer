//! P3 address-observation classification oracles (nat-traversal.md §6.2,
//! §6.1/§12-Q3), deliverables (a) and (f) plus malformed-inertness.
//!
//! The §6.2 classifier is exercised end to end through the core's observation
//! path: a peer at an established address reports our mapping in an
//! `OverlayFrame::AddressObservation`, the core tags it with that peer's
//! identity/address (`AddressDiscovery::record`), and `nat_class()` reads the
//! port-tagged inference back out. The high seam has no NAT, so a node's real
//! peers always observe its bind address (→ `Public`); to drive EIM /
//! PortDependent / Symmetric we establish "observer" peers at chosen
//! addresses and inject the mapping each one claims to see (§6.9's adversarial
//! injection seam). The low seam then proves the *live* protocol path yields
//! the same class without any injection.
//!
//! Grouping is by the observer's inbound port (our destination port when we
//! reached it) and needs ≥2 distinct observer IPs to discriminate. Seeds are
//! fixed literals; observer identities are deterministic keyed pubkeys (they
//! never sign — the QUIC connection authenticates the observer, so
//! `AddressObservation` carries no signature), matching the `discovery.rs`
//! unit-test style.

use std::net::SocketAddr;
use std::time::Duration;

use solana_sdk::pubkey::Pubkey;

use crate::overlay::nat::NatClass;
use crate::overlay::packet::OverlayFrame;
use crate::overlay::sim::highseam::{HighSeamNet, HighSeamNodeOptions};
use crate::overlay::sim::{NodeOptions, SimWorld, nat::NatConfig, net::LinkParams};
use crate::overlay::transport::OverlayTransport;

/// A distinct, deterministic observer identity. Only distinctness matters: the
/// store keys on the observing peer's pubkey, and the observation frame is
/// unsigned, so a bare keyed pubkey stands in for the peer identity — the same
/// shortcut `discovery.rs`'s own unit tests take.
fn observer_id(n: u64) -> Pubkey {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&n.to_le_bytes());
    Pubkey::new_from_array(bytes)
}

/// Establish `id`@`observer_addr` as a connection on `node`, then deliver one
/// `AddressObservation` reporting `mapping` as if it arrived over that
/// connection. Recording is gated on an established identity (§6.2 step 1), so
/// the establish must precede the inject; grouping keys on `observer_addr`'s
/// port. Each `observer_addr` must be distinct (the transport rejects a
/// duplicate bind).
fn observe(
    net: &mut HighSeamNet,
    node: usize,
    id: Pubkey,
    observer_addr: SocketAddr,
    mapping: SocketAddr,
) {
    net.core_mut(node)
        .transport_mut()
        .establish(id, observer_addr);
    let frame = OverlayFrame::address_observation(mapping)
        .encode()
        .expect("address-observation frame encodes");
    net.inject_datagram(node, observer_addr, &frame);
}

fn fresh_node(seed: u64) -> (HighSeamNet, usize) {
    let mut net = HighSeamNet::new(seed);
    let node = net.add_node(HighSeamNodeOptions::default());
    (net, node)
}

/// Deliverable (a) / §6.2 `Public`: two observers on distinct IPs both report
/// the node's own bind address (mapping == local), so the node infers no NAT.
#[test]
fn classifies_public_from_bind_observations() {
    let (mut net, node) = fresh_node(0xC1A55_E01);
    let bind = net.node_addr(node);

    observe(&mut net, node, observer_id(1), "10.1.0.1:65410".parse().unwrap(), bind);
    observe(&mut net, node, observer_id(2), "10.2.0.1:65410".parse().unwrap(), bind);

    assert_eq!(
        net.core(node).nat_class(),
        Some(NatClass::Public),
        "a node observed at its own bind address by two distinct-IP peers is Public",
    );
}

/// Deliverable (a) / §6.2 `EndpointIndependent`: two observers on distinct IPs
/// report one stable public mapping (≠ bind) — a single mapping toward any
/// destination, the plain-hole-punch case.
#[test]
fn classifies_eim_from_stable_mapping() {
    let (mut net, node) = fresh_node(0xC1A55_E02);
    let mapping: SocketAddr = "198.51.100.9:40000".parse().unwrap();

    observe(&mut net, node, observer_id(1), "10.1.0.1:65410".parse().unwrap(), mapping);
    observe(&mut net, node, observer_id(2), "10.2.0.1:65410".parse().unwrap(), mapping);

    assert_eq!(
        net.core(node).nat_class(),
        Some(NatClass::EndpointIndependent),
        "one stable mapping seen by two distinct-IP peers is EIM",
    );
}

/// Deliverable (a) / §6.2 `PortDependent`, the field-note flavor: the mapping
/// is consistent within an observer-port group but differs across groups
/// (keyed on destination port, ignoring destination IP). Two observers share
/// port 3478 (same mapping); a third on port 5321 sees a different mapping —
/// exactly what a fixed-port STUN checker would misread as EIM.
#[test]
fn classifies_port_dependent_field_note() {
    let (mut net, node) = fresh_node(0xC1A55_E03);
    let group_a: SocketAddr = "198.51.100.9:40000".parse().unwrap();
    let group_b: SocketAddr = "198.51.100.9:40001".parse().unwrap();

    observe(&mut net, node, observer_id(1), "10.1.0.1:3478".parse().unwrap(), group_a);
    observe(&mut net, node, observer_id(2), "10.2.0.1:3478".parse().unwrap(), group_a);
    observe(&mut net, node, observer_id(3), "10.3.0.1:5321".parse().unwrap(), group_b);

    assert_eq!(
        net.core(node).nat_class(),
        Some(NatClass::PortDependent),
        "consistent within each observer port, differing across ports, is PortDependent",
    );
}

/// Deliverable (a) / §6.2 `Symmetric`: two observers share one inbound port
/// (distinct IPs) yet report different mappings — a fresh mapping per
/// destination, so no single Direct candidate exists.
#[test]
fn classifies_symmetric_from_within_group_divergence() {
    let (mut net, node) = fresh_node(0xC1A55_E04);

    observe(
        &mut net,
        node,
        observer_id(1),
        "10.1.0.1:65410".parse().unwrap(),
        "198.51.100.9:40000".parse().unwrap(),
    );
    observe(
        &mut net,
        node,
        observer_id(2),
        "10.2.0.1:65410".parse().unwrap(),
        "198.51.100.9:40044".parse().unwrap(),
    );

    assert_eq!(
        net.core(node).nat_class(),
        Some(NatClass::Symmetric),
        "divergent mappings within one observer-port group is Symmetric",
    );
}

/// Deliverable (a) / §6.2 indeterminacy: with fewer than two distinct observer
/// IPs there is no cross-destination evidence, so the class stays `None` even
/// with two observations. Both observers sit on one IP (different ports).
#[test]
fn single_observer_ip_stays_unclassified() {
    let (mut net, node) = fresh_node(0xC1A55_E05);
    let mapping: SocketAddr = "198.51.100.9:40000".parse().unwrap();

    observe(&mut net, node, observer_id(1), "10.5.0.1:3478".parse().unwrap(), mapping);
    observe(&mut net, node, observer_id(2), "10.5.0.1:5321".parse().unwrap(), mapping);

    assert_eq!(
        net.core(node).nat_class(),
        None,
        "a single observer IP cannot discriminate the NAT class",
    );
}

/// Deliverable (f) / §6.1/§12-Q3 observed hints: `observed_hints()` returns one
/// representative mapping per observer-port group regardless of class. A
/// Symmetric node (divergent mappings within port 3478) whose observers span
/// ports {3478, 5321} advertises exactly two port-tagged hints, one per group.
/// (The §12-Q3 policy that a *fully* symmetric node advertises an EMPTY
/// `observed` set is enforced in `service.rs::compute_reachability`, not here;
/// `observed_hints` itself always groups by port.)
#[test]
fn observed_hints_are_one_per_observer_port_group() {
    let (mut net, node) = fresh_node(0xC1A55_E06);

    // Port group 3478: two observers, divergent mappings → classifies Symmetric.
    observe(
        &mut net,
        node,
        observer_id(1),
        "10.1.0.1:3478".parse().unwrap(),
        "198.51.100.9:40000".parse().unwrap(),
    );
    observe(
        &mut net,
        node,
        observer_id(2),
        "10.2.0.1:3478".parse().unwrap(),
        "198.51.100.9:40044".parse().unwrap(),
    );
    // Port group 5321: a third observer on another port.
    observe(
        &mut net,
        node,
        observer_id(3),
        "10.3.0.1:5321".parse().unwrap(),
        "198.51.100.9:40100".parse().unwrap(),
    );

    assert_eq!(
        net.core(node).nat_class(),
        Some(NatClass::Symmetric),
        "the within-group divergence classifies Symmetric",
    );

    let hints = net.core(node).observed_hints();
    let ports: Vec<u16> = hints.iter().map(|hint| hint.observer_port).collect();
    assert_eq!(
        ports,
        vec![3478, 5321],
        "one port-tagged hint per observer-port group, sorted by port",
    );
}

/// Bounded observation store (§6.2, `MAX_OBSERVERS = 512`): churning far more
/// than 512 distinct observer identities never panics, and afterwards the node
/// still classifies. Every churned observer sits on one shared inbound port,
/// on a distinct IP, reporting one stable mapping (≠ bind), so whatever subset
/// the LRU retains still presents a clean EIM signature — proving the store
/// stays live and correct across the bound. Gossip is untouched throughout.
#[test]
fn observation_store_is_bounded_and_stays_live() {
    const CHURN: u64 = 600;
    let (mut net, node) = fresh_node(0xC1A55_E07);
    let mapping: SocketAddr = "198.51.100.50:40000".parse().unwrap();

    for i in 0..CHURN {
        let hi = (i / 250) as u8;
        let lo = (i % 250) as u8 + 1;
        let observer_addr = SocketAddr::from(([100, 64, hi, lo], 4000));
        observe(&mut net, node, observer_id(i), observer_addr, mapping);
    }

    // Still classifies after churning past the 512-entry bound: the retained
    // observers all agree on one mapping over distinct IPs → EIM.
    assert_eq!(
        net.core(node).nat_class(),
        Some(NatClass::EndpointIndependent),
        "the node still classifies after churning {CHURN} observers past the bound",
    );
    assert_eq!(
        net.core(node).gossip_len(),
        0,
        "address observations must never touch the gossip table",
    );
}

/// Malformed / forged observations are inert. A truncated frame (empty body),
/// a garbage-body frame, and a well-formed observation from a NON-established
/// address (identity gate `peer_identity` → `None`, §6.2 step 1) must all be
/// dropped without panic and without corrupting the class: a subsequent valid
/// observation set still classifies correctly, and gossip is untouched.
#[test]
fn malformed_and_forged_observations_are_inert() {
    let (mut net, node) = fresh_node(0xC1A55_E08);

    // An established observer whose only frames are junk records nothing.
    let obs1: SocketAddr = "10.1.0.1:65410".parse().unwrap();
    net.core_mut(node)
        .transport_mut()
        .establish(observer_id(1), obs1);
    net.inject_datagram(node, obs1, &[1u8, 2]); // frame type 2, empty body
    net.inject_datagram(node, obs1, &[1u8, 2, 0xFF]); // frame type 2, garbage body

    // A well-formed observation from an address that is not an established
    // connection is ignored: the identity gate rejects it.
    let stray: SocketAddr = "10.9.9.9:65410".parse().unwrap();
    assert!(
        net.core(node).transport().peer_identity(stray).is_none(),
        "the stray address is not an established connection",
    );
    let forged = OverlayFrame::address_observation("198.51.100.9:40000".parse().unwrap())
        .encode()
        .expect("frame encodes");
    net.inject_datagram(node, stray, &forged);

    assert_eq!(
        net.core(node).nat_class(),
        None,
        "no valid observation was recorded, so the class stays indeterminate",
    );
    assert_eq!(net.core(node).gossip_len(), 0, "junk frames never touch gossip");

    // The class is uncorrupted: a fresh valid set still classifies EIM.
    let mapping: SocketAddr = "198.51.100.9:40000".parse().unwrap();
    observe(&mut net, node, observer_id(2), "10.2.0.1:65410".parse().unwrap(), mapping);
    observe(&mut net, node, observer_id(3), "10.3.0.1:65410".parse().unwrap(), mapping);
    assert_eq!(
        net.core(node).nat_class(),
        Some(NatClass::EndpointIndependent),
        "a valid observation set classifies correctly after the junk",
    );
}

/// Deliverable (a), live protocol path (low seam): a real full-cone
/// (endpoint-independent) subject behind a NAT, dialing three public observers
/// spread across ports {3478, 3478, 5321} on distinct IPs, classifies EIM from
/// the `AddressObservation` frames those peers actually send it — no injection.
/// This proves the in-protocol path, not just the injected-observation seam,
/// reaches the §6.2 verdict.
#[test]
fn low_seam_full_cone_subject_classifies_eim_in_protocol() {
    let mut world = SimWorld::with_trace(0xC1A55_E09, false);
    world.set_default_link(
        LinkParams::default().delay(Duration::from_millis(2), Duration::from_millis(6)),
    );

    // Observers: two share an inbound port on distinct IPs (the within-group
    // check), one on another port (the across-group check).
    let observer_ports = [3478u16, 3478, 5321];
    let observer_addrs: Vec<SocketAddr> = observer_ports
        .iter()
        .map(|&port| {
            let observer = world.add_node(NodeOptions {
                bind_port: port,
                ..NodeOptions::default()
            });
            world.public_addr(observer)
        })
        .collect();

    // Subject binds inside the NAT's external pool (40000-59999) so a
    // port-preserving allocator can present its internal port, and is
    // zero-config so it must discover its own reachability.
    let subject = world.add_node(NodeOptions {
        nat: vec![NatConfig::full_cone()],
        static_peers: observer_addrs,
        bind_port: 51_000,
        zero_config: true,
        ..NodeOptions::default()
    });

    // Connections + observations settle within a couple of advert cycles.
    world.run_for(Duration::from_secs(35));

    assert_eq!(
        world.nat_class(subject),
        Some(NatClass::EndpointIndependent),
        "a full-cone subject classifies EIM from live in-protocol observations",
    );
}

//! Deliverable (c): the §6.2 NAT taxonomy made executable. The presets
//! classify as the port-tagged observation procedure predicts, and the
//! [`NatBox`] state machine honors its mapping/filtering/allocator/lifetime
//! contract at the datagram level.

use std::net::{IpAddr, SocketAddr};

use crate::overlay::sim::{
    SimWorld,
    nat::{NatBox, NatConfig, NatDropReason, TaggedObservation, classify_observations},
    scenario,
};

const EXTERNAL_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 9));
const SEC: u64 = 1_000_000_000;

fn internal() -> SocketAddr {
    SocketAddr::from(([10, 0, 0, 2], 51_000))
}

/// The full §6.2 procedure over every preset classifies as the taxonomy
/// predicts, across fixed seeds.
#[test]
fn nat_classify_scenario_ok() {
    for seed in [1u64, 424_242] {
        let outcome = scenario::nat_classify(seed, false);
        assert!(outcome.ok, "seed {seed}: {}", outcome.summary);
    }
}

/// Each `CLASSIFY_CASES` entry, run through the observation procedure on a
/// fresh world, yields its expected class — including the port-preserving
/// symmetric NAT that presents as EIM (§6.5.1 rung 2) and the field-note NAT
/// that presents as port-dependent EDM.
#[test]
fn classify_cases_match_expected() {
    for (name, preset, expected) in scenario::CLASSIFY_CASES {
        let mut world = SimWorld::new(99);
        let got = scenario::classify_one(&mut world, preset.map(|make| make()));
        assert_eq!(got, Some(*expected), "case {name}");
    }
}

/// The §6.2 field note verbatim: destination-port-keyed mapping. Three
/// distinct destination IPs on the same destination port share one external
/// mapping; the same destination IP on a different port gets a fresh one.
#[test]
fn field_note_mapping_keyed_on_dst_port() {
    let mut nat = NatBox::new(NatConfig::field_note_fiber(), EXTERNAL_IP, 1);
    let src = internal();

    let to_a = nat.outbound(0, src, SocketAddr::from(([1, 1, 1, 1], 3478))).unwrap();
    let to_b = nat.outbound(0, src, SocketAddr::from(([2, 2, 2, 2], 3478))).unwrap();
    let to_c = nat.outbound(0, src, SocketAddr::from(([3, 3, 3, 3], 3478))).unwrap();

    assert!(to_a.created);
    assert!(!to_b.created, "second dst IP on the same port reuses the mapping");
    assert!(!to_c.created);
    assert_eq!(to_a.external, to_b.external);
    assert_eq!(to_b.external, to_c.external);

    // Same destination IP, different destination port: different mapping.
    let to_other_port = nat.outbound(0, src, SocketAddr::from(([1, 1, 1, 1], 443))).unwrap();
    assert!(to_other_port.created);
    assert_ne!(to_a.external, to_other_port.external);
    assert_eq!(nat.stats.mappings_created, 2);
}

/// Endpoint-independent filtering admits any source once the mapping exists.
#[test]
fn filtering_endpoint_independent_admits_any_source() {
    let mut nat = NatBox::new(NatConfig::full_cone(), EXTERNAL_IP, 1);
    let src = internal();
    let peer = SocketAddr::from(([1, 1, 1, 1], 9000));
    let external = nat.outbound(0, src, peer).unwrap().external;

    assert_eq!(nat.inbound(1, peer, external).unwrap(), src);
    let stranger = SocketAddr::from(([2, 2, 2, 2], 1234));
    assert_eq!(nat.inbound(1, stranger, external).unwrap(), src);
    assert_eq!(nat.stats.filtered_drops, 0);
}

/// Address-restricted filtering admits the peer's IP on any port but rejects
/// other IPs.
#[test]
fn filtering_address_restricted() {
    let mut nat = NatBox::new(NatConfig::restricted_cone(), EXTERNAL_IP, 1);
    let src = internal();
    let peer = SocketAddr::from(([1, 1, 1, 1], 9000));
    let external = nat.outbound(0, src, peer).unwrap().external;

    let same_ip_other_port = SocketAddr::from(([1, 1, 1, 1], 9999));
    assert_eq!(nat.inbound(1, same_ip_other_port, external).unwrap(), src);

    let other_ip = SocketAddr::from(([2, 2, 2, 2], 9000));
    assert_eq!(nat.inbound(1, other_ip, external), Err(NatDropReason::Filtered));
    assert_eq!(nat.stats.filtered_drops, 1);
}

/// Port-restricted filtering admits exactly the peer 4-tuple's (IP, port).
#[test]
fn filtering_port_restricted() {
    let mut nat = NatBox::new(NatConfig::port_restricted_cone(), EXTERNAL_IP, 1);
    let src = internal();
    let peer = SocketAddr::from(([1, 1, 1, 1], 9000));
    let external = nat.outbound(0, src, peer).unwrap().external;

    assert_eq!(nat.inbound(1, peer, external).unwrap(), src);

    let same_ip_other_port = SocketAddr::from(([1, 1, 1, 1], 9999));
    assert_eq!(
        nat.inbound(1, same_ip_other_port, external),
        Err(NatDropReason::Filtered)
    );
    assert_eq!(nat.stats.filtered_drops, 1);
}

/// Mappings refresh on outbound only. Outbound resends hold the mapping open;
/// inbound traffic does not, so an inbound-only gap past the idle window
/// expires it; the next outbound then allocates a fresh (higher) port.
#[test]
fn mapping_lifecycle_outbound_refreshes_inbound_does_not() {
    let src = internal();
    let peer = SocketAddr::from(([1, 1, 1, 1], 9000));

    // Outbound refreshes: a resend at 20s carries the mapping to 40s.
    let mut refreshed = NatBox::new(NatConfig::symmetric_sequential(1), EXTERNAL_IP, 1);
    let external = refreshed.outbound(0, src, peer).unwrap().external;
    refreshed.outbound(20 * SEC, src, peer).unwrap();
    assert_eq!(refreshed.inbound(40 * SEC, peer, external).unwrap(), src);
    assert_eq!(refreshed.stats.expired_drops, 0);

    // Inbound does not refresh: an admitted inbound at 20s cannot hold the
    // mapping, so it is expired by 40s (last refresh stayed at t=0).
    let mut stale = NatBox::new(NatConfig::symmetric_sequential(1), EXTERNAL_IP, 2);
    let external = stale.outbound(0, src, peer).unwrap().external;
    assert_eq!(stale.inbound(20 * SEC, peer, external).unwrap(), src);
    assert_eq!(
        stale.inbound(40 * SEC, peer, external),
        Err(NatDropReason::MappingExpired)
    );
    assert_eq!(stale.stats.expired_drops, 1);

    // A fresh outbound after expiry allocates a new mapping on the next
    // sequential port.
    let reborn = stale.outbound(41 * SEC, src, peer).unwrap();
    assert!(reborn.created);
    assert_ne!(reborn.external, external);
    assert_eq!(reborn.external.port(), external.port() + 1);
}

/// Sequential allocation walks the pool by the configured stride, one step
/// per distinct-destination mapping.
#[test]
fn allocator_sequential_stride_walks_pool() {
    let stride = 7u16;
    let mut nat = NatBox::new(NatConfig::symmetric_sequential(stride), EXTERNAL_IP, 1);
    let src = internal();
    let lo = 40_000u16;

    for i in 0..4u16 {
        let dst = SocketAddr::from(([1, 1, 1, (i + 1) as u8], 9000));
        let pass = nat.outbound(0, src, dst).unwrap();
        assert!(pass.created);
        assert_eq!(pass.external.port(), lo + i * stride);
    }
}

/// A port-preserving allocator presents the internal source port externally.
#[test]
fn allocator_preserving_presents_internal_port() {
    let mut nat = NatBox::new(NatConfig::symmetric_preserving(), EXTERNAL_IP, 1);
    let src = SocketAddr::from(([10, 0, 0, 2], 45_000));
    let peer = SocketAddr::from(([1, 1, 1, 1], 9000));
    let pass = nat.outbound(0, src, peer).unwrap();
    assert_eq!(pass.external.port(), 45_000);
}

/// A CGN-flavored NAT with a small port budget exhausts once enough distinct
/// destinations demand distinct mappings.
#[test]
fn allocator_cgn_pool_exhausts() {
    let pool = 4u16;
    let mut nat = NatBox::new(NatConfig::cgn_random(pool), EXTERNAL_IP, 1);
    let src = internal();

    let mut created = 0u64;
    let mut exhausted = false;
    for i in 0..64u16 {
        let dst = SocketAddr::from(([1, 1, 0, i as u8], 9000));
        match nat.outbound(0, src, dst) {
            Ok(pass) => {
                assert!(pass.created);
                created += 1;
            }
            Err(NatDropReason::PortPoolExhausted) => {
                exhausted = true;
                break;
            }
            Err(other) => panic!("unexpected drop {other:?}"),
        }
    }

    assert!(exhausted, "a bounded pool must eventually exhaust");
    assert!(created <= u64::from(pool));
    assert!(nat.stats.pool_exhausted_drops >= 1);
}

/// The classifier needs at least two distinct observer IPs to discriminate;
/// empty and single-IP observation sets are indeterminate.
#[test]
fn classifier_edge_cases_return_none() {
    let local = SocketAddr::from(([203, 0, 113, 1], 51_000));
    assert_eq!(classify_observations(local, &[]), None);

    // Two observations, but a single observer IP (differing only by port).
    let observations = [
        TaggedObservation {
            observer: SocketAddr::from(([9, 9, 9, 9], 3478)),
            mapping: local,
        },
        TaggedObservation {
            observer: SocketAddr::from(([9, 9, 9, 9], 5000)),
            mapping: local,
        },
    ];
    assert_eq!(classify_observations(local, &observations), None);
}

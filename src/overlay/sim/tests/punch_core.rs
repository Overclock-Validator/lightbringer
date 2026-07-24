//! Low-seam P5 packet truth: a targeted Coordinated→Coordinated request is
//! relayed through an authenticated public peer, raw probes open the NAT
//! filters, and the lower-pubkey side creates an ordinary QUIC connection.

use std::time::Duration;

use crate::overlay::sim::{NodeOptions, SimWorld, nat::NatConfig, net::LinkParams};
use crate::overlay::{
    nat::NatClass,
    service::{BIRTHDAY_DURATION, BIRTHDAY_SOCKET_CAP, BIRTHDAY_SPRAY_CAP},
};

#[test]
fn targeted_eim_punch_establishes_an_ordinary_quic_connection() {
    let mut world = SimWorld::with_trace(0x5055_4E43, false);
    world.set_default_link(
        LinkParams::default().delay(Duration::from_millis(2), Duration::from_millis(6)),
    );
    let via = world.add_node(NodeOptions::default());
    let via_addr = world.public_addr(via);
    // Port-restricted cone mappings are EIM but cannot pass P3's fresh-source
    // dial-back. They therefore stay Coordinated and exercise P5 honestly.
    let a = world.add_node(NodeOptions {
        nat: vec![NatConfig::port_restricted_cone()],
        static_peers: vec![via_addr],
        bind_port: 51_000,
        zero_config: true,
        ..NodeOptions::default()
    });
    let b = world.add_node(NodeOptions {
        nat: vec![NatConfig::port_restricted_cone()],
        static_peers: vec![via_addr],
        bind_port: 51_001,
        zero_config: true,
        ..NodeOptions::default()
    });
    let a_pk = world.overlay_pubkey(a);
    let b_pk = world.overlay_pubkey(b);

    // t=10 establishes static links; observations land after that advert;
    // t=20 floods the useful Coordinated hints through the via.
    world.run_for(Duration::from_secs(30));
    assert!(world.request_direct_path(a, b_pk));
    world.run_for(Duration::from_secs(6));

    assert!(
        world.peer_connection_addr(a, &b_pk).is_some()
            && world.peer_connection_addr(b, &a_pk).is_some(),
        "a successful punch must become a normal authenticated QUIC connection",
    );
}

#[test]
fn same_port_helper_upgrades_field_note_nat_to_port_restricted_peer() {
    let mut world = SimWorld::with_trace(0x5055_4E44, false);
    world.set_default_link(
        LinkParams::default().delay(Duration::from_millis(2), Duration::from_millis(6)),
    );
    // §6.2 needs two observers on one port and a third on another to expose
    // the dst-port mapping flavor. All are public and connected, hence valid
    // shared-via candidates; no gateway mapping is present.
    let v1 = world.add_node(NodeOptions {
        bind_port: 3478,
        ..NodeOptions::default()
    });
    let v2 = world.add_node(NodeOptions {
        bind_port: 3478,
        ..NodeOptions::default()
    });
    let v3 = world.add_node(NodeOptions {
        bind_port: 5321,
        ..NodeOptions::default()
    });
    let via_addrs = vec![world.public_addr(v1), world.public_addr(v2), world.public_addr(v3)];
    let a = world.add_node(NodeOptions {
        nat: vec![NatConfig::field_note_fiber()],
        static_peers: via_addrs.clone(),
        bind_port: 51_000,
        zero_config: true,
        ..NodeOptions::default()
    });
    let b = world.add_node(NodeOptions {
        nat: vec![NatConfig::port_restricted_cone()],
        static_peers: vec![via_addrs[0]],
        bind_port: 51_001,
        zero_config: true,
        ..NodeOptions::default()
    });
    let a_pk = world.overlay_pubkey(a);
    let b_pk = world.overlay_pubkey(b);
    world.run_for(Duration::from_secs(45));
    assert_eq!(world.nat_class(a), Some(NatClass::PortDependent));
    assert!(world.request_direct_path(a, b_pk));
    world.run_for(Duration::from_secs(6));
    assert!(
        world.peer_connection_addr(a, &b_pk).is_some()
            && world.peer_connection_addr(b, &a_pk).is_some(),
        "same-port helper must publish the per-destination mapping to B",
    );
}

#[test]
fn sequential_symmetric_bracket_opens_port_restricted_peer_filter() {
    let mut world = SimWorld::with_trace(0x5055_4E42, false);
    world.set_default_link(
        LinkParams::default().delay(Duration::from_millis(2), Duration::from_millis(6)),
    );
    let v1 = world.add_node(NodeOptions {
        bind_port: 3478,
        ..NodeOptions::default()
    });
    let v2 = world.add_node(NodeOptions {
        bind_port: 3478,
        ..NodeOptions::default()
    });
    let v3 = world.add_node(NodeOptions {
        bind_port: 5321,
        ..NodeOptions::default()
    });
    let via_addrs = vec![world.public_addr(v1), world.public_addr(v2), world.public_addr(v3)];
    let a = world.add_node(NodeOptions {
        nat: vec![NatConfig::symmetric_sequential(1)],
        static_peers: via_addrs.clone(),
        bind_port: 51_000,
        zero_config: true,
        ..NodeOptions::default()
    });
    let b = world.add_node(NodeOptions {
        nat: vec![NatConfig::port_restricted_cone()],
        static_peers: vec![via_addrs[0]],
        bind_port: 51_001,
        zero_config: true,
        ..NodeOptions::default()
    });
    let a_pk = world.overlay_pubkey(a);
    let b_pk = world.overlay_pubkey(b);
    world.run_for(Duration::from_secs(45));
    assert_eq!(world.nat_class(a), Some(NatClass::Symmetric));
    assert!(world.request_direct_path(a, b_pk));
    world.run_for(Duration::from_secs(6));
    assert!(
        world.peer_connection_addr(a, &b_pk).is_some()
            && world.peer_connection_addr(b, &a_pk).is_some(),
        "sequential bracket must be capped and sufficient to find P",
    );
}

#[test]
fn sequential_symmetric_double_bracket_composes_both_predictions() {
    let mut world = SimWorld::with_trace(0x5055_4E53, false);
    world.set_default_link(
        LinkParams::default().delay(Duration::from_millis(2), Duration::from_millis(6)),
    );
    let v1 = world.add_node(NodeOptions {
        bind_port: 3478,
        ..NodeOptions::default()
    });
    let v2 = world.add_node(NodeOptions {
        bind_port: 3478,
        ..NodeOptions::default()
    });
    let v3 = world.add_node(NodeOptions {
        bind_port: 5321,
        ..NodeOptions::default()
    });
    let via_addrs = vec![world.public_addr(v1), world.public_addr(v2), world.public_addr(v3)];
    let a = world.add_node(NodeOptions {
        nat: vec![NatConfig::symmetric_sequential(1)],
        static_peers: via_addrs.clone(),
        bind_port: 51_000,
        zero_config: true,
        ..NodeOptions::default()
    });
    let b = world.add_node(NodeOptions {
        nat: vec![NatConfig::symmetric_sequential(1)],
        static_peers: via_addrs,
        bind_port: 51_001,
        zero_config: true,
        ..NodeOptions::default()
    });
    let a_pk = world.overlay_pubkey(a);
    let b_pk = world.overlay_pubkey(b);
    world.run_for(Duration::from_secs(45));
    assert_eq!(world.nat_class(a), Some(NatClass::Symmetric));
    assert_eq!(world.nat_class(b), Some(NatClass::Symmetric));
    assert!(world.request_direct_path(a, b_pk));
    world.run_for(Duration::from_secs(6));
    assert!(
        world.peer_connection_addr(a, &b_pk).is_some()
            && world.peer_connection_addr(b, &a_pk).is_some(),
        "both sequential allocators must compose their predicted next mappings",
    );
}

#[test]
fn random_symmetric_uses_opt_in_birthday_volley() {
    // These hard ceilings are part of the operator-facing cost contract:
    // one P5 exchange cannot consume more than 256 ephemeral mappings, send
    // more than 1,024 target sprays, or run beyond 20 seconds.
    assert_eq!(BIRTHDAY_SOCKET_CAP, 256);
    assert_eq!(BIRTHDAY_SPRAY_CAP, 1_024);
    assert_eq!(BIRTHDAY_DURATION, Duration::from_secs(20));

    let mut world = SimWorld::with_trace(0x5055_4E33, false);
    world.set_default_link(
        LinkParams::default().delay(Duration::from_millis(2), Duration::from_millis(6)),
    );
    let v1 = world.add_node(NodeOptions {
        bind_port: 3478,
        ..NodeOptions::default()
    });
    let v2 = world.add_node(NodeOptions {
        bind_port: 3478,
        ..NodeOptions::default()
    });
    let v3 = world.add_node(NodeOptions {
        bind_port: 5321,
        ..NodeOptions::default()
    });
    let via_addrs = vec![world.public_addr(v1), world.public_addr(v2), world.public_addr(v3)];
    let a = world.add_node(NodeOptions {
        nat: vec![NatConfig::symmetric_random()],
        static_peers: via_addrs.clone(),
        bind_port: 51_000,
        zero_config: true,
        birthday_punch: true,
        ..NodeOptions::default()
    });
    let b = world.add_node(NodeOptions {
        nat: vec![NatConfig::port_restricted_cone()],
        static_peers: vec![via_addrs[0]],
        bind_port: 51_001,
        zero_config: true,
        birthday_punch: true,
        ..NodeOptions::default()
    });
    let a_pk = world.overlay_pubkey(a);
    let b_pk = world.overlay_pubkey(b);
    world.run_for(Duration::from_secs(45));
    assert_eq!(world.nat_class(a), Some(NatClass::Symmetric));
    assert!(world.request_direct_path(a, b_pk));
    world.run_for(Duration::from_secs(8));
    assert!(
        world.peer_connection_addr(a, &b_pk).is_some()
            && world.peer_connection_addr(b, &a_pk).is_some(),
        "opt-in birthday sockets plus the capped target spray must find a mapping",
    );
}

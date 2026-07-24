//! Deliverable (d): QUIC keepalives hold a NAT mapping open across a long
//! idle period (design doc F7 / §6.6). A bare transport node makes a
//! genuinely idle connection through a NAT that expires idle mappings; with
//! the production 10s keepalive the mapping survives, and without it the
//! mapping dies and post-idle inbound traffic is dropped at the NAT.

use std::time::Duration;

use crate::overlay::sim::{NodeOptions, SimWorld, nat::NatConfig, scenario};

/// The public-side address a NATed transport node's dial is observed at,
/// after running the world long enough for the handshake to complete.
fn dial_and_capture_mapping(
    world: &mut SimWorld,
    natted: crate::overlay::sim::HostId,
    public: crate::overlay::sim::HostId,
) -> std::net::SocketAddr {
    let public_addr = world.public_addr(public);
    world.transport_send(natted, public_addr, b"dial-from-behind-nat".to_vec());
    world.run_for(Duration::from_secs(5));
    world
        .transport_received(public)
        .first()
        .expect("public node received the NATed node's dial")
        .0
}

/// With keepalives, the mapping survives the idle and the public side can
/// reach the NATed node afterwards, across fixed seeds.
#[test]
fn keepalive_scenario_holds_mapping() {
    for seed in [1u64, 7] {
        let outcome = scenario::keepalive_nat(seed, false, true);
        assert!(outcome.ok, "keepalive seed {seed}: {}", outcome.summary);
    }
}

/// The control: without keepalives the mapping dies during the idle (the
/// scenario's `ok` asserts exactly that).
#[test]
fn keepalive_control_scenario_lets_mapping_die() {
    for seed in [1u64, 7] {
        let outcome = scenario::keepalive_nat(seed, false, false);
        assert!(outcome.ok, "control seed {seed}: {}", outcome.summary);
    }
}

/// Direct world: a NATed transport node behind a 60s-idle NAT holds its
/// mapping across 300s of virtual idle time under the default 10s keepalive,
/// so a public→mapping datagram after the idle still arrives. The link is
/// clean, so no QUIC loss and no NAT expiry are observed.
#[test]
fn keepalive_holds_nat_mapping_direct() {
    let mut world = SimWorld::new(1);
    let public = world.add_transport_node(NodeOptions::default());
    let natted = world.add_transport_node(NodeOptions {
        nat: vec![NatConfig::port_restricted_cone().idle_timeout(Duration::from_secs(60))],
        ..NodeOptions::default()
    });

    let mapping = dial_and_capture_mapping(&mut world, natted, public);

    world.run_for(Duration::from_secs(300));

    world.transport_send(public, mapping, b"after-idle".to_vec());
    world.run_for(Duration::from_secs(5));

    assert!(
        world
            .transport_received(natted)
            .iter()
            .any(|(_, payload)| payload == b"after-idle"),
        "keepalives should have held the NAT mapping open across the idle"
    );
    assert_eq!(
        world.nat_stats(natted)[0].expired_drops,
        0,
        "no mapping should have expired"
    );
    for (_, stats) in world.transport_stats(natted) {
        assert_eq!(stats.path.lost_packets, 0, "clean link: no QUIC loss");
    }
}

/// Control twin of the direct test: keepalives and the idle timeout disabled
/// on both nodes. The connection sits genuinely silent, the NAT mapping
/// expires, and the post-idle datagram never reaches the NATed node.
#[test]
fn without_keepalive_nat_mapping_dies_direct() {
    let mut world = SimWorld::new(1);
    let silent = || NodeOptions {
        keep_alive_interval: None,
        max_idle_timeout: None,
        ..NodeOptions::default()
    };
    let public = world.add_transport_node(silent());
    let natted = world.add_transport_node(NodeOptions {
        nat: vec![NatConfig::port_restricted_cone().idle_timeout(Duration::from_secs(60))],
        ..silent()
    });

    let mapping = dial_and_capture_mapping(&mut world, natted, public);

    world.run_for(Duration::from_secs(300));

    world.transport_send(public, mapping, b"after-idle".to_vec());
    world.run_for(Duration::from_secs(5));

    assert!(
        !world
            .transport_received(natted)
            .iter()
            .any(|(_, payload)| payload == b"after-idle"),
        "without keepalives the mapping should have expired and dropped the datagram"
    );
    let stats = world.nat_stats(natted)[0];
    assert!(
        stats.expired_drops + stats.no_mapping_drops > 0,
        "the post-idle datagram must have been dropped at the NAT"
    );
}

/// A NAT with an idle timeout of 25s — below the 30s QUIC idle timeout but
/// above the 10s keepalive — still survives, because the keepalive refreshes
/// the mapping well inside its window.
#[test]
fn keepalive_survives_sub_max_idle_nat_timeout() {
    let mut world = SimWorld::new(1);
    let public = world.add_transport_node(NodeOptions::default());
    let natted = world.add_transport_node(NodeOptions {
        nat: vec![NatConfig::port_restricted_cone().idle_timeout(Duration::from_secs(25))],
        ..NodeOptions::default()
    });

    let mapping = dial_and_capture_mapping(&mut world, natted, public);

    world.run_for(Duration::from_secs(300));

    world.transport_send(public, mapping, b"after-idle".to_vec());
    world.run_for(Duration::from_secs(5));

    assert!(
        world
            .transport_received(natted)
            .iter()
            .any(|(_, payload)| payload == b"after-idle"),
        "the 10s keepalive should refresh a 25s NAT mapping in time"
    );
    assert_eq!(world.nat_stats(natted)[0].expired_drops, 0);
}

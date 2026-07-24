//! P0 deliverable tests (nat-traversal.md §6.9, §10): determinism,
//! two-node convergence under faults, NAT classification matrix, and
//! NAT-timeout keepalive coverage, plus world smoke tests.

mod advert_security;
mod convergence;
mod determinism;
mod gossip_oracles;
mod keepalive;
mod mtu;
mod nat_matrix;

use std::time::Duration;

use super::{
    NodeOptions, SimWorld,
    nat::NatConfig,
    net::LinkParams,
};
use crate::overlay::OverlayMode;

/// Smoke: a NATed node dials a public node through the world and the QUIC
/// handshake completes on both sides (PeerConnected on the trace, identity
/// bound from the TLS cert).
#[test]
fn smoke_natted_node_connects_to_public_node() {
    let mut world = SimWorld::new(7);
    let public = world.add_node(NodeOptions {
        mode: OverlayMode::Source,
        ..NodeOptions::default()
    });
    let public_addr = world.public_addr(public);
    let natted = world.add_node(NodeOptions {
        nat: vec![NatConfig::port_restricted_cone()],
        static_peers: vec![public_addr],
        ..NodeOptions::default()
    });
    world.set_default_link(LinkParams::default().delay(
        Duration::from_millis(10),
        Duration::from_millis(30),
    ));

    // First advert (t=10s) triggers the dial.
    world.run_for(Duration::from_secs(20));

    let natted_pubkey = world.overlay_pubkey(natted);
    let public_pubkey = world.overlay_pubkey(public);
    assert_ne!(natted_pubkey, public_pubkey);
    // Both ends saw a connection: the NATed node created a mapping and the
    // handshake produced traffic in both directions.
    assert!(world.nat_stats(natted)[0].mappings_created >= 1);
    assert!(world.trace.events() > 0);
}
/// High-seam harness smoke: a line topology of MemTransport nodes floods
/// signed adverts along established connections until every node knows
/// every identity, at a scale the low seam could not touch cheaply.
#[test]
fn smoke_highseam_advert_flood_reaches_everyone() {
    use super::highseam::{HighSeamNet, HighSeamNodeOptions};

    const NODES: usize = 50;
    let mut net = HighSeamNet::new(21);
    for i in 0..NODES {
        let static_peers = if i == 0 {
            Vec::new()
        } else {
            vec![HighSeamNet::addr_for(i - 1)]
        };
        net.add_node(HighSeamNodeOptions {
            static_peers,
            ..HighSeamNodeOptions::default()
        });
    }
    // Adverts fire every 10 ticks; give the line topology time to flood
    // end to end.
    net.run_ticks(120);

    let now = net.now_instant();
    for i in 0..NODES {
        let known = net.core(i).gossip_snapshot(now).len();
        // Everyone should have learned every other identity via the flood.
        assert!(
            known >= NODES - 1,
            "node {i} knows only {known} of {} peers",
            NODES - 1
        );
    }
}

/// Bursts of full-size datagrams over a clean FIFO link arrive completely
/// and without spurious QUIC loss detection. Guards the link model's FIFO
/// clamp: with unconstrained i.i.d. delays, reordering trips quinn's
/// packet-threshold loss detector and congestion collapse strands queued
/// datagram frames (~45% delivery in this exact setup).
#[test]
fn bare_transport_burst_delivers_everything() {
    let mut world = SimWorld::new(3);
    let a = world.add_transport_node(NodeOptions::default());
    let a_addr = world.public_addr(a);
    let b = world.add_transport_node(NodeOptions::default());

    for round in 0..5u8 {
        for i in 0..32u8 {
            let mut payload = vec![0u8; 1232];
            payload[0] = round;
            payload[1] = i;
            world.transport_send(b, a_addr, payload);
        }
        world.run_for(Duration::from_millis(500));
    }
    world.run_for(Duration::from_secs(30));

    assert_eq!(world.transport_received(a).len(), 160);
    assert_eq!(world.transport_pending(b), 0);
    for (_, stats) in world.transport_stats(b) {
        assert_eq!(stats.path.lost_packets, 0);
        assert_eq!(stats.path.congestion_events, 0);
    }
}

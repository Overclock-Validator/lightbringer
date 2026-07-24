//! P2 core repair-machinery smoke tests (nat-traversal.md §6.4): the
//! request/serve state machines inside `OverlayCore`, exercised over real
//! QUIC streams (low seam) and the MemTransport mirror (high seam). The
//! full NAT-matrix, liveness, performance, and abuse suites live in the
//! dedicated `repair_*` modules.

use std::time::Duration;

use crate::overlay::{
    repair::RepairReq,
    sim::{
        NodeOptions, SimRepairEvent, SimWorld,
        highseam::{HighSeamNet, HighSeamNodeOptions},
    },
};

fn fake_shred(tag: u8) -> Vec<u8> {
    vec![tag; 1203]
}

/// Low seam: a sink node repairs a present shred, observes NotFound for a
/// missing one, and HighestWindowIndex returns the topmost stored index —
/// all over real QUIC streams on the gossip-established connection.
#[test]
fn low_seam_core_repair_exchange() {
    let mut world = SimWorld::new(23);
    let server = world.add_node(NodeOptions::default());
    let server_addr = world.public_addr(server);
    let server_pk = world.overlay_pubkey(server);
    let client = world.add_node(NodeOptions {
        static_peers: vec![server_addr],
        ..NodeOptions::default()
    });

    world.store_insert(server, 42, 3, fake_shred(3));
    world.store_insert(server, 42, 7, fake_shred(7));

    // First advert (t=10s) dials the server.
    world.run_for(Duration::from_secs(15));

    let s1 = world
        .request_repair(client, server_pk, RepairReq::WindowIndex { slot: 42, shred_index: 3 })
        .expect("connected after gossip dial");
    let s2 = world
        .request_repair(client, server_pk, RepairReq::WindowIndex { slot: 42, shred_index: 9 })
        .expect("second stream opens");
    let s3 = world
        .request_repair(
            client,
            server_pk,
            RepairReq::HighestWindowIndex { slot: 42, shred_index: 0 },
        )
        .expect("third stream opens");
    world.run_for(Duration::from_secs(2));

    let events = world.repair_events(client);
    assert_eq!(events.len(), 3, "all three exchanges conclude: {events:?}");
    for event in events {
        match event {
            SimRepairEvent::Response { stream, shred, .. } if *stream == s1 => {
                assert_eq!(shred.as_deref(), Some(fake_shred(3).as_slice()));
            }
            SimRepairEvent::Response { stream, shred, .. } if *stream == s2 => {
                assert!(shred.is_none(), "missing shred answers NotFound");
            }
            SimRepairEvent::Response { stream, shred, .. } if *stream == s3 => {
                assert_eq!(
                    shred.as_deref(),
                    Some(fake_shred(7).as_slice()),
                    "highest stored index wins"
                );
            }
            other => panic!("unexpected repair event {other:?}"),
        }
    }
}

/// Requesting an unconnected identity never dials: the request is dropped
/// and counted — the assertion `dropped_unreachable` existed for (P1 could
/// not exercise it; §6.1 send choke point).
#[test]
fn low_seam_repair_to_unconnected_peer_drops_and_counts() {
    let mut world = SimWorld::new(29);
    let node = world.add_node(NodeOptions::default());
    let stranger = solana_sdk::pubkey::Pubkey::new_unique();

    assert!(
        world
            .request_repair(node, stranger, RepairReq::WindowIndex { slot: 1, shred_index: 0 })
            .is_none()
    );
    assert_eq!(world.dropped_unreachable(node), 1);
    world.run_for(Duration::from_secs(2));
    assert!(world.repair_events(node).is_empty(), "no stream, no outcome");
}

/// High seam: the same exchange through the MemTransport mirror, both
/// directions of the serve relationship (each node repairs from the other).
#[test]
fn high_seam_core_repair_exchange() {
    let mut net = HighSeamNet::new(31);
    let a = net.add_node(HighSeamNodeOptions::default());
    let b = net.add_node(HighSeamNodeOptions::default());
    net.connect(a, b);
    let (a_pk, b_pk) = (net.node_pubkey(a), net.node_pubkey(b));

    net.store_insert(a, 5, 1, fake_shred(1));
    net.store_insert(b, 6, 2, fake_shred(2));

    let s_ab = net
        .request_repair(a, b_pk, RepairReq::WindowIndex { slot: 6, shred_index: 2 })
        .expect("connected");
    let s_ba = net
        .request_repair(b, a_pk, RepairReq::WindowIndex { slot: 5, shred_index: 1 })
        .expect("connected");
    let s_miss = net
        .request_repair(a, b_pk, RepairReq::WindowIndex { slot: 6, shred_index: 3 })
        .expect("connected");
    net.run_ticks(6);

    let outcomes = |events: &[SimRepairEvent], stream: u64| -> Option<Option<Vec<u8>>> {
        events.iter().find_map(|event| match event {
            SimRepairEvent::Response { stream: s, shred, .. } if *s == stream => {
                Some(shred.clone())
            }
            _ => None,
        })
    };
    assert_eq!(
        outcomes(net.repair_events(a), s_ab).expect("concluded"),
        Some(fake_shred(2))
    );
    assert_eq!(
        outcomes(net.repair_events(b), s_ba).expect("concluded"),
        Some(fake_shred(1))
    );
    assert_eq!(outcomes(net.repair_events(a), s_miss).expect("concluded"), None);
}

/// High seam: disconnecting mid-exchange fails the outstanding repair
/// instead of stranding it.
#[test]
fn high_seam_repair_fails_on_disconnect() {
    let mut net = HighSeamNet::new(37);
    let a = net.add_node(HighSeamNodeOptions::default());
    let b = net.add_node(HighSeamNodeOptions::default());
    net.connect(a, b);
    let b_pk = net.node_pubkey(b);

    let stream = net
        .request_repair(a, b_pk, RepairReq::WindowIndex { slot: 1, shred_index: 1 })
        .expect("connected");
    // Kill the connection before the ops ever deliver.
    net.core_mut(a).transport_mut().disconnect(&b_pk);
    net.run_ticks(4);

    assert!(
        net.repair_events(a).iter().any(|event| matches!(
            event,
            SimRepairEvent::Failed { stream: s, .. } if *s == stream
        )),
        "disconnect must surface as RepairFailed: {:?}",
        net.repair_events(a)
    );
}

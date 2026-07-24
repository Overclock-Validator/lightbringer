//! P2 deliverables (a)–(c) — repair over overlay streams under the low-seam
//! simulator (nat-traversal.md §6.4, §6.9, §10 P2 definition of done):
//! the R2 NAT matrix, the liveness oracle under loss/delay/churn, and the
//! protocol-level performance tier. The scenarios live in
//! `sim::scenario` (shared with the `overlay-sim` binary and auto-covered
//! by the determinism suite); these tests pin them across a seed spread.

use std::time::Duration;

use crate::overlay::{
    repair::RepairReq,
    sim::{NodeOptions, SimWorld, nat::NatConfig, net::LinkParams, scenario},
};

const SEEDS: [u64; 4] = [1, 7, 42, 1234];

/// Deliverable (a): every §6.2 requester row (public → cone flavors →
/// field-note fiber → symmetric flavors → CGNAT double-NAT) repairs its
/// gaps from a connected peer's store over real QUIC streams, AND a
/// symmetric+CGNAT server serves the peer connected to it — the R2
/// completion criterion, before any hole punching exists.
#[test]
fn repair_nat_matrix_holds_across_seeds() {
    for seed in SEEDS {
        let outcome = scenario::repair_nat_matrix(seed, false);
        assert!(
            outcome.ok,
            "repair-nat-matrix seed {seed}: {}",
            outcome.summary,
        );
    }
}

/// Deliverable (b): the liveness oracle — every repairable gap repairs
/// within the virtual-time budget while ≥1 connected peer holds the data,
/// through 5% loss, 20–80ms delay, a 20s partition, and a holder restart.
/// Half the gaps are discovered only after the churn window, so passing
/// always proves post-churn recovery.
#[test]
fn repair_liveness_survives_loss_delay_and_churn() {
    for seed in SEEDS {
        let outcome = scenario::repair_liveness(seed, false);
        assert!(
            outcome.ok,
            "repair-liveness seed {seed}: {}",
            outcome.summary,
        );
    }
}

/// Deliverable (c): the §6.9 performance oracles at protocol level under
/// virtual time — repair latency distribution under 10% configured loss
/// stays within the scenario's rails (p50 ≤ 800ms, p95 ≤ 3s) and the
/// control-plane cost stays in the few-KB-per-repaired-shred class
/// (≤ 30KB bound). Loss must show up as stream latency, never as failure.
#[test]
fn repair_performance_within_bounds_under_loss() {
    for seed in SEEDS {
        let outcome = scenario::repair_performance(seed, false);
        assert!(
            outcome.ok,
            "repair-performance seed {seed}: {}",
            outcome.summary,
        );
    }
}

/// A repair response never rides datagrams: the §6.4 reason responses use
/// streams is the 1242-byte datagram budget at the fixed 1280 MTU. A link
/// that clamps datagrams to the overlay path MTU must not affect repair —
/// stream frames fit in ordinary QUIC packets. (A regression that moved
/// responses into oversized datagrams would die at this clamp.)
#[test]
fn repair_survives_mtu_clamped_link() {
    let seed = 5;
    let mut world = SimWorld::new(seed);
    world.set_default_link(
        LinkParams::default()
            .delay(Duration::from_millis(5), Duration::from_millis(15))
            .mtu(1280),
    );
    let server = world.add_node(NodeOptions::default());
    let server_addr = world.public_addr(server);
    let server_pk = world.overlay_pubkey(server);
    let shred = vec![9u8; 1203];
    world.store_insert(server, 3, 0, shred.clone());
    let client = world.add_node(NodeOptions {
        nat: vec![NatConfig::port_restricted_cone()],
        static_peers: vec![server_addr],
        ..NodeOptions::default()
    });
    world.run_for(Duration::from_secs(15));

    let stream = world
        .request_repair(client, server_pk, RepairReq::WindowIndex { slot: 3, shred_index: 0 })
        .expect("connected");
    world.run_for(Duration::from_secs(3));

    let got = world.repair_events(client).iter().any(|event| {
        matches!(
            event,
            crate::overlay::sim::SimRepairEvent::Response { stream: s, shred: Some(bytes), .. }
                if *s == stream && *bytes == shred
        )
    });
    assert!(got, "repair response must fit MTU-clamped links via streams");
}

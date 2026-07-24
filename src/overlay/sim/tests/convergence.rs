//! Deliverable (b) — two-node convergence under faults (nat-traversal.md
//! §6.9, §10 P0): two simulated nodes exchange real signed shreds across a
//! lossy/delayed/partitioned link and both converge on the full set.
//! Injections repeat over several rounds ≥1s apart so link-level datagram
//! loss is covered by redundancy (the role FEC plays on the real flood
//! path) and QUIC congestion control has recovery time between bursts.

use std::{collections::BTreeSet, time::Duration};

use crate::overlay::OverlayMode;
use crate::overlay::sim::{
    NodeOptions, SimWorld,
    crypto::make_signed_shreds,
    net::LinkParams,
    scenario::{self, SHRED_CAPABLE_MTU},
};

fn shred_set(shreds: &[Vec<u8>]) -> BTreeSet<Vec<u8>> {
    shreds.iter().cloned().collect()
}

fn delivered_set(world: &SimWorld, host: crate::overlay::sim::HostId) -> BTreeSet<Vec<u8>> {
    world.delivered_shreds(host).iter().cloned().collect()
}

/// The canned lossy-exchange scenario converges under a spread of fixed
/// seeds (nat-traversal.md deliverable (b)).
#[test]
fn two_node_lossy_converges_across_seeds() {
    for seed in [1u64, 7, 42, 1234] {
        let outcome = scenario::two_node_lossy(seed, false);
        assert!(
            outcome.ok,
            "two-node-lossy seed {seed} did not converge: {}",
            outcome.summary,
        );
    }
}

/// Direct (non-scenario) build: two public source nodes over a harsher link
/// (10% drop, 40–160ms delay, 2% duplication) still fully exchange all 32
/// shreds in each direction after enough redundant rounds.
#[test]
fn two_public_nodes_converge_under_harsh_link() {
    let seed = 0x00C0_FFEE_u64;
    let mut world = SimWorld::new(seed);
    let a = world.add_node(NodeOptions {
        mode: OverlayMode::Source,
        initial_mtu: Some(SHRED_CAPABLE_MTU),
        ..NodeOptions::default()
    });
    let a_addr = world.public_addr(a);
    let b = world.add_node(NodeOptions {
        mode: OverlayMode::Source,
        static_peers: vec![a_addr],
        initial_mtu: Some(SHRED_CAPABLE_MTU),
        ..NodeOptions::default()
    });
    world.set_default_link(
        LinkParams::default()
            .delay(Duration::from_millis(40), Duration::from_millis(160))
            .drop_probability(0.10)
            .duplicate_probability(0.02),
    );

    // Nodes only dial on their advert tick (t=10s); let the connection form
    // before any shreds are injected.
    world.run_for(Duration::from_secs(15));

    let from_a = make_signed_shreds(seed, 42, 0);
    let from_b = make_signed_shreds(seed, 43, 0);
    // 10% loss needs several spaced rounds so congestion control recovers
    // between bursts and redundancy covers dropped datagrams.
    for _round in 0..8 {
        for shred in &from_a {
            world.inject_shred(a, shred);
        }
        for shred in &from_b {
            world.inject_shred(b, shred);
        }
        world.run_for(Duration::from_secs(1));
    }
    world.run_for(Duration::from_secs(10));

    let want_at_a = shred_set(&from_b);
    let want_at_b = shred_set(&from_a);
    let got_at_a = delivered_set(&world, a);
    let got_at_b = delivered_set(&world, b);
    assert!(
        want_at_a.is_subset(&got_at_a),
        "node a missing {} of {} shreds",
        want_at_a.difference(&got_at_a).count(),
        want_at_a.len(),
    );
    assert!(
        want_at_b.is_subset(&got_at_b),
        "node b missing {} of {} shreds",
        want_at_b.difference(&got_at_b).count(),
        want_at_b.len(),
    );
}

/// F1/F3 regression (nat-traversal.md §2.2): behind a NAT the sink converges
/// outbound but its inbound set stays partial. Passes while that failure
/// signature holds; it is the reminder to update once identity-keyed gossip
/// lands. See `scenario::two_node_nat_sink`.
#[test]
fn nat_sink_failure_signature_holds() {
    for seed in [1u64, 7] {
        let outcome = scenario::two_node_nat_sink(seed, false);
        assert!(
            outcome.ok,
            "two-node-nat-sink seed {seed} lost its F1/F3 signature: {}",
            outcome.summary,
        );
    }
}

/// Partition + churn: shreds injected while the link is down never arrive,
/// and once the link is restored fresh injections converge again. The
/// partition is kept under the 30s QUIC idle timeout so the connection
/// survives, and we still wait past an advert interval (>10s) after restore
/// before asserting on the post-reconnect shreds.
#[test]
fn partition_blocks_then_reconnect_delivers() {
    let seed = 0x00AB_CDEF_u64;
    let mut world = SimWorld::new(seed);
    let a = world.add_node(NodeOptions {
        mode: OverlayMode::Source,
        initial_mtu: Some(SHRED_CAPABLE_MTU),
        ..NodeOptions::default()
    });
    let a_addr = world.public_addr(a);
    let b = world.add_node(NodeOptions {
        mode: OverlayMode::Source,
        static_peers: vec![a_addr],
        initial_mtu: Some(SHRED_CAPABLE_MTU),
        ..NodeOptions::default()
    });
    let healthy = LinkParams::default().delay(Duration::from_millis(10), Duration::from_millis(30));
    world.set_default_link(healthy);

    world.run_for(Duration::from_secs(15));

    let baseline = make_signed_shreds(seed, 10, 0);
    for _round in 0..3 {
        for shred in &baseline {
            world.inject_shred(a, shred);
        }
        world.run_for(Duration::from_secs(1));
    }
    world.run_for(Duration::from_secs(3));
    let baseline_set = shred_set(&baseline);
    assert!(
        baseline_set.is_subset(&delivered_set(&world, b)),
        "baseline shreds never reached b on the healthy link",
    );

    world.set_link_bidir(a, b, LinkParams::default().partitioned());
    let during = make_signed_shreds(seed, 20, 0);
    for _round in 0..3 {
        for shred in &during {
            world.inject_shred(a, shred);
        }
        world.run_for(Duration::from_secs(1));
    }
    world.run_for(Duration::from_secs(3));
    let during_set = shred_set(&during);
    assert!(
        during_set.is_disjoint(&delivered_set(&world, b)),
        "{} shred(s) crossed a partitioned link",
        during_set.intersection(&delivered_set(&world, b)).count(),
    );

    world.set_link_bidir(a, b, healthy);
    world.run_for(Duration::from_secs(15));
    let after = make_signed_shreds(seed, 30, 0);
    for _round in 0..5 {
        for shred in &after {
            world.inject_shred(a, shred);
        }
        world.run_for(Duration::from_secs(1));
    }
    world.run_for(Duration::from_secs(5));
    let after_set = shred_set(&after);
    assert!(
        after_set.is_subset(&delivered_set(&world, b)),
        "fresh shreds did not arrive after the link was restored ({} of {} missing)",
        after_set.difference(&delivered_set(&world, b)).count(),
        after_set.len(),
    );
}

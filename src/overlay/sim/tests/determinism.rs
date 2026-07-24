//! Deliverable (a) — reproducibility (nat-traversal.md §6.9, §10 P0): the
//! event-trace hash is the equality witness, so one seed must reproduce one
//! execution. Fixed literal seeds only; a flaky seed is a determinism bug,
//! not a reason to loosen an assertion.

use std::time::Duration;

use crate::overlay::OverlayMode;
use crate::overlay::sim::{
    NodeOptions, SimWorld,
    crypto::make_signed_shreds,
    nat::NatConfig,
    net::LinkParams,
    scenario::{self, SHRED_CAPABLE_MTU},
};

/// Seeds replayed for the per-scenario reproducibility sweep.
const REPLAY_SEEDS: [u64; 2] = [1, 987_654_321];

/// Seeds under which every deliverable scenario reports `ok`.
const OK_SEEDS: [u64; 2] = [1, 7];

/// Every canned scenario is a pure function of its seed: two in-process runs
/// with the same seed produce byte-identical traces (equal hash and equal
/// event count). This is the core §6.9 claim.
#[test]
fn same_seed_reproduces_trace_for_every_scenario() {
    for name in scenario::SCENARIOS {
        for &seed in &REPLAY_SEEDS {
            let first = scenario::run(name, seed, false)
                .unwrap_or_else(|| panic!("unknown scenario {name}"));
            let second = scenario::run(name, seed, false)
                .unwrap_or_else(|| panic!("unknown scenario {name}"));
            assert_eq!(
                first.trace_hash, second.trace_hash,
                "scenario {name} seed {seed}: trace hash diverged between identical runs",
            );
            assert_eq!(
                first.events, second.events,
                "scenario {name} seed {seed}: event count diverged between identical runs",
            );
        }
    }
}

/// Distinct seeds drive distinct executions — the hash actually depends on
/// the seed and is not a constant.
#[test]
fn distinct_seeds_diverge() {
    let a = scenario::run("two-node-lossy", 1, false).expect("known scenario");
    let b = scenario::run("two-node-lossy", 2, false).expect("known scenario");
    assert_ne!(
        a.trace_hash, b.trace_hash,
        "two different seeds collided on the same trace hash",
    );
}

/// A hand-built world (not a canned scenario) is equally reproducible: a
/// NATed node dialing a public node over a lossy link, a few injected
/// shreds, some virtual time. Same seed twice ⇒ same trace hash.
#[test]
fn hand_built_world_is_reproducible() {
    fn run(seed: u64) -> String {
        let mut world = SimWorld::new(seed);
        let public = world.add_node(NodeOptions {
            mode: OverlayMode::Source,
            initial_mtu: Some(SHRED_CAPABLE_MTU),
            ..NodeOptions::default()
        });
        let public_addr = world.public_addr(public);
        let natted = world.add_node(NodeOptions {
            mode: OverlayMode::Source,
            nat: vec![NatConfig::port_restricted_cone()],
            static_peers: vec![public_addr],
            initial_mtu: Some(SHRED_CAPABLE_MTU),
            ..NodeOptions::default()
        });
        world.set_default_link(
            LinkParams::default()
                .delay(Duration::from_millis(10), Duration::from_millis(30))
                .drop_probability(0.05),
        );

        // The NATed node's first advert (t=10s) dials the public node.
        world.run_for(Duration::from_secs(15));

        let shreds = make_signed_shreds(seed, 42, 0);
        for _round in 0..3 {
            for shred in &shreds {
                world.inject_shred(public, shred);
                world.inject_shred(natted, shred);
            }
            world.run_for(Duration::from_millis(500));
        }
        world.run_for(Duration::from_secs(5));
        world.trace_hash()
    }

    assert_eq!(run(42), run(42), "hand-built world was not reproducible");
}

/// Regression: the deliverable scenarios all pass under fixed seeds. Guards
/// against a scenario silently regressing into always-failing.
#[test]
fn deliverable_scenarios_pass_for_fixed_seeds() {
    for name in scenario::SCENARIOS {
        for &seed in &OK_SEEDS {
            let outcome = scenario::run(name, seed, false)
                .unwrap_or_else(|| panic!("unknown scenario {name}"));
            assert!(
                outcome.ok,
                "scenario {name} seed {seed} failed: {}",
                outcome.summary,
            );
        }
    }
}

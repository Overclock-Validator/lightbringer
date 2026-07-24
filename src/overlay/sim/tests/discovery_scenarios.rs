//! P3 deliverable scenarios (nat-traversal.md §10 P3): the in-protocol
//! classification matrix (a), the dial-back/reachability matrix (b), the
//! allocator-calibration matrix (d), and the F1 end-to-end lifecycle (e).
//! Each is a registered `SCENARIOS` entry, so the determinism suite already
//! covers reproducibility and the seed-1/seed-7 pass; these wrappers assert
//! `ok` across a wider seed spread so a preset regressing into always-failing
//! surfaces here.

use crate::overlay::sim::scenario;

const SEEDS: [u64; 4] = [1, 7, 42, 987_654_321];

/// Deliverable (a): real cores exchanging observation frames behind every
/// `sim/nat.rs` preset classify exactly as the taxonomy predicts —
/// field-note-fiber → PortDependent, symmetric-preserving → EIM.
#[test]
fn in_protocol_classification_matrix_holds() {
    for seed in SEEDS {
        let outcome = scenario::nat_classify_inproto(seed, false);
        assert!(outcome.ok, "seed {seed}: {}", outcome.summary);
    }
}

/// Deliverable (b): per preset, the advert a peer actually observes is Direct
/// (public, full-cone — confirmed through a fresh source port) or Coordinated
/// with the §12-Q3 hint policy (fully symmetric → empty; else port-tagged).
#[test]
fn dialback_reachability_matrix_holds() {
    for seed in SEEDS {
        let outcome = scenario::dialback_reachability(seed, false);
        assert!(outcome.ok, "seed {seed}: {}", outcome.summary);
    }
}

/// Deliverable (d): preserving / sequential(stride) / random calibrate to the
/// right allocator discipline from observations toward ≥3 helper endpoints.
#[test]
fn allocator_calibration_matrix_holds() {
    for seed in SEEDS {
        let outcome = scenario::allocator_calibrate(seed, false);
        assert!(outcome.ok, "seed {seed}: {}", outcome.summary);
    }
}

/// Deliverable (e): a zero-config NATed node never advertises a useless or
/// misleading address at any lifecycle checkpoint, under observation loss and
/// peer churn.
#[test]
fn f1_zero_config_node_never_misadvertises() {
    for seed in SEEDS {
        let outcome = scenario::f1_lifecycle(seed, false);
        assert!(outcome.ok, "seed {seed}: {}", outcome.summary);
    }
}

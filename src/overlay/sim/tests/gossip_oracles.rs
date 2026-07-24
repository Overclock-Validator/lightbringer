//! P1 gossip/advert safety oracles at high-seam scale (nat-traversal.md
//! §6.1, §6.7, §6.9, §10 P1 row). Every §6.9 *safety* claim that P1 can
//! assert becomes a hundreds-of-nodes property test on [`HighSeamNet`]:
//! one peer entry per pubkey network-wide (F3), signed adverts with
//! monotone `advert_seq` supersession (F8), bounded gossip under identity
//! churn, the turbine tree flooding over identities (§6.7), and the single
//! send choke point never dialing a `Coordinated`-only peer (F2). Liveness
//! (full propagation) and reproducibility (equal `state_digest` per seed)
//! are asserted alongside so a regression in either surfaces here.
//!
//! Seeds are fixed literals; a statistically unlucky seed is swapped, never
//! papered over with a looser assertion.

use std::collections::{BTreeMap, BTreeSet};

use arrayvec::ArrayVec;
use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};

use crate::overlay::OverlayMode;
use crate::overlay::gossip::{PeerAdvert, Reachability, RepairEndpoint, SignedPeerAdvert};
use crate::overlay::packet::OverlayFrame;
use crate::overlay::sim::crypto::make_signed_shreds;
use crate::overlay::sim::highseam::{HighSeamNet, HighSeamNodeOptions};
use crate::overlay::transport::OverlayTransport;

/// A backbone of `backbone` `Direct` nodes hub-connected through node 0
/// (diameter 2, so the flood converges in a handful of ticks), plus
/// `leaves` `Coordinated` (`direct: false`) nodes that each dial one
/// backbone node via `static_peers`. Backbone indices are `0..backbone`;
/// leaf indices follow.
fn build_mesh(seed: u64, backbone: usize, leaves: usize, mode: OverlayMode) -> HighSeamNet {
    let mut net = HighSeamNet::new(seed);
    for _ in 0..backbone {
        net.add_node(HighSeamNodeOptions {
            mode,
            direct: true,
            ..HighSeamNodeOptions::default()
        });
    }
    for i in 1..backbone {
        net.connect(0, i);
    }
    for j in 0..leaves {
        net.add_node(HighSeamNodeOptions {
            mode,
            direct: false,
            static_peers: vec![HighSeamNet::addr_for(j % backbone)],
            ..HighSeamNodeOptions::default()
        });
    }
    net
}

fn known_pubkeys(net: &HighSeamNet, i: usize) -> BTreeSet<Pubkey> {
    net.core(i)
        .gossip_snapshot(net.now_instant())
        .into_iter()
        .map(|advert| advert.pubkey)
        .collect()
}

/// The `advert_seq` node `i` currently holds for `target`, if any.
fn held_seq(net: &HighSeamNet, i: usize, target: &Pubkey) -> Option<u64> {
    net.core(i)
        .gossip_snapshot(net.now_instant())
        .into_iter()
        .find(|advert| advert.pubkey == *target)
        .map(|advert| advert.advert_seq)
}

fn direct_reach(addr: std::net::SocketAddr) -> Reachability {
    let mut addrs = ArrayVec::new();
    addrs.push(addr);
    Reachability::Direct(addrs)
}

fn coordinated_reach() -> Reachability {
    Reachability::Coordinated {
        observed: ArrayVec::new(),
        via: ArrayVec::new(),
    }
}

/// A wire-ready, correctly-signed advert frame for `kp`.
fn signed_advert_bytes(kp: &Keypair, seq: u64, reach: Reachability) -> Vec<u8> {
    let advert = PeerAdvert {
        pubkey: kp.pubkey(),
        advert_seq: seq,
        ttl_ms: 30_000,
        reachability: reach,
        repair: RepairEndpoint::InConnection,
    };
    let signed = SignedPeerAdvert::sign(advert, kp).expect("advert signs");
    OverlayFrame::peer_advertisement(signed)
        .encode()
        .expect("advert frame encodes")
}

const BACKBONE: usize = 30;
const LEAVES: usize = 270;
const MESH_TICKS: u64 = 34;

/// F3 (§6.1): identity-keyed gossip holds exactly one entry per pubkey no
/// matter how many addresses a node is seen at, and never the node's own
/// identity — asserted across every node of a 300-node mixed mesh after the
/// flood has spread.
#[test]
fn one_peer_entry_per_pubkey_network_wide() {
    let mut net = build_mesh(0xF3, BACKBONE, LEAVES, OverlayMode::Sink);
    net.run_ticks(MESH_TICKS);

    let total = BACKBONE + LEAVES;
    for i in 0..total {
        let snapshot = net.core(i).gossip_snapshot(net.now_instant());
        let mut seen = BTreeSet::new();
        for advert in &snapshot {
            assert!(
                seen.insert(advert.pubkey),
                "node {i} holds a duplicate entry for {}",
                advert.pubkey,
            );
            assert_ne!(
                advert.pubkey,
                net.node_pubkey(i),
                "node {i} holds an entry for its own identity",
            );
        }
    }
}

/// Liveness (§6.9): adverts flood over the mesh regardless of reachability.
/// Every node eventually learns every `Direct` (backbone) identity, and
/// every backbone node learns every `Coordinated` leaf — the leaves are
/// unreachable, yet their adverts still propagate.
#[test]
fn every_advert_propagates_over_the_mesh() {
    let mut net = build_mesh(0x11, BACKBONE, LEAVES, OverlayMode::Sink);
    net.run_ticks(MESH_TICKS);

    let total = BACKBONE + LEAVES;
    let known: Vec<BTreeSet<Pubkey>> = (0..total).map(|i| known_pubkeys(&net, i)).collect();

    for (i, set) in known.iter().enumerate() {
        for b in 0..BACKBONE {
            if b == i {
                continue;
            }
            assert!(
                set.contains(&net.node_pubkey(b)),
                "node {i} never learned backbone node {b}",
            );
        }
    }
    for b in 0..BACKBONE {
        for l in BACKBONE..total {
            assert!(
                known[b].contains(&net.node_pubkey(l)),
                "backbone node {b} never learned coordinated leaf {l}",
            );
        }
    }
}

/// Bounded collections stay bounded (§6.1, §6.9): churning far more
/// identities through one node than the 4096-entry LRU capacity keeps
/// `gossip_len` at or under the bound the whole time and never panics.
#[test]
fn gossip_stays_bounded_under_identity_churn() {
    const CAPACITY: usize = 4096;
    const CHURN: usize = 5_000;

    let mut net = HighSeamNet::new(0xB0);
    net.add_node(HighSeamNodeOptions::default());
    net.add_node(HighSeamNodeOptions::default());
    // The injections arrive as if from an established neighbor (§ note: the
    // neighbor is the frame's sender, so it is skipped by flood-forwarding).
    net.connect(0, 1);
    let neighbor = HighSeamNet::addr_for(1);

    for n in 0..CHURN {
        let kp = Keypair::new();
        let bytes = signed_advert_bytes(&kp, 1, coordinated_reach());
        net.inject_datagram(0, neighbor, &bytes);
        assert!(
            net.core(0).gossip_len() <= CAPACITY,
            "gossip grew past the bound to {} after {} injections",
            net.core(0).gossip_len(),
            n + 1,
        );
    }
    assert_eq!(
        net.core(0).gossip_len(),
        CAPACITY,
        "LRU should saturate at capacity after churning past it",
    );
}

/// Supersession (§6.1): `advert_seq` is monotone. Across a window of ticks,
/// no node ever holds a lower seq for an identity than one it already held,
/// and at an advert-aligned tick (all propagation settled, next origination
/// not yet fired) the whole network agrees on the same seq for that
/// identity.
#[test]
fn advert_seq_is_monotonic_and_converges() {
    const NODES: usize = 60;
    const TARGET: usize = 7;
    // Node `TARGET` re-adverts at ticks 10,20,... with seq 1,2,...; at
    // 10*m+9 the m-th origination has settled and the next has not fired.
    const CONVERGE_TICK: u64 = 59;
    const CONVERGE_SEQ: u64 = 5;

    let mut net = build_mesh(0x5E, NODES, 0, OverlayMode::Sink);
    let target = net.node_pubkey(TARGET);

    net.run_ticks(25);
    let mut last: BTreeMap<usize, u64> = BTreeMap::new();
    let mut tick = 25u64;
    while tick < 60 {
        net.tick();
        tick += 1;
        for i in 0..NODES {
            if i == TARGET {
                continue;
            }
            if let Some(seq) = held_seq(&net, i, &target) {
                let floor = last.get(&i).copied().unwrap_or(0);
                assert!(
                    seq >= floor,
                    "node {i} regressed to seq {seq} after holding {floor} for {target}",
                );
                last.insert(i, seq);
            }
        }
        if tick == CONVERGE_TICK {
            for i in 0..NODES {
                if i == TARGET {
                    continue;
                }
                assert_eq!(
                    held_seq(&net, i, &target),
                    Some(CONVERGE_SEQ),
                    "node {i} not converged to seq {CONVERGE_SEQ} at tick {tick}",
                );
            }
        }
    }
    // The target never stores an entry for its own identity.
    assert_eq!(held_seq(&net, TARGET, &target), None);
}

/// A lower-seq advert for a known identity is stale flood residue: it must
/// not overwrite the higher seq already held (§6.1 replay defense).
#[test]
fn stale_seq_advert_does_not_supersede() {
    let mut net = HighSeamNet::new(0x57A1E);
    net.add_node(HighSeamNodeOptions::default());
    let from = HighSeamNet::addr_for(9);
    let kp = Keypair::new();

    net.inject_datagram(0, from, &signed_advert_bytes(&kp, 5, coordinated_reach()));
    assert_eq!(held_seq(&net, 0, &kp.pubkey()), Some(5));

    net.inject_datagram(0, from, &signed_advert_bytes(&kp, 3, coordinated_reach()));
    assert_eq!(
        held_seq(&net, 0, &kp.pubkey()),
        Some(5),
        "a stale (lower) seq superseded the held advert",
    );
    assert_eq!(net.core(0).gossip_len(), 1);
}

/// Advert signature rules hold at scale (§6.9, F8): an advert whose
/// signature does not match its claimed pubkey is rejected on arrival
/// (`invalid_adverts` increments) and never enters — nor is flooded into —
/// any node's gossip.
#[test]
fn forged_advert_is_rejected_and_never_flooded() {
    const NODES: usize = 4;
    let mut net = build_mesh(0xF8, NODES, 0, OverlayMode::Sink);
    net.run_ticks(15);

    // Advert claims `victim` but is signed by `attacker` (F8: pointing the
    // flood at someone else's identity) — verify() checks against the
    // claimed pubkey and fails.
    let victim = Keypair::new();
    let attacker = Keypair::new();
    let forged = PeerAdvert {
        pubkey: victim.pubkey(),
        advert_seq: 1,
        ttl_ms: 30_000,
        reachability: direct_reach(HighSeamNet::addr_for(1)),
        repair: RepairEndpoint::InConnection,
    };
    let bytes = OverlayFrame::peer_advertisement(
        SignedPeerAdvert::sign(forged, &attacker).expect("signs"),
    )
    .encode()
    .expect("encodes");

    let before = net.core(0).invalid_adverts();
    net.inject_datagram(0, HighSeamNet::addr_for(1), &bytes);
    assert!(
        net.core(0).invalid_adverts() > before,
        "forged advert was not counted invalid",
    );
    net.run_ticks(5);

    for i in 0..NODES {
        assert!(
            !known_pubkeys(&net, i).contains(&victim.pubkey()),
            "forged identity leaked into node {i}'s gossip",
        );
    }
}

/// Determinism (§6.9): the high seam is a pure function of its seed. Same
/// seed ⇒ identical `state_digest`; distinct seeds and distinct fault
/// budgets ⇒ distinct digests. Holds with and without seeded drop.
#[test]
fn high_seam_run_is_deterministic() {
    fn digest(seed: u64, drop: f64) -> String {
        let mut net = build_mesh(seed, 10, 30, OverlayMode::Sink);
        net.set_drop_probability(drop);
        net.run_ticks(30);
        net.state_digest()
    }

    assert_eq!(digest(7, 0.0), digest(7, 0.0), "same seed diverged");
    assert_ne!(digest(7, 0.0), digest(9, 0.0), "distinct seeds collided");

    assert_eq!(
        digest(7, 0.1),
        digest(7, 0.1),
        "seeded drop is not reproducible",
    );
    assert_ne!(
        digest(7, 0.0),
        digest(7, 0.1),
        "drop probability had no observable effect",
    );
}

/// §6.7: the turbine tree over identities floods a shred across a converged
/// all-`Direct` mesh (every node's usable-peer set is identical, so the
/// global tree is consistent) and the origin does not re-deliver its own
/// shred — its bounded dedup drops the copy returning over the mesh.
#[test]
fn source_shred_floods_over_identity_tree() {
    const NODES: usize = 64;
    const ORIGIN: usize = 10;

    let mut net = build_mesh(0x67, NODES, 0, OverlayMode::Source);
    net.run_ticks(24);

    let shred = make_signed_shreds(0x67, 42, 0)
        .into_iter()
        .next()
        .expect("shredder yields at least one data shred");
    net.inject_shred(ORIGIN, &shred);
    net.run_ticks(8);

    let reached = (0..NODES)
        .filter(|&i| i != ORIGIN)
        .filter(|&i| net.delivered_shreds(i).iter().any(|d| d == &shred))
        .count();
    let others = NODES - 1;
    assert!(
        reached * 10 >= others * 9,
        "shred reached only {reached}/{others} nodes",
    );
    assert!(
        !net.delivered_shreds(ORIGIN).iter().any(|d| d == &shred),
        "origin re-delivered its own shred (dedup failed)",
    );
}

/// F2 (§6.1, §6.7): a `Coordinated`-only peer is never a dial target. A
/// fresh Source node knows exactly one peer — `Coordinated`, unconnected —
/// then originates a shred. `usable_peers` excludes the peer from the
/// fan-out, so nothing is ever sent toward it: no connection is formed and
/// no address is dialed.
///
/// Note: this pre-exclusion means `send_to_peer`'s drop-and-count branch is
/// never reached, so `dropped_unreachable` stays 0 here (see final report).
#[test]
fn coordinated_only_peer_is_never_dialed() {
    let mut net = HighSeamNet::new(0xF2);
    let src = net.add_node(HighSeamNodeOptions {
        mode: OverlayMode::Source,
        direct: true,
        ..HighSeamNodeOptions::default()
    });

    let coord = Keypair::new();
    net.inject_datagram(
        src,
        HighSeamNet::addr_for(200),
        &signed_advert_bytes(&coord, 1, coordinated_reach()),
    );
    assert_eq!(net.core(src).gossip_len(), 1, "coordinated advert not held");

    let shred = vec![0xACu8; 256];
    net.inject_shred(src, &shred);
    net.run_ticks(3);

    assert!(
        net.core(src)
            .transport()
            .connection_addr(&coord.pubkey())
            .is_none(),
        "the choke point dialed a coordinated-only peer",
    );
    assert!(!net.core(src).transport().is_connected_to(&coord.pubkey()));
    assert!(
        net.core(src).transport().connected_peers().is_empty(),
        "no connection should exist to an unreachable peer",
    );
    assert_eq!(
        net.core(src).dropped_unreachable(),
        0,
        "coordinated peer is pre-excluded from fan-out, not drop-counted",
    );
}

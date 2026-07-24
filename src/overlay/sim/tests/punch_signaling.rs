//! High-seam P5 control-plane oracles: signature/origin binding and the
//! public via's helper-bind refusal path. Packet-truth probes stay in
//! `punch_core.rs`; this suite deliberately uses MemTransport at scale.

use arrayvec::ArrayVec;
use solana_sdk::{signature::Keypair, signer::Signer};

use crate::overlay::{
    nat::{AllocatorProfile, NatClass},
    packet::OverlayFrame,
    punch::{ConnectRequest, NatProfile},
    sim::{crypto, highseam::{HighSeamNet, HighSeamNodeOptions}},
};

fn profile() -> NatProfile {
    NatProfile {
        class: Some(NatClass::PortDependent),
        allocator: Some(AllocatorProfile::Sequential { stride: 1 }),
        birthday_punch: false,
        generation: Some("198.51.100.9".parse().unwrap()),
    }
}

#[test]
fn via_rejects_signed_request_when_connection_identity_is_not_origin() {
    let seed = 0x5151_0001;
    let mut net = HighSeamNet::new(seed);
    let origin = net.add_node(HighSeamNodeOptions::default());
    let via = net.add_node(HighSeamNodeOptions::default());
    let target = net.add_node(HighSeamNodeOptions {
        direct: false,
        ..HighSeamNodeOptions::default()
    });
    net.connect(origin, via);
    net.connect(via, target);
    net.run_ticks(20);

    let attacker = Keypair::new();
    let mut candidates = ArrayVec::new();
    candidates.push(net.node_addr(origin));
    let request = ConnectRequest::sign(
        7,
        net.node_pubkey(target),
        candidates,
        profile(),
        &attacker,
    )
    .unwrap();
    let raw = OverlayFrame::connect_request(request).encode().unwrap();
    let before = net.core(via).punch_refused();
    net.inject_datagram(via, net.node_addr(origin), &raw);
    net.run_ticks(3);

    assert!(net.core(via).punch_refused() > before);
    assert_eq!(net.core(target).active_punch_sessions(), 0);
}

#[test]
fn high_seam_helper_bind_refusal_is_inert_and_bounded() {
    let seed = 0x5151_0002;
    let mut net = HighSeamNet::new(seed);
    let origin = net.add_node(HighSeamNodeOptions::default());
    let via = net.add_node(HighSeamNodeOptions::default());
    let target = net.add_node(HighSeamNodeOptions::default());
    net.connect(origin, via);
    net.connect(via, target);
    net.run_ticks(20);

    // HighSeamEnv intentionally refuses every bind. The request is otherwise
    // genuine: its signer is the deterministic key of origin index 0.
    let signer = crypto::derive_keypair(seed, origin as u32);
    assert_eq!(signer.pubkey(), net.node_pubkey(origin));
    let mut candidates = ArrayVec::new();
    candidates.push(net.node_addr(origin));
    let request = ConnectRequest::sign(
        8,
        net.node_pubkey(target),
        candidates,
        profile(),
        &signer,
    )
    .unwrap();
    let raw = OverlayFrame::connect_request(request).encode().unwrap();
    net.inject_datagram(via, net.node_addr(origin), &raw);
    net.run_ticks(6);

    assert_eq!(
        net.core(via).active_punch_helpers(),
        0,
        "a bind refusal must not leak helper state",
    );
    assert_eq!(net.core(via).active_punch_forwards(), 0);
}

#[test]
fn target_requires_a_gossip_visible_signed_origin_before_probing() {
    let seed = 0x5151_0003;
    let mut net = HighSeamNet::new(seed);
    let via = net.add_node(HighSeamNodeOptions::default());
    let target = net.add_node(HighSeamNodeOptions {
        direct: false,
        ..HighSeamNodeOptions::default()
    });
    net.connect(via, target);
    net.run_ticks(12);

    // The envelope itself is valid, but its signer has no gossip entry at B.
    // A connected via must not turn that into a probe of its candidate.
    let invisible = Keypair::new();
    let mut candidates = ArrayVec::new();
    candidates.push("198.51.100.77:51000".parse().unwrap());
    let request = ConnectRequest::sign(11, net.node_pubkey(target), candidates, profile(), &invisible)
        .unwrap();
    let raw = OverlayFrame::connect_request(request).encode().unwrap();
    let before = net.core(target).punch_refused();
    net.inject_datagram(target, net.node_addr(via), &raw);

    assert!(net.core(target).punch_refused() > before);
    assert_eq!(net.core(target).active_punch_sessions(), 0);
}

#[test]
fn via_rate_limits_each_initiator_and_each_target_independently_at_scale() {
    const ORIGINS: usize = 12;
    const TARGETS: usize = 5;
    let seed = 0x5151_0004;
    let mut net = HighSeamNet::new(seed);
    let via = net.add_node(HighSeamNodeOptions::default());
    let origins: Vec<_> = (0..ORIGINS)
        .map(|_| net.add_node(HighSeamNodeOptions::default()))
        .collect();
    let targets: Vec<_> = (0..TARGETS)
        .map(|_| {
            net.add_node(HighSeamNodeOptions {
                direct: false,
                ..HighSeamNodeOptions::default()
            })
        })
        .collect();
    for &origin in &origins {
        net.connect(origin, via);
    }
    for &target in &targets {
        net.connect(via, target);
    }
    net.run_ticks(20);

    // Twelve distinct authenticated initiators aim at one target in the same
    // rate window. The target-keyed cap rejects after the fourth, regardless
    // of identity churn.
    let shared_target = targets[0];
    let before_target_cap = net.core(via).punch_refused();
    for (nonce, &origin) in origins.iter().enumerate() {
        let signer = crypto::derive_keypair(seed, origin as u32);
        let mut candidates = ArrayVec::new();
        candidates.push(net.node_addr(origin));
        let request = ConnectRequest::sign(
            nonce as u64 + 100,
            net.node_pubkey(shared_target),
            candidates,
            profile(),
            &signer,
        )
        .unwrap();
        let raw = OverlayFrame::connect_request(request).encode().unwrap();
        net.inject_datagram(via, net.node_addr(origin), &raw);
    }
    assert!(
        net.core(via).punch_refused() >= before_target_cap + (ORIGINS - 4) as u64,
        "per-target cap must survive many initiator identities",
    );

    // A fresh second later clears the first window. One origin now aims at
    // five different targets; the fifth must trip the independent
    // initiator-keyed cap rather than borrowing target quota.
    net.run_ticks(2);
    let origin = origins[0];
    let signer = crypto::derive_keypair(seed, origin as u32);
    let before_origin_cap = net.core(via).punch_refused();
    for (nonce, &target) in targets.iter().enumerate() {
        let mut candidates = ArrayVec::new();
        candidates.push(net.node_addr(origin));
        let request = ConnectRequest::sign(
            nonce as u64 + 1_000,
            net.node_pubkey(target),
            candidates,
            profile(),
            &signer,
        )
        .unwrap();
        let raw = OverlayFrame::connect_request(request).encode().unwrap();
        net.inject_datagram(via, net.node_addr(origin), &raw);
    }
    assert!(
        net.core(via).punch_refused() > before_origin_cap,
        "fifth target in one window must be refused by the initiator cap",
    );
}

#[test]
fn oversized_bracket_is_rejected_before_it_can_open_a_range() {
    let seed = 0x5151_0005;
    let mut net = HighSeamNet::new(seed);
    let via = net.add_node(HighSeamNodeOptions::default());
    let target = net.add_node(HighSeamNodeOptions::default());
    net.connect(via, target);
    net.run_ticks(12);

    let raw = OverlayFrame::PunchBracket {
        nonce: 99,
        origin: net.node_pubkey(via),
        target: net.node_pubkey(target),
        ip: "198.51.100.9".parse().unwrap(),
        start: 50_000,
        end: 50_032,
    }
    .encode()
    .unwrap();
    let before = net.core(target).punch_refused();
    net.inject_datagram(target, net.node_addr(via), &raw);
    assert!(net.core(target).punch_refused() > before);
    assert_eq!(net.core(target).active_punch_sessions(), 0);
}

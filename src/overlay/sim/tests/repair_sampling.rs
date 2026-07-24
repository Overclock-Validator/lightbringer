//! P2 deliverable (e) — repair peer sampling and serve-side fan-in
//! (nat-traversal.md §6.4). Two layers:
//!
//! * The pure selection logic behind every `RepairPeerSource`:
//!   [`overlay_repair_targets`] mapping a gossip view to targets (Udp peers
//!   are always requestable, in-connection peers only when connected), and
//!   [`PeerSample`] latency-weighting keyed by *pubkey* (ported from the
//!   old SocketAddr-keyed original) — so a Udp and an Overlay target for the
//!   same identity score identically, and a timed-out peer floors at 1.0
//!   rather than 0 so it can recover.
//!
//! * The high-seam plumbing at scale: `repair_peer_view` reflecting gossip +
//!   connections, a hand-crafted Udp advert flowing into the view, and one
//!   server fanning in repair over many concurrent streams from distinct
//!   client identities.
//!
//! The pinned assertion P1 could not make lives here too: `Overlay(Pubkey)`
//! repair targeting finally exercises `dropped_unreachable` (§6.1's send
//! choke point), which the flood path can never reach because it pre-filters
//! unreachable peers (see the doc comment on `dropped_unreachable` in
//! service.rs).
//!
//! Determinism: every RNG is `StdRng::seed_from_u64(fixed)` and every net is
//! `HighSeamNet::new(fixed)`; frequency assertions keep comfortable margins.

use std::net::SocketAddr;

use arrayvec::ArrayVec;
use rand::{SeedableRng, rngs::StdRng};
use solana_sdk::{pubkey::Pubkey, signer::Signer};

use crate::overlay::gossip::{PeerAdvert, Reachability, RepairEndpoint, SignedPeerAdvert};
use crate::overlay::packet::OverlayFrame;
use crate::overlay::repair::{
    PeerSample, RepairPeerEntry, RepairReq, RepairTarget, overlay_repair_targets,
};
use crate::overlay::sim::crypto;
use crate::overlay::sim::highseam::{HighSeamNet, HighSeamNodeOptions};
use crate::overlay::sim::SimRepairEvent;

fn fake_shred(tag: u8) -> Vec<u8> {
    vec![tag; 1203]
}

fn addr(s: &str) -> SocketAddr {
    s.parse().expect("valid socket addr literal")
}

/// Drive `pubkey` to the hard-filter floor (>50% timeouts across >=10
/// requests → score 1.0), mirroring the real request-then-timeout rhythm.
fn drive_to_timeout_floor(sample: &mut PeerSample, pubkey: Pubkey) {
    for _ in 0..15 {
        sample.record_request(pubkey);
        sample.record_timeout(pubkey);
    }
}

/// Count how many of `draws` selections over `targets` land on `wanted`.
fn count_selected(
    sample: &PeerSample,
    targets: &[RepairTarget],
    wanted: Pubkey,
    draws: usize,
    seed: u64,
) -> usize {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut hits = 0;
    for _ in 0..draws {
        if sample
            .select_weighted(targets, &mut rng)
            .expect("non-empty targets always select")
            .pubkey()
            == wanted
        {
            hits += 1;
        }
    }
    hits
}

// ---------------------------------------------------------------------------
// Pure selection logic (no network).
// ---------------------------------------------------------------------------

/// §6.4 target mapping: a peer advertising `RepairEndpoint::Udp` is a target
/// whether or not a connection exists (request/response over one UDP 4-tuple
/// traverses any NAT on the requester's side); an `InConnection` peer is a
/// target only while connected.
#[test]
fn overlay_repair_targets_maps_udp_always_and_inconnection_only_when_connected() {
    let udp_unconn = Pubkey::new_unique();
    let udp_conn = Pubkey::new_unique();
    let inconn_conn = Pubkey::new_unique();
    let inconn_unconn = Pubkey::new_unique();
    let a1 = addr("203.0.113.10:65411");
    let a2 = addr("203.0.113.20:65411");

    let view = vec![
        // (a) Udp advertised, no connection → still a Udp target.
        RepairPeerEntry { pubkey: udp_unconn, repair: RepairEndpoint::Udp(a1), connected: false },
        // (b) Udp advertised, connected → still dialed over UDP, not Overlay.
        RepairPeerEntry { pubkey: udp_conn, repair: RepairEndpoint::Udp(a2), connected: true },
        // (c) InConnection + connected → an Overlay target.
        RepairPeerEntry { pubkey: inconn_conn, repair: RepairEndpoint::InConnection, connected: true },
        // (d) InConnection + not connected → excluded entirely.
        RepairPeerEntry { pubkey: inconn_unconn, repair: RepairEndpoint::InConnection, connected: false },
    ];

    let targets = overlay_repair_targets(&view);

    assert_eq!(targets.len(), 3, "exactly the three requestable peers: {targets:?}");
    assert!(targets.contains(&RepairTarget::Udp(a1, udp_unconn)), "Udp peer targetable unconnected");
    assert!(
        targets.contains(&RepairTarget::Udp(a2, udp_conn)),
        "connected Udp peer is a Udp target, never Overlay",
    );
    assert!(
        !targets.contains(&RepairTarget::Overlay(udp_conn)),
        "a Udp peer is never turned into an Overlay target",
    );
    assert!(targets.contains(&RepairTarget::Overlay(inconn_conn)), "connected InConnection → Overlay");
    assert!(
        targets.iter().all(|t| t.pubkey() != inconn_unconn),
        "an unconnected InConnection peer is not requestable",
    );
}

/// §6.4 latency weighting keyed by pubkey: many fast responses lift a peer,
/// slow responses sink it, and timeouts floor it — selection frequency over a
/// seeded RNG orders fast > slow > timeout with the fast peer taking a strict
/// majority.
#[test]
fn peer_sample_weights_selection_fast_over_slow_over_timeout() {
    let fast = Pubkey::new_unique();
    let slow = Pubkey::new_unique();
    let timed_out = Pubkey::new_unique();

    let mut sample = PeerSample::new();
    for pk in [fast, slow, timed_out] {
        sample.observe(pk);
    }
    for _ in 0..30 {
        sample.record_response(fast, 20.0);
        sample.record_response(slow, 280.0);
    }
    drive_to_timeout_floor(&mut sample, timed_out);

    let targets = vec![
        RepairTarget::Overlay(fast),
        RepairTarget::Overlay(slow),
        RepairTarget::Overlay(timed_out),
    ];
    const DRAWS: usize = 4000;
    let fast_hits = count_selected(&sample, &targets, fast, DRAWS, 0xF00D);
    let slow_hits = count_selected(&sample, &targets, slow, DRAWS, 0xF00D);
    let to_hits = count_selected(&sample, &targets, timed_out, DRAWS, 0xF00D);

    assert_eq!(fast_hits + slow_hits + to_hits, DRAWS, "every draw selects exactly one peer");
    assert!(fast_hits > slow_hits, "fast {fast_hits} !> slow {slow_hits}");
    assert!(slow_hits > to_hits, "slow {slow_hits} !> timed-out {to_hits}");
    assert!(fast_hits > DRAWS / 2, "fast peer takes no strict majority: {fast_hits}/{DRAWS}");
    // Comfortable, non-knife-edge margins (empirical ratios ~5x and ~18x).
    assert!(fast_hits > slow_hits * 2, "fast/slow gap too small");
    assert!(slow_hits > to_hits * 3, "slow/timeout gap too small");
}

/// Scoring is by pubkey, independent of the target *variant*: a `Udp` and an
/// `Overlay` target sharing a pubkey draw the same weight. Two arrays that
/// swap which identity wears the Udp vs Overlay coat produce byte-identical
/// selection streams under the same seed, and equal-pubkey pairs split 50/50.
#[test]
fn peer_sample_scores_by_pubkey_not_by_target_variant() {
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    let a1 = addr("203.0.113.30:65411");
    let a2 = addr("203.0.113.40:65411");

    let mut sample = PeerSample::new();
    sample.observe(pk_a);
    sample.observe(pk_b);
    for _ in 0..30 {
        sample.record_response(pk_a, 20.0); // → score 92
        sample.record_response(pk_b, 280.0); // → score ~17.9
    }

    // pk_a wearing the Udp coat vs pk_a wearing the Overlay coat: identical
    // weights ⇒ identical index choices ⇒ exactly equal selection counts.
    let a_is_udp = [RepairTarget::Udp(a1, pk_a), RepairTarget::Overlay(pk_b)];
    let a_is_overlay = [RepairTarget::Overlay(pk_a), RepairTarget::Udp(a2, pk_b)];
    const DRAWS: usize = 4000;
    let a_hits_udp = count_selected(&sample, &a_is_udp, pk_a, DRAWS, 0xBEEF);
    let a_hits_overlay = count_selected(&sample, &a_is_overlay, pk_a, DRAWS, 0xBEEF);
    assert_eq!(
        a_hits_udp, a_hits_overlay,
        "the Udp/Overlay variant changed pk_a's weight — scoring is not pubkey-pure",
    );
    assert!(a_hits_udp > DRAWS / 2, "the higher-scoring pubkey should win regardless of variant");

    // Two targets sharing ONE pubkey have identical weights → uniform split.
    let same_pubkey = [RepairTarget::Udp(a1, pk_a), RepairTarget::Overlay(pk_a)];
    let udp_share = count_selected(&sample, &same_pubkey, pk_a, DRAWS, 0xBEEF);
    assert_eq!(udp_share, DRAWS, "both targets carry pk_a, so pk_a is always selected");
    // Distinguish the variants by route to confirm each is picked ~half the time.
    let mut rng = StdRng::seed_from_u64(0xC0DE);
    let mut udp_route = 0;
    for _ in 0..DRAWS {
        if matches!(
            sample.select_weighted(&same_pubkey, &mut rng).unwrap(),
            RepairTarget::Udp(..)
        ) {
            udp_route += 1;
        }
    }
    assert!(
        (DRAWS as i64 / 2 - udp_route as i64).abs() < DRAWS as i64 / 5,
        "equal-weight targets should split ~50/50, got {udp_route}/{DRAWS} on the Udp coat",
    );
}

/// A timed-out peer floors at 1.0, not 0: it stays occasionally selectable,
/// and once `record_request`'s window dilutes the timeout ratio (and
/// eventually resets it) the score recovers well above the floor.
#[test]
fn timed_out_peer_floors_at_one_and_recovers() {
    let good = Pubkey::new_unique();
    let floored = Pubkey::new_unique();

    let mut sample = PeerSample::new();
    sample.observe(good);
    sample.observe(floored);
    for _ in 0..30 {
        sample.record_response(good, 20.0); // → score 92
    }
    drive_to_timeout_floor(&mut sample, floored); // → score 1.0

    let targets = vec![RepairTarget::Overlay(good), RepairTarget::Overlay(floored)];
    const DRAWS: usize = 8000;
    let floor_hits = count_selected(&sample, &targets, floored, DRAWS, 0x5EED);
    assert!(
        floor_hits > 0,
        "a floored peer (score 1.0, not 0) must remain selectable: {floor_hits}/{DRAWS}",
    );

    // Continued requests without new timeouts dilute the ratio below 50% and
    // cross the 100-request window reset, lifting the peer off the floor.
    for _ in 0..120 {
        sample.record_request(floored);
    }
    let recovered_hits = count_selected(&sample, &targets, floored, DRAWS, 0x5EED);
    assert!(
        recovered_hits > floor_hits * 3,
        "recovery did not raise selection frequency: floor {floor_hits} vs recovered {recovered_hits}",
    );
}

// ---------------------------------------------------------------------------
// View plumbing (high seam, real cores).
// ---------------------------------------------------------------------------

/// `repair_peer_view` reflects gossip identities plus live connections. In a
/// line A—B—C (only A—B and B—C connected), A learns C's identity by flood
/// yet is not connected to it: both peers show `InConnection` (every
/// high-seam node has `repair_addr: None`), B connected, C not — and
/// `overlay_repair_targets` turns only the connected B into a target.
#[test]
fn repair_peer_view_reflects_gossip_and_connections() {
    let mut net = HighSeamNet::new(0x5A11);
    let a = net.add_node(HighSeamNodeOptions::default());
    let b = net.add_node(HighSeamNodeOptions::default());
    let c = net.add_node(HighSeamNodeOptions::default());
    net.connect(a, b);
    net.connect(b, c);
    let (a_pk, b_pk, c_pk) = (net.node_pubkey(a), net.node_pubkey(b), net.node_pubkey(c));

    net.run_ticks(35); // adverts fire every 10 ticks; flood settles well before this

    let now = net.now_instant();
    let view = net.core_mut(a).repair_peer_view(now);

    let b_row = view.iter().find(|e| e.pubkey == b_pk).expect("A learned its neighbor B");
    assert_eq!(b_row.repair, RepairEndpoint::InConnection);
    assert!(b_row.connected, "B is connected to A");

    let c_row = view.iter().find(|e| e.pubkey == c_pk).expect("A learned C by flood through B");
    assert_eq!(c_row.repair, RepairEndpoint::InConnection);
    assert!(!c_row.connected, "C is reachable only through B, not connected to A");

    assert!(view.iter().all(|e| e.pubkey != a_pk), "A never lists its own identity");

    let targets = overlay_repair_targets(&view);
    assert!(targets.contains(&RepairTarget::Overlay(b_pk)), "connected B is an Overlay target");
    assert!(
        targets.iter().all(|t| t.pubkey() != c_pk),
        "unconnected C is excluded from targets",
    );
}

/// A peer advertising `RepairEndpoint::Udp` flows into the view as a Udp
/// target even with no connection. The advert is hand-crafted (high-seam
/// nodes never self-advertise Udp) and injected as if from a connected
/// neighbor.
#[test]
fn udp_advert_becomes_a_udp_target_without_a_connection() {
    let seed = 0x5A12;
    let mut net = HighSeamNet::new(seed);
    let a = net.add_node(HighSeamNodeOptions::default());
    let b = net.add_node(HighSeamNodeOptions::default());
    net.connect(a, b);
    let b_addr = net.node_addr(b);

    // A fresh identity that advertises a routable UDP repair socket.
    let udp_kp = crypto::derive_keypair(seed, 99);
    let udp_pk = udp_kp.pubkey();
    let repair_sock = addr("203.0.113.200:65411");
    let mut addrs = ArrayVec::new();
    addrs.push(addr("203.0.113.200:65410"));
    let advert = PeerAdvert {
        pubkey: udp_pk,
        advert_seq: 1,
        ttl_ms: 30_000,
        reachability: Reachability::Direct(addrs),
        repair: RepairEndpoint::Udp(repair_sock),
    };
    let frame = OverlayFrame::peer_advertisement(SignedPeerAdvert::sign(advert, &udp_kp).unwrap())
        .encode()
        .unwrap();
    net.inject_datagram(a, b_addr, &frame);

    let now = net.now_instant();
    let view = net.core_mut(a).repair_peer_view(now);
    let row = view.iter().find(|e| e.pubkey == udp_pk).expect("A learned the Udp peer");
    assert_eq!(row.repair, RepairEndpoint::Udp(repair_sock));
    assert!(!row.connected, "A never opened a connection to the Udp peer");

    let targets = overlay_repair_targets(&view);
    assert!(
        targets.contains(&RepairTarget::Udp(repair_sock, udp_pk)),
        "a Udp-advertising peer is a target despite no overlay connection",
    );
}

// ---------------------------------------------------------------------------
// Serve-side fan-in at scale (high seam).
// ---------------------------------------------------------------------------

/// One server fans repair in from ~60 distinct client identities, each on its
/// own connection issuing several streamed requests. Every client receives
/// the correct shred for each request, and — because the per-pubkey serve cap
/// is keyed by identity — no request is ever refused.
#[test]
fn server_fans_in_repair_from_many_clients() {
    const CLIENTS: usize = 60;
    let mut net = HighSeamNet::new(0xFA17);
    let server = net.add_node(HighSeamNodeOptions::default());
    let server_pk = net.node_pubkey(server);
    let clients: Vec<usize> = (0..CLIENTS)
        .map(|_| net.add_node(HighSeamNodeOptions::default()))
        .collect();
    for &client in &clients {
        net.connect(client, server);
    }

    let slot = 100u64;
    let indices = [0u32, 1, 2];
    for &idx in &indices {
        net.store_insert(server, slot, idx, fake_shred(idx as u8));
    }

    // Each client opens a stream per stored index; remember (stream, index).
    let mut expected: Vec<Vec<(u64, u32)>> = Vec::with_capacity(CLIENTS);
    for &client in &clients {
        let mut per_client = Vec::new();
        for &idx in &indices {
            let stream = net
                .request_repair(client, server_pk, RepairReq::WindowIndex { slot, shred_index: idx })
                .expect("client is connected to the server");
            per_client.push((stream, idx));
        }
        expected.push(per_client);
    }
    net.run_ticks(10);

    for (ci, &client) in clients.iter().enumerate() {
        let events = net.repair_events(client);
        for &(stream, idx) in &expected[ci] {
            let got = events.iter().find_map(|event| match event {
                SimRepairEvent::Response { stream: s, shred, .. } if *s == stream => Some(shred.clone()),
                _ => None,
            });
            assert_eq!(
                got,
                Some(Some(fake_shred(idx as u8))),
                "client {ci} did not receive the correct shred for index {idx}",
            );
        }
    }
    assert_eq!(
        net.core(server).repairs_refused(),
        0,
        "each client is a distinct pubkey, so the per-pubkey serve cap never trips",
    );
}

// ---------------------------------------------------------------------------
// The P1-pinned assertion (high seam).
// ---------------------------------------------------------------------------

/// `dropped_unreachable` finally becomes exercisable through `Overlay(Pubkey)`
/// targeting. A node knows a `Coordinated`, `InConnection` peer purely from
/// gossip — no connection — so `overlay_repair_targets` excludes it; but if a
/// caller targets that identity anyway, `request_repair` opens no stream,
/// drops the request, and increments the counter by exactly one. A separate
/// node repairing only connected targets keeps the counter at zero.
///
/// P1's oracles could never reach this counter: the flood path
/// (`usable_peers`) pre-filters `Coordinated`-only peers, so `send_to_peer`'s
/// drop-and-count branch is unreachable there (see the `dropped_unreachable`
/// doc comment in service.rs). Only by-identity repair targeting, where the
/// target is chosen before its reachability is known, reaches it.
#[test]
fn dropped_unreachable_counts_overlay_targeting_of_an_unconnected_peer() {
    let seed = 0xDEAD;
    let mut net = HighSeamNet::new(seed);
    let a = net.add_node(HighSeamNodeOptions::default());
    let b = net.add_node(HighSeamNodeOptions::default());
    net.connect(a, b);
    let (a_pk, b_pk) = (net.node_pubkey(a), net.node_pubkey(b));
    let b_addr = net.node_addr(b);

    net.run_ticks(15); // A learns B (connected, InConnection) via the flood

    // A knows a stranger only through a Coordinated advert — never connected.
    let stranger_kp = crypto::derive_keypair(seed, 77);
    let stranger_pk = stranger_kp.pubkey();
    let advert = PeerAdvert {
        pubkey: stranger_pk,
        advert_seq: 1,
        ttl_ms: 30_000,
        reachability: Reachability::Coordinated {
            observed: ArrayVec::new(),
            via: ArrayVec::new(),
        },
        repair: RepairEndpoint::InConnection,
    };
    let frame =
        OverlayFrame::peer_advertisement(SignedPeerAdvert::sign(advert, &stranger_kp).unwrap())
            .encode()
            .unwrap();
    net.inject_datagram(a, b_addr, &frame);

    // The target filter excludes the unconnected stranger but keeps B.
    let now = net.now_instant();
    let view = net.core_mut(a).repair_peer_view(now);
    let targets = overlay_repair_targets(&view);
    assert!(
        targets.iter().all(|t| t.pubkey() != stranger_pk),
        "an unconnected InConnection peer is not a repair target",
    );
    assert!(
        targets.contains(&RepairTarget::Overlay(b_pk)),
        "the connected neighbor remains a legitimate target",
    );

    // Targeting the stranger anyway (bypassing the filter) drops and counts.
    let before = net.core(a).dropped_unreachable();
    let dropped = net.request_repair(a, stranger_pk, RepairReq::WindowIndex { slot: 1, shred_index: 0 });
    assert!(dropped.is_none(), "no connection to the stranger — the request opens no stream");
    assert_eq!(
        net.core(a).dropped_unreachable(),
        before + 1,
        "the unreachable target is counted exactly once",
    );
    net.run_ticks(5);
    assert!(
        net.repair_events(a).is_empty(),
        "a dropped request never produces a repair outcome: {:?}",
        net.repair_events(a),
    );

    // A node repairing only a connected target never drop-counts. B repairs
    // from A (connected); A's store is empty, so the answer is NotFound — a
    // completed exchange, not a drop.
    let stream = net
        .request_repair(b, a_pk, RepairReq::WindowIndex { slot: 1, shred_index: 0 })
        .expect("B is connected to A");
    net.run_ticks(5);
    assert_eq!(
        net.core(b).dropped_unreachable(),
        0,
        "a node repairing only connected targets never drops-unreachable",
    );
    assert!(
        net.repair_events(b)
            .iter()
            .any(|event| matches!(event, SimRepairEvent::Response { stream: s, .. } if *s == stream)),
        "B's legitimate connected repair concludes: {:?}",
        net.repair_events(b),
    );
}

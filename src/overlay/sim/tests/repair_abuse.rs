//! P2 repair-abuse suite — deliverable (d) (nat-traversal.md §6.4, §9): the
//! serve side of the §6.4 repair sub-protocol under load and attack. Pins
//! three invariants the design owes: per-pubkey rate caps are enforced,
//! over-limit requests are refused without unbounded state growth, and
//! malformed/truncated requests *and* responses are inert — counted, no
//! panic, no state corruption, and subsequent traffic is unaffected.
//!
//! Volume and exactness live in the high seam, where virtual time advances
//! one second per tick and the 1s rate window is deterministic: a burst
//! issued before ticking lands on one server tick and therefore shares one
//! window. The low seam re-checks the same guarantees over real quinn-proto
//! streams, where QUIC timing means we bound with `>`/`>=` rather than exact
//! counts.

use std::time::Duration;

use crate::overlay::{
    repair::{MAX_REPAIR_REQUESTS_PER_SECOND, RepairReq, encode_request},
    sim::{
        NodeOptions, SimRepairEvent, SimWorld,
        highseam::{HighSeamNet, HighSeamNodeOptions, MemStreamOp, MemStreamOpKind},
    },
};

/// A max-size merkle *data* shred payload (1203 B → 1227 B v1 frame): the
/// largest thing that fits the 1242-byte datagram budget, and a valid repair
/// response body.
fn fake_shred(tag: u8) -> Vec<u8> {
    vec![tag; 1203]
}

fn responses(events: &[SimRepairEvent]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event, SimRepairEvent::Response { .. }))
        .count()
}

fn failures(events: &[SimRepairEvent]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event, SimRepairEvent::Failed { .. }))
        .count()
}

/// High seam: a single client that fires more than the per-second cap in one
/// virtual-time window is served exactly the cap and refused the excess. The
/// refused streams surface to the client as `Failed`, the served ones as
/// `Response` — nothing is silently dropped, and the server's refusal counter
/// is exactly the over-limit count.
#[test]
fn high_seam_per_pubkey_rate_cap_enforced() {
    let mut net = HighSeamNet::new(1001);
    let server = net.add_node(HighSeamNodeOptions::default());
    let client = net.add_node(HighSeamNodeOptions::default());
    net.connect(server, client);
    let server_pk = net.node_pubkey(server);
    net.store_insert(server, 7, 0, fake_shred(1));

    let cap = MAX_REPAIR_REQUESTS_PER_SECOND as usize;
    let excess = 20;
    // Whole burst issued BEFORE ticking: every request is delivered on the
    // same server tick and shares one 1s rate window.
    for _ in 0..cap + excess {
        net.request_repair(client, server_pk, RepairReq::WindowIndex { slot: 7, shred_index: 0 });
    }
    net.run_ticks(6);

    // Exactly the over-limit excess is refused (the tick model makes this
    // exact, not merely `> 0`).
    assert_eq!(net.core(server).repairs_refused(), excess as u64);
    // Requests up to the cap were served; the excess came back as Failed.
    let events = net.repair_events(client);
    assert_eq!(responses(events), cap, "served exactly the cap");
    assert_eq!(failures(events), excess, "refused clients see Failed");
    // Nothing else leaked out of the exchange.
    assert_eq!(events.len(), cap + excess);
}

/// High seam: the cap is per identity, not global. Two clients each sending a
/// modest sub-cap burst in the same window are both fully served — the
/// server's window for one pubkey never charges the other.
#[test]
fn high_seam_rate_cap_is_per_pubkey_not_global() {
    let mut net = HighSeamNet::new(1002);
    let server = net.add_node(HighSeamNodeOptions::default());
    let c1 = net.add_node(HighSeamNodeOptions::default());
    let c2 = net.add_node(HighSeamNodeOptions::default());
    net.connect(server, c1);
    net.connect(server, c2);
    let server_pk = net.node_pubkey(server);
    net.store_insert(server, 1, 0, fake_shred(2));

    // 50 + 50 = 100 total across two identities in one window; neither pubkey
    // reaches its own 100-per-second cap.
    for _ in 0..50 {
        net.request_repair(c1, server_pk, RepairReq::WindowIndex { slot: 1, shred_index: 0 });
    }
    for _ in 0..50 {
        net.request_repair(c2, server_pk, RepairReq::WindowIndex { slot: 1, shred_index: 0 });
    }
    net.run_ticks(6);

    assert_eq!(net.core(server).repairs_refused(), 0, "no per-pubkey cap hit");
    assert_eq!(responses(net.repair_events(c1)), 50);
    assert_eq!(responses(net.repair_events(c2)), 50);
}

/// High seam: the rate window is sliding, not a permanent ban. A client
/// rate-limited in one virtual second is served again once ≥1s of virtual
/// time has passed and its window has reopened.
#[test]
fn high_seam_rate_window_reopens_after_a_second() {
    let mut net = HighSeamNet::new(1003);
    let server = net.add_node(HighSeamNodeOptions::default());
    let client = net.add_node(HighSeamNodeOptions::default());
    net.connect(server, client);
    let server_pk = net.node_pubkey(server);
    net.store_insert(server, 9, 0, fake_shred(3));

    let cap = MAX_REPAIR_REQUESTS_PER_SECOND as usize;
    // Window 1: overflow the cap.
    for _ in 0..cap + 20 {
        net.request_repair(client, server_pk, RepairReq::WindowIndex { slot: 9, shred_index: 0 });
    }
    net.run_ticks(6);
    let refused_after_first = net.core(server).repairs_refused();
    let served_after_first = responses(net.repair_events(client));
    assert_eq!(refused_after_first, 20);
    assert_eq!(served_after_first, cap);

    // Six ticks have advanced virtual time well past the 1s window. A modest
    // fresh burst from the same client lands in a new window and is served.
    for _ in 0..10 {
        net.request_repair(client, server_pk, RepairReq::WindowIndex { slot: 9, shred_index: 0 });
    }
    net.run_ticks(6);

    assert_eq!(
        net.core(server).repairs_refused(),
        refused_after_first,
        "reopened window adds no refusals"
    );
    assert_eq!(
        responses(net.repair_events(client)),
        served_after_first + 10,
        "same client served again in the new window"
    );
}

/// High seam: a malformed (undecodable) request injected as raw stream ops
/// from a connected peer is inert — the malformed counter ticks, no panic,
/// and a subsequent *valid* request from the same peer is still served.
#[test]
fn high_seam_malformed_request_is_inert() {
    let mut net = HighSeamNet::new(1004);
    let server = net.add_node(HighSeamNodeOptions::default());
    let peer = net.add_node(HighSeamNodeOptions::default());
    net.connect(server, peer);
    let (server_pk, peer_pk) = (net.node_pubkey(server), net.node_pubkey(peer));
    net.store_insert(server, 5, 0, fake_shred(4));

    // Open + garbage Data + Fin, on an unused seq, as if sent by `peer`.
    let seq = 9999;
    let inject = |net: &mut HighSeamNet, kind| {
        net.inject_stream_op(
            server,
            peer_pk,
            MemStreamOp { initiator_is_sender: true, seq, kind },
        );
    };
    inject(&mut net, MemStreamOpKind::Open);
    inject(&mut net, MemStreamOpKind::Data(vec![0xff; 8]));
    inject(&mut net, MemStreamOpKind::Fin);

    assert!(
        net.core(server).repairs_malformed() >= 1,
        "undecodable request counted as malformed"
    );
    assert_eq!(net.core(server).repairs_refused(), 0, "malformed is not a refusal");

    // The server keeps working: a valid request from the same peer is served.
    let stream = net
        .request_repair(peer, server_pk, RepairReq::WindowIndex { slot: 5, shred_index: 0 })
        .expect("peer is connected");
    net.run_ticks(6);
    assert!(
        net.repair_events(peer).iter().any(|event| matches!(
            event,
            SimRepairEvent::Response { stream: s, shred: Some(sh), .. }
                if *s == stream && sh == &fake_shred(4)
        )),
        "valid request after garbage still served: {:?}",
        net.repair_events(peer)
    );
    assert!(net.core(server).repairs_malformed() >= 1);
}

/// High seam: an oversized request body (beyond `MAX_REPAIR_REQ_WIRE`) is
/// dropped the instant the inbound buffer overflows the ceiling — the stream
/// is torn down, the malformed counter ticks, and the server stays live for a
/// following valid request.
#[test]
fn high_seam_oversized_request_is_inert() {
    let mut net = HighSeamNet::new(1005);
    let server = net.add_node(HighSeamNodeOptions::default());
    let peer = net.add_node(HighSeamNodeOptions::default());
    net.connect(server, peer);
    let (server_pk, peer_pk) = (net.node_pubkey(server), net.node_pubkey(peer));
    net.store_insert(server, 6, 1, fake_shred(5));

    // 500 bytes >> MAX_REPAIR_REQ_WIRE (64): rejected at the buffer cap,
    // before it ever reaches decode.
    let seq = 8888;
    net.inject_stream_op(
        server,
        peer_pk,
        MemStreamOp { initiator_is_sender: true, seq, kind: MemStreamOpKind::Open },
    );
    net.inject_stream_op(
        server,
        peer_pk,
        MemStreamOp { initiator_is_sender: true, seq, kind: MemStreamOpKind::Data(vec![0xab; 500]) },
    );
    // The stream is already gone; a trailing Fin is a no-op, not a panic.
    net.inject_stream_op(
        server,
        peer_pk,
        MemStreamOp { initiator_is_sender: true, seq, kind: MemStreamOpKind::Fin },
    );

    assert!(
        net.core(server).repairs_malformed() >= 1,
        "oversized request counted as malformed"
    );

    let stream = net
        .request_repair(peer, server_pk, RepairReq::WindowIndex { slot: 6, shred_index: 1 })
        .expect("peer is connected");
    net.run_ticks(6);
    assert!(
        net.repair_events(peer).iter().any(|event| matches!(
            event,
            SimRepairEvent::Response { stream: s, shred: Some(sh), .. }
                if *s == stream && sh == &fake_shred(5)
        )),
        "server survived the oversized request"
    );
}

/// High seam, requester side: a garbage response injected onto an
/// outstanding repair stream fails the repair cleanly. The requester records
/// `Failed` (never a bogus `Response`) and counts the malformed body. Uses a
/// one-sided connection (A believes it is connected; B never answers) so the
/// only response A sees is the injected garbage.
#[test]
fn high_seam_malformed_response_is_inert() {
    let mut net = HighSeamNet::new(1006);
    let a = net.add_node(HighSeamNodeOptions::default());
    let b = net.add_node(HighSeamNodeOptions::default());
    let b_pk = net.node_pubkey(b);
    let b_addr = net.node_addr(b);
    // One-sided: A thinks it can reach B, but B has no connection back and
    // will never send a real response.
    net.core_mut(a).transport_mut().establish(b_pk, b_addr);

    let stream = net
        .request_repair(a, b_pk, RepairReq::WindowIndex { slot: 1, shred_index: 0 })
        .expect("A believes it is connected");

    // Inject an undecodable response body (as if from B) then FIN.
    net.inject_stream_op(
        a,
        b_pk,
        MemStreamOp {
            initiator_is_sender: false,
            seq: stream,
            kind: MemStreamOpKind::Data(vec![0xde, 0xad, 0xbe, 0xef]),
        },
    );
    net.inject_stream_op(
        a,
        b_pk,
        MemStreamOp { initiator_is_sender: false, seq: stream, kind: MemStreamOpKind::Fin },
    );

    let events = net.repair_events(a);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, SimRepairEvent::Failed { stream: s, .. } if *s == stream)),
        "garbage response fails the repair: {events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, SimRepairEvent::Response { .. })),
        "no bogus Response synthesized from garbage"
    );
    assert!(net.core(a).repairs_malformed() >= 1);
}

/// High seam, requester side: a *truncated* response (a bare FIN with no
/// body — the empty-bincode case) is equally inert. The requester fails the
/// repair and counts it malformed rather than trusting an empty buffer.
#[test]
fn high_seam_truncated_response_is_inert() {
    let mut net = HighSeamNet::new(1007);
    let a = net.add_node(HighSeamNodeOptions::default());
    let b = net.add_node(HighSeamNodeOptions::default());
    let b_pk = net.node_pubkey(b);
    let b_addr = net.node_addr(b);
    net.core_mut(a).transport_mut().establish(b_pk, b_addr);

    let stream = net
        .request_repair(a, b_pk, RepairReq::WindowIndex { slot: 2, shred_index: 0 })
        .expect("A believes it is connected");

    // FIN with no Data: an empty response buffer, which decodes to an error.
    net.inject_stream_op(
        a,
        b_pk,
        MemStreamOp { initiator_is_sender: false, seq: stream, kind: MemStreamOpKind::Fin },
    );

    let events = net.repair_events(a);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, SimRepairEvent::Failed { stream: s, .. } if *s == stream)),
        "truncated response fails the repair: {events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, SimRepairEvent::Response { .. })),
        "no Response from an empty body"
    );
    assert!(net.core(a).repairs_malformed() >= 1);
}

/// Low seam: over real quinn-proto streams, an attacker that opens a genuine
/// bidi stream and writes garbage before FIN is counted malformed and cannot
/// wedge the node — a legit repair from a second, gossip-connected sink still
/// succeeds afterward.
#[test]
fn low_seam_malformed_stream_is_inert_and_node_survives() {
    let mut world = SimWorld::new(1008);
    let server = world.add_node(NodeOptions::default());
    let server_addr = world.public_addr(server);
    let server_pk = world.overlay_pubkey(server);
    world.store_insert(server, 77, 3, fake_shred(9));

    let attacker = world.add_transport_node(NodeOptions::default());
    // A second overlay node that will reach the server the honest way, via a
    // gossip-established connection (first advert at t=10s).
    let sink = world.add_node(NodeOptions {
        static_peers: vec![server_addr],
        ..NodeOptions::default()
    });

    // Attacker dials the server and floods garbage on a real bidi stream.
    world.transport_send(attacker, server_addr, b"hello".to_vec());
    world.run_for(Duration::from_secs(2));
    let stream = world
        .transport_open_stream(attacker, &server_pk)
        .expect("attacker connection established, stream opens");
    world.transport_write_stream(attacker, stream, &vec![0xff; 40]);
    world.transport_finish_stream(attacker, stream);
    world.run_for(Duration::from_secs(2));

    assert!(
        world.repairs_malformed(server) >= 1,
        "garbage stream counted malformed, not panicked"
    );

    // Let gossip bring the sink's connection up, then repair honestly.
    world.run_for(Duration::from_secs(15));
    let s = world
        .request_repair(sink, server_pk, RepairReq::WindowIndex { slot: 77, shred_index: 3 })
        .expect("sink connected after gossip dial");
    world.run_for(Duration::from_secs(2));

    assert!(
        world.repair_events(sink).iter().any(|event| matches!(
            event,
            SimRepairEvent::Response { stream: st, shred: Some(sh), .. }
                if *st == s && sh == &fake_shred(9)
        )),
        "legit repair still served after the abuse: {:?}",
        world.repair_events(sink)
    );
    assert!(world.repairs_malformed(server) >= 1);
}

/// Low seam: the per-pubkey rate cap holds over real QUIC too. One bare
/// transport peer opens >100 valid repair streams within one virtual second
/// (batched under the 64-concurrent-bidi-stream limit, with short runs
/// between batches so streams complete and free slots), and the server
/// refuses the over-limit excess.
#[test]
fn low_seam_rate_limit_over_quic() {
    let mut world = SimWorld::new(1009);
    let server = world.add_node(NodeOptions::default());
    let server_addr = world.public_addr(server);
    let server_pk = world.overlay_pubkey(server);
    world.store_insert(server, 3, 0, fake_shred(1));

    let client = world.add_transport_node(NodeOptions::default());
    world.transport_send(client, server_addr, b"hello".to_vec());
    world.run_for(Duration::from_secs(2));

    let req = encode_request(&RepairReq::WindowIndex { slot: 3, shred_index: 0 });

    // Three batches of 60 (< the 64-concurrent cap) with 100ms runs between
    // them so each batch completes and returns stream credit: 180 valid
    // requests, all within one 1s rate window.
    let mut total = 0;
    for _ in 0..3 {
        for _ in 0..60 {
            if let Some(stream) = world.transport_open_stream(client, &server_pk) {
                world.transport_write_stream(client, stream, &req);
                world.transport_finish_stream(client, stream);
                total += 1;
            }
        }
        world.run_for(Duration::from_millis(100));
    }
    world.run_for(Duration::from_secs(1));

    assert!(total > 100, "sent {total} valid requests in one window");
    assert!(
        world.repairs_refused(server) > 0,
        "over-limit requests must be refused"
    );
}

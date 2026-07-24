//! P1 adversarial advert-security oracles (nat-traversal.md §2.2 F8, §6.1,
//! §9): signed adverts are verified before they are accepted OR forwarded,
//! sequence numbers order supersession and reject replay/downgrade, a node
//! ignores adverts for its own identity, and the single send choke point
//! (`send_to_peer`) only ever dials `Reachability::Direct` peers. The one
//! residual F8 surface the design leaves open until P3 (a *validly signed*
//! advert that lies about a `Direct` address it does not own) is pinned by
//! name so its closure is visible.
//!
//! Every frame reaches the node through `inject_datagram` — the harness's
//! adversarial injection point, delivering arbitrary bytes as if they came
//! from an established peer.

use arrayvec::ArrayVec;
use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};

use crate::overlay::OverlayMode;
use crate::overlay::gossip::{
    PeerAdvert, PortTaggedAddr, Reachability, RepairEndpoint, SignedPeerAdvert,
};
use crate::overlay::packet::{OVERLAY_PROTOCOL_VERSION, OverlayFrame};
use crate::overlay::sim::crypto;
use crate::overlay::sim::highseam::{HighSeamNet, HighSeamNodeOptions};
use crate::overlay::transport::OverlayTransport;

fn node_opts(mode: OverlayMode) -> HighSeamNodeOptions {
    HighSeamNodeOptions {
        mode,
        ..HighSeamNodeOptions::default()
    }
}

/// A `Direct` advert for `pubkey` reachable at a single address.
fn direct_advert(pubkey: Pubkey, seq: u64, addr: std::net::SocketAddr) -> PeerAdvert {
    let mut addrs = ArrayVec::new();
    addrs.push(addr);
    PeerAdvert {
        pubkey,
        advert_seq: seq,
        ttl_ms: 30_000,
        reachability: Reachability::Direct(addrs),
        repair: RepairEndpoint::InConnection,
    }
}

/// Encode `advert` into an overlay frame, signing with `signer` (which need
/// not match `advert.pubkey` — that mismatch is exactly what several tests
/// exercise).
fn signed_frame(advert: PeerAdvert, signer: &Keypair) -> Vec<u8> {
    let signed = SignedPeerAdvert::sign(advert, signer).expect("advert signs");
    OverlayFrame::peer_advertisement(signed)
        .encode()
        .expect("advert frame encodes")
}

/// The advert a node currently holds for `pubkey`, if any (live entries only).
fn stored_advert(net: &HighSeamNet, node: usize, pubkey: &Pubkey) -> Option<PeerAdvert> {
    let now = net.now_instant();
    net.core(node)
        .gossip_snapshot(now)
        .into_iter()
        .find(|advert| advert.pubkey == *pubkey)
}

/// F8: a forged signature is counted as invalid, dropped, and — crucially —
/// never flood-forwarded to the next hop (verify-before-forward).
#[test]
fn forged_advert_signature_is_rejected_and_never_forwarded() {
    let mut net = HighSeamNet::new(801);
    let a = net.add_node(node_opts(OverlayMode::Sink));
    let b = net.add_node(node_opts(OverlayMode::Sink));
    let c = net.add_node(node_opts(OverlayMode::Sink));
    net.connect(a, b);
    net.connect(b, c);
    let a_addr = net.node_addr(a);

    // Throwaway victim identity; the frame is signed by an unrelated key.
    let victim = Keypair::new();
    let attacker = Keypair::new();
    let frame = signed_frame(
        direct_advert(victim.pubkey(), 1, "203.0.113.9:65410".parse().unwrap()),
        &attacker,
    );

    let before = net.core(b).invalid_adverts();
    net.inject_datagram(b, a_addr, &frame);

    assert_eq!(
        net.core(b).invalid_adverts(),
        before + 1,
        "B must count the forged advert as invalid"
    );
    assert!(
        stored_advert(&net, b, &victim.pubkey()).is_none(),
        "B must not store a forged advert"
    );

    net.run_ticks(5);
    assert!(
        stored_advert(&net, b, &victim.pubkey()).is_none(),
        "forged advert must not appear in B after ticks"
    );
    assert!(
        stored_advert(&net, c, &victim.pubkey()).is_none(),
        "forged advert must never be forwarded to C"
    );
}

/// Positive control for the verify-before-forward path: a correctly signed
/// advert is accepted at the receiver and forwarded to its other peer.
#[test]
fn valid_advert_is_accepted_and_forwarded() {
    let mut net = HighSeamNet::new(802);
    let a = net.add_node(node_opts(OverlayMode::Sink));
    let b = net.add_node(node_opts(OverlayMode::Sink));
    let c = net.add_node(node_opts(OverlayMode::Sink));
    net.connect(a, b);
    net.connect(b, c);
    let a_addr = net.node_addr(a);

    // A fourth identity, correctly self-signed.
    let fourth = Keypair::new();
    let frame = signed_frame(
        direct_advert(fourth.pubkey(), 7, "203.0.113.44:65410".parse().unwrap()),
        &fourth,
    );

    net.inject_datagram(b, a_addr, &frame);
    assert!(
        stored_advert(&net, b, &fourth.pubkey()).is_some(),
        "B accepts a validly signed advert"
    );

    // The forward is queued on inject and delivered on the next tick.
    net.run_ticks(3);
    assert!(
        stored_advert(&net, c, &fourth.pubkey()).is_some(),
        "B forwards the valid advert on to C"
    );
}

/// §6.1 supersession: a lower `advert_seq` is a replay/downgrade and must not
/// overwrite the held reachability; a higher one supersedes.
#[test]
fn stale_sequence_is_rejected_and_higher_supersedes() {
    let mut net = HighSeamNet::new(803);
    let a = net.add_node(node_opts(OverlayMode::Sink));
    let b = net.add_node(node_opts(OverlayMode::Sink));
    net.connect(a, b);
    let a_addr = net.node_addr(a);

    let id = Keypair::new();
    let addr1: std::net::SocketAddr = "203.0.113.10:65410".parse().unwrap();
    let addr2: std::net::SocketAddr = "203.0.113.20:65410".parse().unwrap();

    net.inject_datagram(b, a_addr, &signed_frame(direct_advert(id.pubkey(), 5, addr1), &id));
    // Downgrade attempt: valid signature, older sequence, different address.
    net.inject_datagram(b, a_addr, &signed_frame(direct_advert(id.pubkey(), 3, addr2), &id));

    let held = stored_advert(&net, b, &id.pubkey()).expect("advert stored");
    assert_eq!(held.advert_seq, 5, "stale sequence must not overwrite");
    assert_eq!(
        held.direct_addrs(),
        &[addr1],
        "stale reachability must not overwrite"
    );

    // A genuinely newer sequence does supersede.
    net.inject_datagram(b, a_addr, &signed_frame(direct_advert(id.pubkey(), 6, addr2), &id));
    let held = stored_advert(&net, b, &id.pubkey()).expect("advert stored");
    assert_eq!(held.advert_seq, 6, "higher sequence supersedes");
    assert_eq!(
        held.direct_addrs(),
        &[addr2],
        "higher sequence updates reachability"
    );
}

/// §6.1 trust rule: a claimed pubkey is only trusted with a valid signature.
/// An advert bearing a victim's real pubkey but signed by an attacker is
/// rejected and cannot clobber the victim's genuine advert.
#[test]
fn advert_forged_under_victim_pubkey_cannot_clobber_genuine() {
    let mut net = HighSeamNet::new(804);
    // X is a real node whose genuine advert reaches B by its own flooding.
    let x = net.add_node(node_opts(OverlayMode::Sink));
    let b = net.add_node(node_opts(OverlayMode::Sink));
    net.connect(x, b);
    let x_pubkey = net.node_pubkey(x);
    let x_addr = net.node_addr(x);

    // First self-advert fires at tick 10; give it time to arrive.
    net.run_ticks(12);
    let genuine = stored_advert(&net, b, &x_pubkey).expect("B learned X's genuine advert");
    assert_eq!(
        genuine.direct_addrs(),
        &[x_addr],
        "genuine advert carries X's real address"
    );

    // Attacker forges an advert under X's identity, signed with its own key,
    // claiming a far-future sequence and a bogus address.
    let attacker = Keypair::new();
    let frame = signed_frame(
        direct_advert(
            x_pubkey,
            genuine.advert_seq + 100,
            "203.0.113.66:65410".parse().unwrap(),
        ),
        &attacker,
    );

    let before = net.core(b).invalid_adverts();
    net.inject_datagram(b, x_addr, &frame);
    assert_eq!(
        net.core(b).invalid_adverts(),
        before + 1,
        "identity theft is a signature failure"
    );

    let after = stored_advert(&net, b, &x_pubkey).expect("X's advert still present");
    assert_eq!(
        after.direct_addrs(),
        &[x_addr],
        "genuine advert is untouched by the forgery"
    );
    assert_eq!(
        after.advert_seq, genuine.advert_seq,
        "forged higher sequence never took effect"
    );
}

/// A node must ignore adverts for its own identity (no self-entry, no
/// forward) even when the signature is valid — the advert here is signed with
/// the receiver's own seed-derived keypair.
#[test]
fn self_advert_is_ignored_and_not_forwarded() {
    let seed = 805u64;
    let mut net = HighSeamNet::new(seed);
    let a = net.add_node(node_opts(OverlayMode::Sink));
    let b = net.add_node(node_opts(OverlayMode::Sink));
    let c = net.add_node(node_opts(OverlayMode::Sink));
    net.connect(a, b);
    net.connect(b, c);
    let a_addr = net.node_addr(a);
    let b_pubkey = net.node_pubkey(b);

    // The harness derives node keypairs from (seed, index); reconstruct B's.
    let b_keypair = crypto::derive_keypair(seed, b as u32);
    assert_eq!(b_keypair.pubkey(), b_pubkey, "reconstructed B's own keypair");

    let frame = signed_frame(
        direct_advert(b_pubkey, 9, "203.0.113.77:65410".parse().unwrap()),
        &b_keypair,
    );
    net.inject_datagram(b, a_addr, &frame);
    assert!(
        stored_advert(&net, b, &b_pubkey).is_none(),
        "node never stores an advert for its own identity"
    );

    // Fewer than 10 ticks: B never floods a genuine self-advert either, so
    // any B entry at C could only have come from forwarding the injected one.
    net.run_ticks(5);
    assert!(
        stored_advert(&net, c, &b_pubkey).is_none(),
        "a self-advert is not forwarded"
    );
}

/// F2/F8: a `Coordinated` advert (no dialable address) for an unconnected
/// identity is excluded from the usable-peer set (`usable_peers` in
/// service.rs only admits established connections + `Direct` peers). It
/// therefore never enters the turbine tree, `send_to_peer` is never invoked
/// for it, `dropped_unreachable` never even increments, and the bystander
/// address named in its `observed` hint is never dialed.
///
/// Semantics verified: exclusion-from-tree (counter stays 0), NOT
/// dial-then-drop.
#[test]
fn coordinated_advert_is_never_dialed() {
    let mut net = HighSeamNet::new(806);
    let source = net.add_node(node_opts(OverlayMode::Source));
    // A real bystander whose address the attacker names as V's mapping.
    let bystander = net.add_node(node_opts(OverlayMode::Sink));
    let bystander_addr = net.node_addr(bystander);
    let bystander_pubkey = net.node_pubkey(bystander);

    // Throwaway identity V, validly signed, advertised as Coordinated with
    // the bystander's address as an observed (hint-only) mapping.
    let v = Keypair::new();
    let mut observed = ArrayVec::new();
    observed.push(PortTaggedAddr {
        observer_port: 65_410,
        mapping: bystander_addr,
    });
    let advert = PeerAdvert {
        pubkey: v.pubkey(),
        advert_seq: 1,
        ttl_ms: 30_000,
        reachability: Reachability::Coordinated {
            observed,
            via: ArrayVec::new(),
        },
        repair: RepairEndpoint::InConnection,
    };
    net.inject_datagram(source, "203.0.113.5:65410".parse().unwrap(), &signed_frame(advert, &v));
    assert!(
        stored_advert(&net, source, &v.pubkey()).is_some(),
        "the coordinated advert is stored (valid signature)"
    );

    // Originate a shred: V must not be selected as a fan-out target.
    net.inject_shred(source, &[3u8; 64]);
    net.run_ticks(5);

    assert_eq!(
        net.core(source).dropped_unreachable(),
        0,
        "a coordinated-without-connection peer never enters the tree"
    );
    assert!(
        net.core(source)
            .transport()
            .connection_addr(&v.pubkey())
            .is_none(),
        "V is never dialed or connected"
    );
    assert!(
        !net.core(source)
            .transport()
            .is_connected_to(&bystander_pubkey),
        "the observed-hint bystander is never dialed"
    );
    assert!(
        net.delivered_shreds(bystander).is_empty(),
        "the bystander receives no unsolicited overlay traffic"
    );
}

/// F8 CLOSED (P3, §6.2.3 step 3 / §9): a *validly signed* advert that claims
/// `Direct([victim_addr])` for an address it does not own can no longer direct
/// traffic at the victim. The identity-gated dial-on-demand releases the shred
/// only to the advertised identity; the victim answers as itself (≠ V), so the
/// payload is dropped undelivered and the liar is quarantined. This is the
/// inversion of the pre-P3 pinned limitation.
#[test]
fn lying_direct_advert_cannot_direct_traffic_at_victim() {
    let mut net = HighSeamNet::new(807);
    let source = net.add_node(node_opts(OverlayMode::Source));
    // The victim is a real node that never advertised itself.
    let victim = net.add_node(node_opts(OverlayMode::Sink));
    let victim_addr = net.node_addr(victim);

    // Identity V lies: validly self-signed, but claims the victim's address
    // as its own Direct address.
    let v = Keypair::new();
    let frame = signed_frame(direct_advert(v.pubkey(), 1, victim_addr), &v);
    net.inject_datagram(source, "203.0.113.5:65410".parse().unwrap(), &frame);
    assert!(
        stored_advert(&net, source, &v.pubkey()).is_some(),
        "the lying advert is stored (its signature is valid)"
    );

    // Originate several shreds over time: V is the only Direct peer, so the
    // tree keeps selecting it. None of them may reach the victim.
    for _ in 0..3 {
        net.inject_shred(source, &[7u8; 64]);
        net.run_ticks(3);
    }

    assert!(
        net.delivered_shreds(victim).is_empty(),
        "the victim received shreds via a lying Direct advert (F8 not closed)",
    );
    assert!(
        net.core(source).quarantined_count() >= 1,
        "source must quarantine the lied-about address",
    );
}

/// Malformed frames must never panic, never mutate gossip, and never wedge
/// the node: a valid advert injected afterwards is still accepted.
#[test]
fn malformed_frames_do_not_disturb_the_node() {
    let mut net = HighSeamNet::new(808);
    let a = net.add_node(node_opts(OverlayMode::Sink));
    let b = net.add_node(node_opts(OverlayMode::Sink));
    net.connect(a, b);
    let a_addr = net.node_addr(a);

    let malformed: Vec<Vec<u8>> = vec![
        vec![],                                             // empty datagram
        vec![OVERLAY_PROTOCOL_VERSION],                     // header truncated
        vec![OVERLAY_PROTOCOL_VERSION + 1, 1, 0],           // unsupported version
        vec![OVERLAY_PROTOCOL_VERSION, 200, 0],             // unknown frame type
        vec![OVERLAY_PROTOCOL_VERSION, 1],                  // advert body missing
        vec![OVERLAY_PROTOCOL_VERSION, 1, 0xFF, 0xFF, 0xFF],// garbage advert body
    ];
    for bytes in &malformed {
        net.inject_datagram(b, a_addr, bytes);
    }
    assert_eq!(
        net.core(b).gossip_len(),
        0,
        "malformed frames add nothing to gossip"
    );

    // The node still functions: a subsequent valid advert is accepted.
    let id = Keypair::new();
    let frame = signed_frame(
        direct_advert(id.pubkey(), 1, "203.0.113.88:65410".parse().unwrap()),
        &id,
    );
    net.inject_datagram(b, a_addr, &frame);
    assert!(
        stored_advert(&net, b, &id.pubkey()).is_some(),
        "a valid advert is accepted after the malformed junk"
    );
}

//! P3 dial-back reflection defense, the requester-side advert-policy state
//! machine, and extra F8 closure (nat-traversal.md §6.2.3, §9), both sim tiers.
//!
//! Sibling `dialback_core.rs` already covers the low-seam full-cone/port-
//! restricted confirmation outcomes and the high-seam per-pubkey rate limit,
//! privileged-port refusal, and malformed-frame inertness. This file adds what
//! those do not: the reflection oracle (a dial-back can never be aimed at a
//! third party — structurally, because the request frame carries no address),
//! the requester-side reachability state machine read straight off a peer's
//! gossip (Direct after a genuine fresh-source confirm; Coordinated otherwise
//! with the §12-Q3 hint policy), a sustained multi-victim F8 closure, and the
//! unconnected-requester helper refusal.

use std::{net::SocketAddr, time::Duration};

use arrayvec::ArrayVec;
use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};

use crate::overlay::OverlayMode;
use crate::overlay::gossip::{PeerAdvert, Reachability, RepairEndpoint, SignedPeerAdvert};
use crate::overlay::nat::NatClass;
use crate::overlay::packet::OverlayFrame;
use crate::overlay::sim::highseam::{HighSeamNet, HighSeamNodeOptions};
use crate::overlay::sim::{HostId, NodeOptions, SimWorld, nat::NatConfig, net::LinkParams};
use crate::overlay::transport::OverlayTransport;

fn dialback_request_frame(nonce: u64) -> Vec<u8> {
    OverlayFrame::dialback_request(nonce)
        .encode()
        .expect("dial-back request encodes")
}

fn node_opts(mode: OverlayMode) -> HighSeamNodeOptions {
    HighSeamNodeOptions {
        mode,
        ..HighSeamNodeOptions::default()
    }
}

/// A `Direct` advert for `pubkey` reachable at a single address (local mirror
/// of the `advert_security.rs` helper — reproduced, not shared, per the P1
/// style of small per-suite builders).
fn direct_advert(pubkey: Pubkey, seq: u64, addr: SocketAddr) -> PeerAdvert {
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

/// Encode `advert` into an overlay frame, signing with `signer`.
fn signed_frame(advert: PeerAdvert, signer: &Keypair) -> Vec<u8> {
    let signed = SignedPeerAdvert::sign(advert, signer).expect("advert signs");
    OverlayFrame::peer_advertisement(signed)
        .encode()
        .expect("advert frame encodes")
}

/// A zero-config subject behind `nat` (or public if `None`) plus three public
/// observers on the §6.2 port spread `[3478, 3478, 5321]` — two share an
/// inbound port on distinct IPs (the within-group symmetric check), one is on
/// a different port (the across-group check). Bind port 51000 sits inside the
/// NAT external pool so a port-preserving allocator can present it. Returns the
/// world (already advanced 45s: classification + dial-back both on advert
/// cycles), a witness observer, the subject, and the subject's pubkey.
fn reachability_subject(seed: u64, nat: Option<NatConfig>) -> (SimWorld, HostId, HostId, Pubkey) {
    const OBSERVER_PORTS: [u16; 3] = [3478, 3478, 5321];
    const SUBJECT_BIND_PORT: u16 = 51_000;

    let mut world = SimWorld::with_trace(seed, false);
    world.set_default_link(
        LinkParams::default().delay(Duration::from_millis(2), Duration::from_millis(6)),
    );
    let observers: Vec<HostId> = OBSERVER_PORTS
        .iter()
        .map(|&port| {
            world.add_node(NodeOptions {
                bind_port: port,
                ..NodeOptions::default()
            })
        })
        .collect();
    let observer_addrs: Vec<SocketAddr> =
        observers.iter().map(|&host| world.public_addr(host)).collect();
    let witness = observers[0];
    let subject = world.add_node(NodeOptions {
        nat: nat.into_iter().collect(),
        static_peers: observer_addrs,
        bind_port: SUBJECT_BIND_PORT,
        zero_config: true,
        ..NodeOptions::default()
    });
    let subject_pk = world.overlay_pubkey(subject);
    world.run_for(Duration::from_secs(45));
    (world, witness, subject, subject_pk)
}

/// Reflection defense (§9), low seam with the real probe: a full-cone subject
/// confirms Direct through a helper's genuine fresh-source probe, yet a
/// bystander the subject neither controls nor connects to receives zero probe
/// traffic. The probe target is structurally the subject's OWN observed
/// mapping (the request frame carries no address), so no third party can be
/// aimed at — confirmed by the candidate's IP matching the subject's mapping.
#[test]
fn dialback_probe_never_reflects_at_a_bystander() {
    let mut world = SimWorld::with_trace(0xD1A1, false);
    world.set_default_link(
        LinkParams::default().delay(Duration::from_millis(2), Duration::from_millis(6)),
    );
    // Three public helpers the subject dials and is observed by.
    let helper_addrs: Vec<SocketAddr> = (0..3)
        .map(|_| {
            let helper = world.add_node(NodeOptions::default());
            world.public_addr(helper)
        })
        .collect();
    // A bystander on its own public IP, bound so any stray datagram to it would
    // be recorded. No overlay node ever learns of it, so nothing legitimately
    // targets it — and a reflected probe would have to.
    let bystander = world.add_probe(Vec::new());
    world.probe_bind(bystander, 65_410);

    let subject = world.add_node(NodeOptions {
        nat: vec![NatConfig::full_cone()],
        static_peers: helper_addrs,
        ..NodeOptions::default()
    });
    world.run_for(Duration::from_secs(45));

    let confirmed = world
        .confirmed_direct(subject)
        .expect("full-cone confirms Direct via a fresh-source probe");
    assert_eq!(
        confirmed.ip(),
        world.external_ip(subject, 0),
        "the probe confirmed the subject's OWN external mapping, not a third party",
    );
    assert!(
        world.probe_received(bystander).is_empty(),
        "a bystander received dial-back probe traffic — reflection vector open",
    );
}

/// Reflection defense (§9), high seam, structural: the dial-back request frame
/// carries no address, so a helper can only ever target the requester's own
/// connection address. Injecting a request into a helper connected to A, with a
/// bystander B present, starts no probe (the high seam binds no sockets) and
/// sends nothing toward B — any datagram to B would auto-establish a
/// connection, so B staying peerless proves it was never contacted. A
/// well-formed request from a genuine peer is not counted as a refusal.
#[test]
fn dialback_request_carries_no_third_party_target() {
    let mut net = HighSeamNet::new(0xD1A2);
    let helper = net.add_node(HighSeamNodeOptions::default());
    let requester = net.add_node(HighSeamNodeOptions::default());
    let bystander = net.add_node(HighSeamNodeOptions::default());
    net.connect(helper, requester);
    let requester_addr = net.node_addr(requester);
    let helper_pubkey = net.node_pubkey(helper);
    let bystander_pubkey = net.node_pubkey(bystander);

    let before = net.core(helper).dialbacks_refused();
    net.inject_datagram(helper, requester_addr, &dialback_request_frame(1));
    net.run_ticks(3);

    assert_eq!(
        net.core(helper).active_helper_probes(),
        0,
        "the high seam binds no sockets, so no fresh-source probe is started",
    );
    assert_eq!(
        net.core(helper).dialbacks_refused(),
        before,
        "a well-formed request from a connected peer is not a refusal",
    );
    assert!(
        !net.core(helper).transport().is_connected_to(&bystander_pubkey),
        "the helper reached a third party from a dial-back request",
    );
    assert!(
        net.core(bystander).transport().connected_peers().is_empty(),
        "the bystander was contacted by the helper (reflection)",
    );
    assert!(
        net.core(helper)
            .transport()
            .is_connected_to(&net.node_pubkey(requester)),
        "the helper's only correspondent stays the requester itself",
    );
    // Sanity: the bystander never learned the helper's identity either.
    assert!(
        !net.core(bystander)
            .transport()
            .is_connected_to(&helper_pubkey),
    );
}

/// F8 CLOSED, sustained multi-victim (§6.2.3 step 3 / §9): two validly signed
/// adverts each claim a distinct real victim's address as their own `Direct`.
/// Across many shred originations the identity-gated dial never releases a
/// payload to a victim — each victim answers as itself, not the liar — so both
/// victims stay at zero deliveries and both lied-about addresses are
/// quarantined and thereafter excluded from fan-out. This extends the
/// single-shot flip in `advert_security.rs` to a longer, multi-victim run.
#[test]
fn lying_direct_adverts_cannot_sustain_traffic_at_multiple_victims() {
    let mut net = HighSeamNet::new(0xD1F8);
    let source = net.add_node(node_opts(OverlayMode::Source));
    // Two real victims that never advertised themselves.
    let victim_a = net.add_node(node_opts(OverlayMode::Sink));
    let victim_b = net.add_node(node_opts(OverlayMode::Sink));
    let victim_a_addr = net.node_addr(victim_a);
    let victim_b_addr = net.node_addr(victim_b);

    // Two liars, each validly self-signed, each claiming a victim's address.
    let liar_a = Keypair::new();
    let liar_b = Keypair::new();
    net.inject_datagram(
        source,
        "203.0.113.5:65410".parse().unwrap(),
        &signed_frame(direct_advert(liar_a.pubkey(), 1, victim_a_addr), &liar_a),
    );
    net.inject_datagram(
        source,
        "203.0.113.6:65410".parse().unwrap(),
        &signed_frame(direct_advert(liar_b.pubkey(), 1, victim_b_addr), &liar_b),
    );
    assert_eq!(
        net.core(source).gossip_len(),
        2,
        "both lying adverts are stored (their signatures are valid)",
    );

    // Sustain origination: the liars are the only Direct peers, so the tree
    // keeps selecting them until each lied-about address is quarantined.
    for round in 0..10u8 {
        net.inject_shred(source, &[0xA0 | round; 96]);
        net.run_ticks(2);
    }
    net.run_ticks(4);

    assert!(
        net.delivered_shreds(victim_a).is_empty(),
        "victim A received shreds via a lying Direct advert (F8 not closed)",
    );
    assert!(
        net.delivered_shreds(victim_b).is_empty(),
        "victim B received shreds via a lying Direct advert (F8 not closed)",
    );
    assert!(
        net.core(source).quarantined_count() >= 2,
        "source must quarantine both lied-about addresses, got {}",
        net.core(source).quarantined_count(),
    );
}

/// §9 helper hardening (distinct from the rate-limit / privileged-port refusals
/// already in `dialback_core.rs`): a dial-back request from an address the
/// helper has no established connection with is dropped before any work — the
/// helper cannot be induced to probe a target it does not itself already see
/// the requester at. Being unauthenticated, such a request starts no probe and
/// is not even counted, so an off-path attacker cannot amplify helper state
/// however large the burst.
#[test]
fn helper_refuses_dialback_without_requester_connection() {
    let mut net = HighSeamNet::new(0xD1C0);
    let helper = net.add_node(HighSeamNodeOptions::default());
    // The helper does have a real, unrelated peer — "has connections" is true
    // in general, just not with the request's source address.
    let neighbor = net.add_node(HighSeamNodeOptions::default());
    net.connect(helper, neighbor);

    let stranger: SocketAddr = "203.0.113.201:65410".parse().unwrap();
    const BURST: u64 = 32;
    for nonce in 0..BURST {
        net.inject_datagram(helper, stranger, &dialback_request_frame(nonce));
    }

    assert_eq!(
        net.core(helper).active_helper_probes(),
        0,
        "no probe is started for an unconnected requester",
    );
    assert_eq!(
        net.core(helper).dialbacks_refused(),
        0,
        "an off-path (unconnected) request is dropped uncounted, not refused",
    );
}

/// Advert-policy state machine (deliverable b), low seam with the real probe:
/// a zero-config full-cone subject classifies EIM, confirms its mapping through
/// a genuinely fresh source port, and the advert a peer actually holds for it
/// is `Reachability::Direct` carrying a dial address.
#[test]
fn full_cone_advert_becomes_direct_after_dialback() {
    let (world, witness, subject, subject_pk) =
        reachability_subject(0xD1B0, Some(NatConfig::full_cone()));

    assert_eq!(
        world.nat_class(subject),
        Some(NatClass::EndpointIndependent),
        "full-cone classifies EIM",
    );
    assert!(
        world.confirmed_direct(subject).is_some(),
        "full-cone confirms a Direct candidate via the fresh-source probe",
    );
    let advert = world
        .peer_advert(witness, &subject_pk)
        .expect("the observer learned the subject's advert");
    match advert.reachability {
        Reachability::Direct(addrs) => assert!(
            !addrs.is_empty(),
            "a Direct advert carries at least one dial address",
        ),
        other => panic!("expected Direct after dial-back, got {other:?}"),
    }
}

/// Advert-policy state machine (deliverable b), low seam: a port-restricted
/// subject classifies EIM too, but the fresh-source probe (a port the NAT was
/// never primed with) is filtered, so dial-back never confirms — classification
/// is not confirmation. The advert stays `Reachability::Coordinated` carrying
/// non-empty port-tagged `observed` hints (the §12-Q3 policy for a non-symmetric
/// flavor).
#[test]
fn port_restricted_advert_stays_coordinated_with_hints() {
    let (world, witness, subject, subject_pk) =
        reachability_subject(0xD1B1, Some(NatConfig::port_restricted_cone()));

    assert_eq!(
        world.nat_class(subject),
        Some(NatClass::EndpointIndependent),
        "port-restricted still classifies EIM (its mapping is endpoint-independent)",
    );
    assert_eq!(
        world.confirmed_direct(subject),
        None,
        "the filtered fresh-source probe never confirms Direct",
    );
    let advert = world
        .peer_advert(witness, &subject_pk)
        .expect("the observer learned the subject's advert");
    match advert.reachability {
        Reachability::Coordinated { observed, .. } => assert!(
            !observed.is_empty(),
            "an EIM-but-unconfirmed node advertises port-tagged observed hints",
        ),
        other => panic!("expected Coordinated hints, got {other:?}"),
    }
}

/// Advert-policy state machine (deliverable b), low seam: a fully symmetric
/// subject has no single Direct candidate (a fresh mapping per destination), so
/// dial-back never confirms and, per the §12-Q3 flavor policy, its advert is
/// `Reachability::Coordinated` with EMPTY `observed` (per-destination ports are
/// noise) and a non-empty `via` list of connected relays.
#[test]
fn symmetric_random_advert_is_coordinated_via_only() {
    let (world, witness, subject, subject_pk) =
        reachability_subject(0xD1B2, Some(NatConfig::symmetric_random()));

    assert_eq!(
        world.nat_class(subject),
        Some(NatClass::Symmetric),
        "a fresh mapping per destination classifies fully symmetric",
    );
    assert_eq!(
        world.confirmed_direct(subject),
        None,
        "a symmetric node has no single Direct candidate to confirm",
    );
    let advert = world
        .peer_advert(witness, &subject_pk)
        .expect("the observer learned the subject's advert");
    match advert.reachability {
        Reachability::Coordinated { observed, via } => {
            assert!(
                observed.is_empty(),
                "a fully symmetric node advertises no observed hints",
            );
            assert!(
                !via.is_empty(),
                "coordinated reachability lists connected relays in via",
            );
        }
        other => panic!("expected Coordinated via-only, got {other:?}"),
    }
}

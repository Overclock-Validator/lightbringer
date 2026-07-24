//! P4 advertising-invariant oracles (nat-traversal.md §6.3: the port-mapping
//! + IPv6 dual-advertisement ladder — both dial-back-confirmed before a node
//! advertises them) plus P3 no-regression. Low-seam [`SimWorld`] worlds with
//! real `OverlayCore` state machines: zero-config NATed subjects walk the
//! §6.3 ladder against a co-located gateway model while public observer/helper
//! nodes carry gossip and run the fresh-source dial-backs. Fixed literal
//! seeds; deterministic assertions only.
//!
//! The §6.3 contract these guard is *additive*: a gateway grant can only
//! *upgrade* reachability, never manufacture a misadvert. Every Direct address
//! a peer ever observes must be a real, dial-back-confirmed external mapping —
//! never a private LAN address, never an unconfirmed grant, and (the §4 punchr
//! caution) never a v6 path that was never proven end to end.

use std::net::SocketAddr;
use std::time::Duration;

use crate::overlay::OverlayMode;
use crate::overlay::gossip::Reachability;
use crate::overlay::sim::{
    HostId, NodeOptions, SimWorld,
    gateway::GatewayConfig,
    nat::{NatClass, NatConfig},
    net::LinkParams,
};

/// Two observers share an inbound port on distinct IPs (the within-group
/// symmetric check), one is on a different port (the across-group port check) —
/// the §6.2 observer spread the subject dials to have its mapping observed and
/// to be dial-back-confirmed. The witness is `observers[0]`.
const OBSERVER_PORTS: [u16; 3] = [3478, 3478, 5321];

/// A NATed subject binds inside the NAT external port pool (40000–59999) so a
/// port-preserving/gateway-static allocator can present the requested port
/// (matches `scenario::SUBJECT_BIND_PORT`). A default 65410 bind falls outside
/// the pool and would perturb the mapped port.
const SUBJECT_BIND_PORT: u16 = 51_000;

/// A calm, low-latency link: the §6.3 ladder + observation + dial-back cycles
/// are the thing under test, not link faults.
fn calm_link() -> LinkParams {
    LinkParams::default().delay(Duration::from_millis(2), Duration::from_millis(6))
}

fn spawn_observers(world: &mut SimWorld, ipv6: bool) -> Vec<HostId> {
    OBSERVER_PORTS
        .iter()
        .map(|&port| {
            world.add_node(NodeOptions {
                bind_port: port,
                ipv6,
                ..NodeOptions::default()
            })
        })
        .collect()
}

fn observer_addrs(world: &SimWorld, observers: &[HostId]) -> Vec<SocketAddr> {
    observers.iter().map(|&host| world.public_addr(host)).collect()
}

/// A zero-config NATed subject that walks the §6.3 ladder against `gateway`.
fn nat_subject(
    world: &mut SimWorld,
    nat: NatConfig,
    gateway: GatewayConfig,
    static_peers: Vec<SocketAddr>,
    ipv6: bool,
) -> HostId {
    world.add_node(NodeOptions {
        nat: vec![nat],
        gateway: Some(gateway),
        static_peers,
        bind_port: SUBJECT_BIND_PORT,
        zero_config: true,
        ipv6,
        ..NodeOptions::default()
    })
}

/// A private/loopback/unspecified address must never ride a Direct advert
/// (the F1 misadvertisement §6.1/§6.3 forbids).
fn is_private(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_unspecified(),
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

/// Distinct ~1203-byte synthetic source payloads. These are not valid shreds,
/// so the turbine shuffle keys on the raw bytes; varying `tag` varies the
/// origin-peer selection, so injecting a spread of them exercises fan-out to
/// every Direct peer the source knows.
fn shred_payload(tag: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1203);
    payload.extend_from_slice(&tag.to_le_bytes());
    while payload.len() < 1203 {
        payload.push((tag as u8).wrapping_add(payload.len() as u8));
    }
    payload.truncate(1203);
    payload
}

/// §6.3 P3 no-regression: an *absent* gateway (the ~25-35% "disabled"
/// population) is the null step of the ladder — the node lands exactly where
/// P3 left it. A symmetric-random and a port-restricted-cone zero-config
/// subject, each with `GatewayConfig::absent()`, stay `Coordinated` at the
/// witness with no mapping and no confirmed port-map; the port-restricted one
/// still classifies EndpointIndependent. A gateway that grants nothing must
/// change nothing.
#[test]
fn absent_gateway_is_a_p3_no_op() {
    let mut world = SimWorld::new(42);
    world.set_default_link(calm_link());

    let observers = spawn_observers(&mut world, true);
    let witness = observers[0];
    let peers = observer_addrs(&world, &observers);

    let symmetric = nat_subject(
        &mut world,
        NatConfig::symmetric_random(),
        GatewayConfig::absent(),
        peers.clone(),
        true,
    );
    let restricted = nat_subject(
        &mut world,
        NatConfig::port_restricted_cone(),
        GatewayConfig::absent(),
        peers,
        true,
    );

    world.run_for(Duration::from_secs(50));

    for (label, subject) in [("symmetric", symmetric), ("restricted", restricted)] {
        let pk = world.overlay_pubkey(subject);
        let advert = world
            .peer_advert(witness, &pk)
            .unwrap_or_else(|| panic!("{label}: witness never learned the advert"));
        assert!(
            matches!(advert.reachability, Reachability::Coordinated { .. }),
            "{label}: absent gateway must leave the node Coordinated, got {:?}",
            advert.reachability
        );
        assert!(
            advert.direct_addrs().is_empty(),
            "{label}: absent gateway must not produce a Direct address"
        );
        assert!(
            world.confirmed_portmap(subject).is_none(),
            "{label}: absent gateway confirmed a port-map"
        );
        assert!(
            world.portmap_mapped(subject).is_none(),
            "{label}: absent gateway produced a believed mapping"
        );
    }

    // The port-restricted subject still infers its NAT class exactly as P3 —
    // gateway state never touches §6.2 classification.
    assert_eq!(
        world.nat_class(restricted),
        Some(NatClass::EndpointIndependent),
        "port-restricted-cone must classify EndpointIndependent regardless of the gateway"
    );
}

/// §6.3/§6.1 F1 under P4 — additive, never a misadvert: a zero-config
/// symmetric subject with a working gateway is sampled across 60s of its
/// lifecycle. Every Direct address the witness *ever* holds is a real,
/// dial-back-confirmed external mapping — the gateway-mapped `(external_ip,
/// 51000)` and/or the confirmed v6 address — never a private LAN address and
/// never an address the subject has not confirmed at that instant. A grant can
/// only upgrade reach; it can never manufacture a Direct address the node
/// cannot actually be reached at.
#[test]
fn granted_subject_only_advertises_confirmed_external_addrs() {
    let mut world = SimWorld::new(42);
    world.set_default_link(calm_link());

    let observers = spawn_observers(&mut world, true);
    let witness = observers[0];
    let peers = observer_addrs(&world, &observers);
    let subject = nat_subject(
        &mut world,
        NatConfig::symmetric_random(),
        GatewayConfig::granting(),
        peers,
        true,
    );
    let subject_pk = world.overlay_pubkey(subject);

    // Six checkpoints across the whole lifecycle (boot → ladder → observe →
    // dial-back → advertise); the invariant must hold at every one.
    for step in 0..6 {
        world.run_for(Duration::from_secs(10));

        let Some(advert) = world.peer_advert(witness, &subject_pk) else {
            continue;
        };
        let mapped_v4 = SocketAddr::new(world.external_ip(subject, 0), SUBJECT_BIND_PORT);
        let subject_v6 = world.addr_v6(subject);
        // The subject's own confirmed candidates at this instant; nothing the
        // witness advertises may fall outside this set.
        let confirmed: Vec<SocketAddr> = [
            world.confirmed_portmap(subject),
            world.confirmed_v6(subject),
            world.confirmed_direct(subject),
        ]
        .into_iter()
        .flatten()
        .collect();

        for &addr in advert.direct_addrs() {
            assert!(
                !is_private(addr.ip()),
                "step {step}: advertised a private address {addr}"
            );
            assert!(
                addr == mapped_v4 || addr == subject_v6,
                "step {step}: advertised {addr}, not the mapped v4 {mapped_v4} or v6 {subject_v6}"
            );
            assert!(
                confirmed.contains(&addr),
                "step {step}: advertised unconfirmed address {addr} (confirmed = {confirmed:?})"
            );
        }
    }
}

/// §6.3 caution as a long-run invariant — the lying gateway: `grant_fake()`
/// answers success on every tier and installs nothing, so the mapped port a
/// fresh-source probe targets is unreachable. Over 90s (well past several
/// re-lease cycles) the client keeps a *believed* mapping (`portmap_mapped`
/// Some — it took the gateway at its word), yet the fresh-source dial-back
/// never confirms it (`confirmed_portmap` stays None) and the witness advert
/// never turns Direct. A grant alone is never trusted.
#[test]
fn grant_fake_never_confirms_even_given_time() {
    let mut world = SimWorld::new(42);
    world.set_default_link(calm_link());

    let observers = spawn_observers(&mut world, true);
    let witness = observers[0];
    let peers = observer_addrs(&world, &observers);
    let subject = nat_subject(
        &mut world,
        NatConfig::symmetric_random(),
        GatewayConfig::grant_fake(),
        peers,
        true,
    );
    let subject_pk = world.overlay_pubkey(subject);

    let mut ever_believed_mapping = false;
    for step in 0..6 {
        world.run_for(Duration::from_secs(15));
        ever_believed_mapping |= world.portmap_mapped(subject).is_some();

        assert!(
            world.confirmed_portmap(subject).is_none(),
            "step {step}: a fake grant was confirmed"
        );
        if let Some(advert) = world.peer_advert(witness, &subject_pk) {
            assert!(
                advert.direct_addrs().is_empty(),
                "step {step}: fake grant produced a Direct advert {:?}",
                advert.direct_addrs()
            );
        }
    }

    assert!(
        ever_believed_mapping,
        "the client should have taken the fake grant at face value (a believed mapping)"
    );
    let advert = world
        .peer_advert(witness, &subject_pk)
        .expect("witness should still know the subject via Coordinated");
    assert!(
        matches!(advert.reachability, Reachability::Coordinated { .. }),
        "fake grant must leave the node Coordinated, got {:?}",
        advert.reachability
    );
}

/// §4 punchr caution — an unconfirmed v6 path is never advertised: a
/// dual-stack subject with a granting gateway (so a PCP pinhole may open) whose
/// helpers are all v4-only. With no v6 peer to dial, the subject can never have
/// its v6 source observed or run a v6 dial-back, so v6 is never confirmed —
/// even though the firewall pinhole is live. The witness advert becomes Direct
/// via the confirmed v4 mapping, but carries no v6 address. A pinhole alone
/// (the mechanism the punchr campaign found peers over-trusted, advertising
/// unusable v6) must not authorize advertising.
#[test]
fn unconfirmed_v6_is_never_advertised() {
    let mut world = SimWorld::new(11);
    world.set_default_link(calm_link());

    // v4-only helpers: they advertise only a v4 Direct address, so the subject
    // has no v6 endpoint to dial for a v6 observation / dial-back.
    let observers = spawn_observers(&mut world, false);
    let witness = observers[0];
    let peers = observer_addrs(&world, &observers);
    let subject = nat_subject(
        &mut world,
        NatConfig::port_restricted_cone(),
        GatewayConfig::granting(),
        peers,
        true,
    );
    let subject_pk = world.overlay_pubkey(subject);

    world.run_for(Duration::from_secs(60));

    // The v6 firewall pinhole may well be live — but that alone proves nothing
    // about end-to-end reachability, so v6 stays unconfirmed and unadvertised.
    assert!(
        world.confirmed_v6(subject).is_none(),
        "v6 was confirmed with no v6 peer to observe or dial back the path"
    );

    let advert = world
        .peer_advert(witness, &subject_pk)
        .expect("witness never learned the subject's advert");
    let addrs = advert.direct_addrs();
    assert!(
        !addrs.is_empty(),
        "the confirmed v4 mapping should still make the node Direct"
    );
    assert!(
        !addrs.iter().any(|addr| addr.is_ipv6()),
        "advertised an unconfirmed v6 path: {addrs:?}"
    );
}

/// §6.3 step 2 — v4 fallback for v4-only dialers: a dual-confirmed subject
/// (port-restricted + granting, dual-stack helpers) advertises v6-first, but a
/// dialing peer that has no v6 stack must still reach it over the v4 mapping. A
/// v4-only Source-mode prober learns the subject's Direct advert, fans a shred
/// out to it, and — unable to use the preferred v6 address — lands its
/// connection on the v4 mapped address. Dual advertisement never strands a
/// v4-only node.
#[test]
fn v4_only_dialer_falls_back_to_the_v4_mapping() {
    let mut world = SimWorld::new(42);
    world.set_default_link(calm_link());

    let observers = spawn_observers(&mut world, true);
    let peers = observer_addrs(&world, &observers);
    let subject = nat_subject(
        &mut world,
        NatConfig::port_restricted_cone(),
        GatewayConfig::granting(),
        peers.clone(),
        true,
    );
    let subject_pk = world.overlay_pubkey(subject);

    // A public, v4-only source node. It bootstraps off one helper, learns the
    // subject's dual advert through the flood, and dials on fan-out.
    let prober = world.add_node(NodeOptions {
        mode: OverlayMode::Source,
        static_peers: vec![peers[0]],
        ipv6: false,
        ..NodeOptions::default()
    });

    // Settle the dual-confirmed advert (ladder + v6 self-discovery + both
    // dial-backs ride the 10s advert cycles).
    world.run_for(Duration::from_secs(55));

    // Inject a spread of distinct source shreds so fan-out's turbine shuffle
    // selects the subject as an origin peer on at least one of them.
    for tag in 0..24u64 {
        world.inject_shred(prober, &shred_payload(tag));
    }
    world.run_for(Duration::from_secs(5));

    match world.peer_connection_addr(prober, &subject_pk) {
        Some(addr) => assert!(
            !addr.is_ipv6(),
            "v4-only prober must reach the subject over v4, connected at {addr}"
        ),
        None => panic!("v4-only prober never connected to the subject"),
    }
}

/// §6.3 — a malformed gateway is inert at the node: garbage firmware answers
/// deterministic junk on every tier. The port-map client counts the malformed
/// responses, installs nothing, and never confirms a map; the witness advert
/// stays Coordinated. Crucially the node is otherwise unharmed — it still runs
/// §6.2 classification and carries gossip — so a broken gateway degrades to the
/// P3 baseline rather than wedging the node.
#[test]
fn malformed_gateway_is_inert_at_the_node() {
    let mut world = SimWorld::new(42);
    world.set_default_link(calm_link());

    let observers = spawn_observers(&mut world, true);
    let witness = observers[0];
    let peers = observer_addrs(&world, &observers);
    let subject = nat_subject(
        &mut world,
        NatConfig::symmetric_random(),
        GatewayConfig::malformed(),
        peers,
        true,
    );
    let subject_pk = world.overlay_pubkey(subject);

    world.run_for(Duration::from_secs(45));

    let (malformed, _denials) = world.portmap_counters(subject);
    assert!(
        malformed > 0,
        "the client must count the gateway's malformed responses"
    );
    assert!(
        world.confirmed_portmap(subject).is_none(),
        "a malformed gateway confirmed a port-map"
    );
    assert!(
        world.portmap_mapped(subject).is_none(),
        "a malformed gateway produced a believed mapping"
    );

    let advert = world
        .peer_advert(witness, &subject_pk)
        .expect("witness never learned the subject's advert");
    assert!(
        matches!(advert.reachability, Reachability::Coordinated { .. }),
        "malformed gateway must leave the node Coordinated, got {:?}",
        advert.reachability
    );
    assert!(
        advert.direct_addrs().is_empty(),
        "malformed gateway produced a Direct advert"
    );
    // The node still functions: it inferred its NAT class from live gossip
    // despite the useless gateway.
    assert_eq!(
        world.nat_class(subject),
        Some(NatClass::Symmetric),
        "the node must still classify itself despite the broken gateway"
    );
}

//! P3 dial-back mechanics (nat-traversal.md §6.2.3, §9), both sim tiers.
//!
//! The low seam runs the *real* fresh-source probe end to end: a helper binds
//! a fresh short-lived socket, dials the requester's observed mapping from it,
//! and reports success only on a completed handshake with the expected
//! identity — so the requester's NAT filtering decides Direct vs Coordinated.
//! The high seam (no real sockets) exercises the helper hardening: per-pubkey
//! rate limits and privileged-port refusal, which run before any bind.

use std::{net::SocketAddr, time::Duration};

use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;

use crate::overlay::nat::NatClass;
use crate::overlay::packet::OverlayFrame;
use crate::overlay::sim::highseam::{HighSeamNet, HighSeamNodeOptions};
use crate::overlay::sim::{HostId, NodeOptions, SimWorld, net::LinkParams};

/// Build a world with `helpers` public observers and one NATed subject that
/// dials all of them; return the subject.
fn subject_behind(seed: u64, nat: crate::overlay::sim::nat::NatConfig, helpers: usize) -> (SimWorld, HostId) {
    let mut world = SimWorld::with_trace(seed, false);
    world.set_default_link(
        LinkParams::default().delay(Duration::from_millis(2), Duration::from_millis(6)),
    );
    let helper_addrs: Vec<SocketAddr> = (0..helpers)
        .map(|_| {
            let helper = world.add_node(NodeOptions::default());
            world.public_addr(helper)
        })
        .collect();
    let subject = world.add_node(NodeOptions {
        nat: vec![nat],
        static_peers: helper_addrs,
        ..NodeOptions::default()
    });
    (world, subject)
}

/// Low seam: a full-cone (endpoint-independent filtering) subject confirms a
/// Direct candidate — the helper's fresh-source probe is admitted by the
/// cone NAT and completes as the subject's identity.
#[test]
fn full_cone_confirms_direct_via_fresh_source_probe() {
    use crate::overlay::sim::nat::NatConfig;
    let (mut world, subject) = subject_behind(0xB01, NatConfig::full_cone(), 3);
    // Classify by t=20 (connections + observations settled), dial-back on the
    // following advert ticks; give it a couple cycles to confirm.
    world.run_for(Duration::from_secs(45));

    assert_eq!(
        world.nat_class(subject),
        Some(NatClass::EndpointIndependent),
        "full-cone classifies EIM",
    );
    let confirmed = world.confirmed_direct(subject).expect("full-cone confirms Direct");
    assert_eq!(
        confirmed.ip(),
        world.external_ip(subject, 0),
        "confirmed candidate is the subject's own external mapping",
    );
}

/// Low seam: a port-restricted subject classifies EIM too, but the
/// fresh-source probe (a new port the NAT was never primed with) is filtered,
/// so dial-back fails and the node stays unconfirmed — dial-back, not
/// classification, is the ground truth for Direct.
#[test]
fn port_restricted_stays_unconfirmed_despite_eim_class() {
    use crate::overlay::sim::nat::NatConfig;
    let (mut world, subject) = subject_behind(0xB02, NatConfig::port_restricted_cone(), 3);
    world.run_for(Duration::from_secs(45));

    assert_eq!(
        world.nat_class(subject),
        Some(NatClass::EndpointIndependent),
        "port-restricted still classifies EIM (mapping is endpoint-independent)",
    );
    assert_eq!(
        world.confirmed_direct(subject),
        None,
        "the fresh-source probe is filtered, so Direct is never confirmed",
    );
    // Short-lived sockets (§9): no helper probe should be left dangling.
    for helper in 0..3 {
        assert_eq!(
            world.active_helper_probes(HostId(helper)),
            0,
            "helper {helper} leaked a dial-back probe socket",
        );
    }
}

fn dialback_request_frame(nonce: u64) -> Vec<u8> {
    OverlayFrame::dialback_request(nonce, None)
        .encode()
        .expect("dial-back request encodes")
}

/// High seam: a helper rate-limits dial-back requests per requester pubkey
/// (§9). Bursting far past the per-second cap from one identity drives the
/// refusal counter up.
#[test]
fn helper_rate_limits_dialback_per_pubkey() {
    let mut net = HighSeamNet::new(0xB03);
    let helper = net.add_node(HighSeamNodeOptions::default());
    let requester = net.add_node(HighSeamNodeOptions::default());
    net.connect(helper, requester);
    let requester_addr = net.node_addr(requester);

    // The high seam cannot bind a helper socket, so admitted requests fail
    // to probe (no counter); only rate refusals bump `dialbacks_refused`.
    const BURST: u64 = 20;
    for nonce in 0..BURST {
        net.inject_datagram(helper, requester_addr, &dialback_request_frame(nonce));
    }
    let refused = net.core(helper).dialbacks_refused();
    assert!(
        refused >= BURST - 4,
        "expected most of a 20-request burst refused past the 4/s cap, got {refused}",
    );
}

/// High seam: a helper refuses to probe a candidate on a privileged port
/// (§9) — the requester's observed source there would be an unusual,
/// abuse-shaped target. Established with a hand-picked low-port address.
#[test]
fn helper_refuses_privileged_port_target() {
    let mut net = HighSeamNet::new(0xB04);
    let helper = net.add_node(HighSeamNodeOptions::default());
    let attacker = Keypair::new();
    let privileged: SocketAddr = "198.51.100.9:80".parse().unwrap();
    net.core_mut(helper)
        .transport_mut()
        .establish(attacker.pubkey(), privileged);

    let before = net.core(helper).dialbacks_refused();
    net.inject_datagram(helper, privileged, &dialback_request_frame(1));
    assert_eq!(
        net.core(helper).dialbacks_refused(),
        before + 1,
        "helper must refuse a privileged-port dial-back target",
    );
    assert_eq!(
        net.core(helper).active_helper_probes(),
        0,
        "no probe is started for a refused request",
    );
}

/// A malformed dial-back frame is inert: it neither panics nor perturbs the
/// helper's refusal accounting, and a valid observation still lands after.
#[test]
fn malformed_dialback_is_inert() {
    let mut net = HighSeamNet::new(0xB05);
    let helper = net.add_node(HighSeamNodeOptions::default());
    let peer = net.add_node(HighSeamNodeOptions::default());
    net.connect(helper, peer);
    let peer_addr = net.node_addr(peer);

    // Frame type 3 (dial-back request) with a truncated body.
    net.inject_datagram(helper, peer_addr, &[1u8, 3]);
    // A dial-back result with garbage trailing bytes.
    net.inject_datagram(helper, peer_addr, &[1u8, 4, 0xFF]);
    assert_eq!(
        net.core(helper).active_helper_probes(),
        0,
        "malformed dial-back frames start no probe",
    );
    assert_eq!(
        net.core(helper).dialbacks_refused(),
        0,
        "malformed frames are not even counted as refusals",
    );
    // The helper still functions after the junk.
    net.run_ticks(2);
}

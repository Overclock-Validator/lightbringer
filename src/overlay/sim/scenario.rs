//! Canned simulation scenarios shared by the `overlay-sim` binary and the
//! deliverable test suite. Every scenario is a pure function of
//! `(seed, verbose)`; the returned trace hash is the reproducibility
//! witness (nat-traversal.md §6.9).

use std::{collections::BTreeSet, time::Duration};

use super::{
    NodeOptions, SimWorld, crypto,
    nat::{NatClass, NatConfig, TaggedObservation, classify_observations},
    net::LinkParams,
};
use crate::overlay::OverlayMode;

pub const SCENARIOS: &[&str] = &[
    "two-node-lossy",
    "two-node-nat-sink",
    "keepalive-nat",
    "keepalive-nat-control",
    "nat-classify",
];

#[derive(Debug)]
pub struct ScenarioOutcome {
    pub name: &'static str,
    pub seed: u64,
    pub trace_hash: String,
    pub events: u64,
    pub ok: bool,
    pub summary: String,
}

pub fn run(name: &str, seed: u64, verbose: bool) -> Option<ScenarioOutcome> {
    match name {
        "two-node-lossy" => Some(two_node_lossy(seed, verbose)),
        "two-node-nat-sink" => Some(two_node_nat_sink(seed, verbose)),
        "keepalive-nat" => Some(keepalive_nat(seed, verbose, true)),
        "keepalive-nat-control" => Some(keepalive_nat(seed, verbose, false)),
        "nat-classify" => Some(nat_classify(seed, verbose)),
        _ => None,
    }
}

fn shred_hashes(shreds: &[Vec<u8>]) -> BTreeSet<u64> {
    shreds.iter().map(|shred| super::hash_bytes(shred)).collect()
}

struct ExchangeResult {
    world: SimWorld,
    sink_got: usize,
    sink_want: usize,
    source_got: usize,
    source_want: usize,
    sink_converged: bool,
    source_converged: bool,
}

fn two_node_exchange(seed: u64, verbose: bool, sink_nat: Vec<NatConfig>) -> ExchangeResult {
    let mut world = SimWorld::with_trace(seed, verbose);
    let source = world.add_node(NodeOptions {
        mode: OverlayMode::Source,
        ..NodeOptions::default()
    });
    let source_addr = world.public_addr(source);
    let sink = world.add_node(NodeOptions {
        mode: OverlayMode::Source,
        nat: sink_nat,
        static_peers: vec![source_addr],
        ..NodeOptions::default()
    });
    world.set_default_link(
        LinkParams::default()
            .delay(Duration::from_millis(20), Duration::from_millis(80))
            .drop_probability(0.05)
            .duplicate_probability(0.02),
    );

    // The sink's first advert (t=10s) dials the source node.
    world.run_for(Duration::from_secs(15));

    let from_source = crypto::make_signed_shreds(seed, 42, 0);
    let from_sink = crypto::make_signed_shreds(seed, 43, 0);
    for _round in 0..5 {
        for shred in &from_source {
            world.inject_shred(source, shred);
        }
        for shred in &from_sink {
            world.inject_shred(sink, shred);
        }
        world.run_for(Duration::from_millis(500));
    }
    world.run_for(Duration::from_secs(10));

    let want_at_sink = shred_hashes(&from_source);
    let want_at_source = shred_hashes(&from_sink);
    let got_at_sink = shred_hashes(world.delivered_shreds(sink));
    let got_at_source = shred_hashes(world.delivered_shreds(source));
    ExchangeResult {
        sink_got: want_at_sink.intersection(&got_at_sink).count(),
        sink_want: want_at_sink.len(),
        source_got: want_at_source.intersection(&got_at_source).count(),
        source_want: want_at_source.len(),
        sink_converged: want_at_sink.is_subset(&got_at_sink),
        source_converged: want_at_source.is_subset(&got_at_source),
        world,
    }
}

fn exchange_summary(result: &ExchangeResult) -> String {
    format!(
        "sink got {}/{} shreds, source got {}/{}",
        result.sink_got, result.sink_want, result.source_got, result.source_want,
    )
}

/// Deliverable (b): two public nodes exchange real signed shreds across a
/// lossy/delayed/duplicating link and both converge on the full sets.
/// Injections repeat several rounds so link-level datagram loss (QUIC
/// datagrams are unreliable by design) is covered by redundancy, the same
/// role FEC plays on the real flood path.
pub fn two_node_lossy(seed: u64, verbose: bool) -> ScenarioOutcome {
    let result = two_node_exchange(seed, verbose, Vec::new());
    ScenarioOutcome {
        name: "two-node-lossy",
        seed,
        trace_hash: result.world.trace_hash(),
        events: result.world.trace.events(),
        ok: result.sink_converged && result.source_converged,
        summary: exchange_summary(&result),
    }
}

/// Guards the P1 fixes for F1–F4 (nat-traversal.md §2.2, §6.1, §6.7):
/// under the pre-P1 address-keyed protocol, the NATed sink flooded its
/// useless LAN bind address and the source's gossip grew a dead entry that
/// deterministically ate every shred whose turbine shuffle rooted there.
/// With identity-keyed gossip, `Coordinated` reachability, and the
/// send_to_peer choke point, the NATed sink is a first-class participant
/// over its single outbound connection (§5): both sides must now converge
/// fully, exactly like the public-public exchange.
pub fn two_node_nat_sink(seed: u64, verbose: bool) -> ScenarioOutcome {
    let result = two_node_exchange(seed, verbose, vec![NatConfig::port_restricted_cone()]);
    ScenarioOutcome {
        name: "two-node-nat-sink",
        seed,
        trace_hash: result.world.trace_hash(),
        events: result.world.trace.events(),
        ok: result.sink_converged && result.source_converged,
        summary: exchange_summary(&result),
    }
}

/// Deliverable (d): a NATed transport-only host holds a QUIC connection
/// across a long idle period through a NAT that expires idle mappings in
/// 60s. With the production 10s keepalive the mapping survives and the
/// public side can still reach the NATed side afterwards; with keepalives
/// disabled (`keepalive = false`) the mapping expires and the post-idle
/// datagram dies at the NAT.
pub fn keepalive_nat(seed: u64, verbose: bool, keepalive: bool) -> ScenarioOutcome {
    let name: &'static str = if keepalive {
        "keepalive-nat"
    } else {
        "keepalive-nat-control"
    };
    let tuning = |nat: Vec<NatConfig>| NodeOptions {
        nat,
        keep_alive_interval: keepalive.then(|| Duration::from_secs(10)),
        // The control must not tear the connection down for idleness —
        // only the NAT mapping may die.
        max_idle_timeout: keepalive.then(|| Duration::from_secs(30)),
        ..NodeOptions::default()
    };

    let mut world = SimWorld::with_trace(seed, verbose);
    let public = world.add_transport_node(tuning(Vec::new()));
    let public_addr = world.public_addr(public);
    let natted = world.add_transport_node(tuning(vec![
        NatConfig::port_restricted_cone().idle_timeout(Duration::from_secs(60)),
    ]));

    world.transport_send(natted, public_addr, b"hello-from-behind-nat".to_vec());
    world.run_for(Duration::from_secs(5));
    let Some(&(mapping, _)) = world.transport_received(public).first() else {
        return ScenarioOutcome {
            name,
            seed,
            trace_hash: world.trace_hash(),
            events: world.trace.events(),
            ok: false,
            summary: "handshake/datagram never reached the public node".into(),
        };
    };

    // Idle: no application traffic for 5 minutes of virtual time; only
    // QUIC keepalives (when enabled) cross the NAT.
    world.run_for(Duration::from_secs(300));

    world.transport_send(public, mapping, b"after-idle".to_vec());
    world.run_for(Duration::from_secs(5));

    let delivered_after_idle = world
        .transport_received(natted)
        .iter()
        .any(|(_, payload)| payload == b"after-idle");
    let nat_stats = world.nat_stats(natted)[0];
    let ok = if keepalive {
        delivered_after_idle
    } else {
        !delivered_after_idle && (nat_stats.expired_drops > 0 || nat_stats.no_mapping_drops > 0)
    };

    ScenarioOutcome {
        name,
        seed,
        trace_hash: world.trace_hash(),
        events: world.trace.events(),
        ok,
        summary: format!(
            "delivered_after_idle={delivered_after_idle} expired_drops={} no_mapping_drops={}",
            nat_stats.expired_drops, nat_stats.no_mapping_drops,
        ),
    }
}

pub const CLASSIFY_CASES: &[(&str, Option<fn() -> NatConfig>, NatClass)] = &[
    ("public", None, NatClass::Public),
    (
        "full-cone",
        Some(NatConfig::full_cone),
        NatClass::EndpointIndependent,
    ),
    (
        "port-restricted-cone",
        Some(NatConfig::port_restricted_cone),
        NatClass::EndpointIndependent,
    ),
    (
        "field-note-fiber",
        Some(NatConfig::field_note_fiber),
        NatClass::PortDependent,
    ),
    (
        "symmetric-sequential",
        Some(|| NatConfig::symmetric_sequential(1)),
        NatClass::Symmetric,
    ),
    (
        "symmetric-random",
        Some(NatConfig::symmetric_random),
        NatClass::Symmetric,
    ),
    // Port-preserving symmetric NATs present the internal port everywhere
    // and are indistinguishable from EIM until a collision (§6.5.1 rung 2).
    (
        "symmetric-preserving",
        Some(NatConfig::symmetric_preserving),
        NatClass::EndpointIndependent,
    ),
];

/// Deliverable (c): each NAT preset, probed through §6.2's port-tagged
/// observation procedure, classifies as the taxonomy predicts — including
/// the field-note NAT, which fixed-port observers would misclassify as EIM.
pub fn nat_classify(seed: u64, verbose: bool) -> ScenarioOutcome {
    let mut world = SimWorld::with_trace(seed, verbose);
    let mut failures = Vec::new();

    for (case_name, preset, expected) in CLASSIFY_CASES {
        let got = classify_one(&mut world, preset.map(|make| make()));
        if got != Some(*expected) {
            failures.push(format!("{case_name}: got {got:?}, want {expected:?}"));
        }
    }

    ScenarioOutcome {
        name: "nat-classify",
        seed,
        trace_hash: world.trace_hash(),
        events: world.trace.events(),
        ok: failures.is_empty(),
        summary: if failures.is_empty() {
            format!("{} presets classified as predicted", CLASSIFY_CASES.len())
        } else {
            failures.join("; ")
        },
    }
}

/// Run the §6.2 observation procedure for one client: probe helpers that
/// share an inbound port from three distinct IPs (the within-group check)
/// plus helpers on two other ports (the across-group check), then classify
/// the port-tagged observations.
pub fn classify_one(world: &mut SimWorld, nat: Option<NatConfig>) -> Option<NatClass> {
    const SHARED_PORT: u16 = 3478;
    const OTHER_PORTS: [u16; 2] = [5321, 7443];

    let client = world.add_probe(nat.into_iter().collect());
    let client_socket = world.probe_bind(client, 51_000);
    let client_addr = world.local_addr(client);

    let mut helpers = Vec::new();
    for _ in 0..3 {
        let helper = world.add_probe(Vec::new());
        world.probe_bind(helper, SHARED_PORT);
        helpers.push(helper);
    }
    for port in OTHER_PORTS {
        let helper = world.add_probe(Vec::new());
        world.probe_bind(helper, port);
        helpers.push(helper);
    }

    for &helper in &helpers {
        let to = world.local_addr(helper);
        world.probe_send(client, client_socket, to, b"observe-me".to_vec());
    }
    world.run_for(Duration::from_secs(1));

    let observations: Vec<TaggedObservation> = helpers
        .iter()
        .flat_map(|&helper| {
            let observer = world.local_addr(helper);
            world
                .probe_received(helper)
                .iter()
                .map(move |datagram| TaggedObservation {
                    observer,
                    mapping: datagram.src,
                })
                .collect::<Vec<_>>()
        })
        .collect();

    classify_observations(client_addr, &observations)
}

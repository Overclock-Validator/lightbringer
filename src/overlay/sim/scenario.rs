//! Canned simulation scenarios shared by the `overlay-sim` binary and the
//! deliverable test suite. Every scenario is a pure function of
//! `(seed, verbose)`; the returned trace hash is the reproducibility
//! witness (nat-traversal.md §6.9).

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use rand::{SeedableRng, rngs::StdRng};

use super::{
    HostId, NodeOptions, SimRepairEvent, SimWorld, crypto,
    nat::{NatClass, NatConfig, TaggedObservation, classify_observations},
    net::LinkParams,
};
use crate::overlay::{
    OverlayMode,
    repair::{PeerSample, RepairReq, overlay_repair_targets},
};

pub const SCENARIOS: &[&str] = &[
    "two-node-lossy",
    "two-node-nat-sink",
    "keepalive-nat",
    "keepalive-nat-control",
    "nat-classify",
    "repair-nat-matrix",
    "repair-liveness",
    "repair-performance",
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
        "repair-nat-matrix" => Some(repair_nat_matrix(seed, verbose)),
        "repair-liveness" => Some(repair_liveness(seed, verbose)),
        "repair-performance" => Some(repair_performance(seed, verbose)),
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

/// Deterministic ~1203-byte synthetic shred payload for the repair
/// scenarios. Repair moves opaque store bytes; signature checking happens
/// later in the packet filter, so signed shreds add nothing here.
fn synth_shred(seed: u64, slot: u64, index: u32) -> Vec<u8> {
    let stamp = crypto::derive_bytes(seed, index, "repair-shred");
    let mut payload = Vec::with_capacity(1203);
    payload.extend_from_slice(&slot.to_le_bytes());
    while payload.len() < 1203 {
        payload.extend_from_slice(&stamp);
    }
    payload.truncate(1203);
    payload
}

/// The §6.2 NAT rows a requester is exercised behind in `repair-nat-matrix`.
pub const REPAIR_NAT_ROWS: &[&str] = &[
    "public",
    "full-cone",
    "restricted-cone",
    "port-restricted-cone",
    "field-note-fiber",
    "symmetric-sequential",
    "symmetric-preserving",
    "symmetric-random",
    "cgnat-double",
];

fn repair_nat_row(name: &str) -> Vec<NatConfig> {
    match name {
        "public" => Vec::new(),
        "full-cone" => vec![NatConfig::full_cone()],
        "restricted-cone" => vec![NatConfig::restricted_cone()],
        "port-restricted-cone" => vec![NatConfig::port_restricted_cone()],
        "field-note-fiber" => vec![NatConfig::field_note_fiber()],
        "symmetric-sequential" => vec![NatConfig::symmetric_sequential(1)],
        "symmetric-preserving" => vec![NatConfig::symmetric_preserving()],
        "symmetric-random" => vec![NatConfig::symmetric_random()],
        // The worst home situation: an EIM router behind a random-allocating
        // carrier-grade NAT.
        "cgnat-double" => vec![
            NatConfig::port_restricted_cone(),
            NatConfig::cgn_random(4096),
        ],
        other => panic!("unknown repair NAT row {other}"),
    }
}

/// Which of `streams` concluded with the expected shred bytes, per stream.
fn verify_repairs(
    events: &[SimRepairEvent],
    streams: &BTreeMap<u64, u32>,
    seed: u64,
    slot: u64,
) -> Vec<u32> {
    let mut repaired = Vec::new();
    for event in events {
        if let SimRepairEvent::Response { stream, shred: Some(bytes), .. } = event
            && let Some(&index) = streams.get(stream)
            && *bytes == synth_shred(seed, slot, index)
        {
            repaired.push(index);
        }
    }
    repaired
}

/// Deliverable (a) — the R2 matrix (nat-traversal.md §6.2, §6.4, §10 P2):
/// a requester behind EVERY NAT preset repairs its gaps from a public
/// peer's store over real QUIC streams, and — the R2 completion criterion —
/// a server behind symmetric NAT + CGNAT serves repair to the peer it is
/// connected to. No punching, no relays: connectivity alone suffices (§5).
pub fn repair_nat_matrix(seed: u64, verbose: bool) -> ScenarioOutcome {
    const SLOT: u64 = 42;
    const SHREDS_PER_ROW: u32 = 4;

    let mut world = SimWorld::with_trace(seed, verbose);
    world.set_default_link(
        LinkParams::default().delay(Duration::from_millis(10), Duration::from_millis(40)),
    );
    let server = world.add_node(NodeOptions::default());
    let server_addr = world.public_addr(server);
    let server_pk = world.overlay_pubkey(server);
    for index in 0..SHREDS_PER_ROW {
        world.store_insert(server, SLOT, index, synth_shred(seed, SLOT, index));
    }

    let requesters: Vec<(&str, HostId)> = REPAIR_NAT_ROWS
        .iter()
        .map(|&name| {
            let host = world.add_node(NodeOptions {
                nat: repair_nat_row(name),
                static_peers: vec![server_addr],
                ..NodeOptions::default()
            });
            (name, host)
        })
        .collect();

    // Reverse direction: the hardest home situation SERVES. The NATed node
    // dials out; the public peer repairs from it over that connection.
    let reverse_requester = world.add_node(NodeOptions::default());
    let reverse_requester_addr = world.public_addr(reverse_requester);
    let natted_server = world.add_node(NodeOptions {
        nat: vec![NatConfig::symmetric_random(), NatConfig::cgn_random(4096)],
        static_peers: vec![reverse_requester_addr],
        ..NodeOptions::default()
    });
    let natted_server_pk = world.overlay_pubkey(natted_server);
    for index in 0..SHREDS_PER_ROW {
        world.store_insert(natted_server, SLOT, index, synth_shred(seed, SLOT, index));
    }

    // Static-peer dials happen at the first advert (t=10s).
    world.run_for(Duration::from_secs(15));

    let mut failures = Vec::new();
    let mut forward: Vec<(&str, HostId, BTreeMap<u64, u32>)> = Vec::new();
    for &(name, host) in &requesters {
        let mut streams = BTreeMap::new();
        for index in 0..SHREDS_PER_ROW {
            match world.request_repair(
                host,
                server_pk,
                RepairReq::WindowIndex { slot: SLOT, shred_index: index },
            ) {
                Some(stream) => {
                    streams.insert(stream, index);
                }
                None => failures.push(format!("{name}: no connection for shred {index}")),
            }
        }
        forward.push((name, host, streams));
    }
    let mut reverse_streams = BTreeMap::new();
    for index in 0..SHREDS_PER_ROW {
        match world.request_repair(
            reverse_requester,
            natted_server_pk,
            RepairReq::WindowIndex { slot: SLOT, shred_index: index },
        ) {
            Some(stream) => {
                reverse_streams.insert(stream, index);
            }
            None => failures.push(format!("reverse: no connection for shred {index}")),
        }
    }

    world.run_for(Duration::from_secs(5));

    for (name, host, streams) in &forward {
        let repaired = verify_repairs(world.repair_events(*host), streams, seed, SLOT);
        if repaired.len() != SHREDS_PER_ROW as usize {
            failures.push(format!(
                "{name}: repaired {}/{SHREDS_PER_ROW}",
                repaired.len()
            ));
        }
    }
    let reverse_repaired =
        verify_repairs(world.repair_events(reverse_requester), &reverse_streams, seed, SLOT);
    if reverse_repaired.len() != SHREDS_PER_ROW as usize {
        failures.push(format!(
            "symmetric+CGNAT server served {}/{SHREDS_PER_ROW}",
            reverse_repaired.len()
        ));
    }

    ScenarioOutcome {
        name: "repair-nat-matrix",
        seed,
        trace_hash: world.trace_hash(),
        events: world.trace.events(),
        ok: failures.is_empty(),
        summary: if failures.is_empty() {
            format!(
                "{} requester rows + symmetric/CGNAT server all repaired {SHREDS_PER_ROW} shreds",
                REPAIR_NAT_ROWS.len()
            )
        } else {
            failures.join("; ")
        },
    }
}

/// Deliverable (b) — the §6.9 repair liveness oracle under loss, delay, and
/// churn (§10 P2 definition of done): a symmetric-NATed sink with gaps
/// keeps sampling its connected peers (real `overlay_repair_targets` +
/// latency-weighted `PeerSample` selection) through a partition and a peer
/// restart, and every gap repairs within the virtual-time budget — some
/// connected peer holds the data at all times. Half the gaps are only
/// discovered after the churn window, so completion always proves repair
/// works BOTH before and after the partition + restart, on every seed.
pub fn repair_liveness(seed: u64, verbose: bool) -> ScenarioOutcome {
    const SLOT: u64 = 7;
    const GAPS: u32 = 8;
    const BUDGET: Duration = Duration::from_secs(90);

    let mut world = SimWorld::with_trace(seed, verbose);
    let faulty_link = LinkParams::default()
        .delay(Duration::from_millis(20), Duration::from_millis(80))
        .drop_probability(0.05);
    world.set_default_link(faulty_link);

    let holder_a = world.add_node(NodeOptions::default());
    let holder_b = world.add_node(NodeOptions::default());
    let a_addr = world.public_addr(holder_a);
    let b_addr = world.public_addr(holder_b);
    let sink = world.add_node(NodeOptions {
        nat: vec![NatConfig::symmetric_random()],
        static_peers: vec![a_addr, b_addr],
        ..NodeOptions::default()
    });
    for index in 0..GAPS {
        let shred = synth_shred(seed, SLOT, index);
        world.store_insert(holder_a, SLOT, index, shred.clone());
        world.store_insert(holder_b, SLOT, index, shred);
    }

    world.run_for(Duration::from_secs(15));

    // The second half of the gaps is only "discovered" after the churn
    // window opens, so late repairs must ride the post-churn recovery
    // (holder A healed, holder B re-dialed after its restart).
    let mut missing: BTreeSet<u32> = (0..GAPS / 2).collect();
    let mut undiscovered: BTreeSet<u32> = (GAPS / 2..GAPS).collect();
    let mut in_flight: BTreeMap<u64, (u32, u64)> = BTreeMap::new();
    let mut sample = PeerSample::new();
    let mut rng = StdRng::seed_from_u64(seed ^ 0x9e37_79b9_7f4a_7c15);
    let mut cursor = 0usize;
    let (mut partitioned, mut restarted, mut healed) = (false, false, false);

    let deadline = world.now_nanos() + BUDGET.as_nanos() as u64;
    while world.now_nanos() < deadline && !(missing.is_empty() && undiscovered.is_empty()) {
        world.run_for(Duration::from_millis(500));
        let now = world.now_nanos();

        // Churn schedule: partition the sink from one holder, restart the
        // other while the partition holds, then heal.
        if !partitioned && now >= 20_000_000_000 {
            world.set_link_bidir(sink, holder_a, faulty_link.partitioned());
            partitioned = true;
        }
        if !restarted && now >= 30_000_000_000 {
            world.restart_overlay_node(holder_b);
            restarted = true;
        }
        if now >= 32_000_000_000 {
            missing.append(&mut undiscovered);
        }
        if !healed && now >= 40_000_000_000 {
            world.set_link_bidir(sink, holder_a, faulty_link);
            healed = true;
        }

        let events = world.repair_events(sink).to_vec();
        while cursor < events.len() {
            match &events[cursor] {
                SimRepairEvent::Response { at_nanos, stream, peer, shred } => {
                    if let Some((index, issued)) = in_flight.remove(stream) {
                        let latency_ms = at_nanos.saturating_sub(issued) as f64 / 1e6;
                        sample.record_response(*peer, latency_ms);
                        if shred.as_deref() == Some(synth_shred(seed, SLOT, index).as_slice()) {
                            missing.remove(&index);
                        }
                    }
                }
                SimRepairEvent::Failed { stream, peer, .. } => {
                    if in_flight.remove(stream).is_some() {
                        sample.record_timeout(*peer);
                    }
                }
            }
            cursor += 1;
        }

        let targets = overlay_repair_targets(&world.repair_peer_view(sink));
        if targets.is_empty() {
            continue;
        }
        for target in &targets {
            sample.observe(target.pubkey());
        }
        let outstanding: BTreeSet<u32> = in_flight.values().map(|&(index, _)| index).collect();
        for index in missing.clone() {
            if outstanding.contains(&index) {
                continue;
            }
            let Some(target) = sample.select_weighted(&targets, &mut rng) else {
                break;
            };
            if let Some(stream) = world.request_repair(
                sink,
                target.pubkey(),
                RepairReq::WindowIndex { slot: SLOT, shred_index: index },
            ) {
                sample.record_request(target.pubkey());
                in_flight.insert(stream, (index, world.now_nanos()));
            }
        }
    }

    let repaired = GAPS - missing.len() as u32;
    let elapsed_s = world.now_nanos() as f64 / 1e9;
    ScenarioOutcome {
        name: "repair-liveness",
        seed,
        trace_hash: world.trace_hash(),
        events: world.trace.events(),
        ok: missing.is_empty(),
        summary: format!(
            "repaired {repaired}/{GAPS} gaps by t={elapsed_s:.1}s virtual (partition + restart survived)"
        ),
    }
}

/// Deliverable (c) — the §6.9 performance tier, protocol-level under
/// virtual time: repair latency distribution and control-plane bytes per
/// repaired shred across a lossy, delayed link. The bounds are sanity
/// rails, not benchmarks — QUIC stream retransmission must keep loss as
/// latency (never failure) and the byte cost must stay in the
/// few-KB-per-shred class.
pub fn repair_performance(seed: u64, verbose: bool) -> ScenarioOutcome {
    const SLOT: u64 = 11;
    const COUNT: u32 = 64;
    const MAX_IN_FLIGHT: usize = 8;
    const BUDGET: Duration = Duration::from_secs(120);
    const P50_BOUND_MS: u64 = 800;
    const P95_BOUND_MS: u64 = 3_000;
    const BYTES_PER_SHRED_BOUND: u64 = 30_000;

    let mut world = SimWorld::with_trace(seed, verbose);
    world.set_default_link(
        LinkParams::default()
            .delay(Duration::from_millis(20), Duration::from_millis(60))
            .drop_probability(0.10),
    );
    let server = world.add_node(NodeOptions::default());
    let server_addr = world.public_addr(server);
    let server_pk = world.overlay_pubkey(server);
    for index in 0..COUNT {
        world.store_insert(server, SLOT, index, synth_shred(seed, SLOT, index));
    }
    let requester = world.add_node(NodeOptions {
        static_peers: vec![server_addr],
        ..NodeOptions::default()
    });

    world.run_for(Duration::from_secs(15));
    let bytes_before = world.host_sent(server).1 + world.host_sent(requester).1;

    let mut missing: BTreeSet<u32> = (0..COUNT).collect();
    let mut in_flight: BTreeMap<u64, (u32, u64)> = BTreeMap::new();
    let mut latencies_ms: Vec<u64> = Vec::new();
    let mut cursor = 0usize;
    let deadline = world.now_nanos() + BUDGET.as_nanos() as u64;

    while world.now_nanos() < deadline && !missing.is_empty() {
        world.run_for(Duration::from_millis(100));

        let events = world.repair_events(requester).to_vec();
        while cursor < events.len() {
            match &events[cursor] {
                SimRepairEvent::Response { at_nanos, stream, shred, .. } => {
                    if let Some((index, issued)) = in_flight.remove(stream)
                        && shred.as_deref() == Some(synth_shred(seed, SLOT, index).as_slice())
                    {
                        latencies_ms.push(at_nanos.saturating_sub(issued) / 1_000_000);
                        missing.remove(&index);
                    }
                }
                SimRepairEvent::Failed { stream, .. } => {
                    in_flight.remove(stream);
                }
            }
            cursor += 1;
        }

        let outstanding: BTreeSet<u32> = in_flight.values().map(|&(index, _)| index).collect();
        for index in missing.clone() {
            if in_flight.len() >= MAX_IN_FLIGHT {
                break;
            }
            if outstanding.contains(&index) {
                continue;
            }
            if let Some(stream) = world.request_repair(
                requester,
                server_pk,
                RepairReq::WindowIndex { slot: SLOT, shred_index: index },
            ) {
                in_flight.insert(stream, (index, world.now_nanos()));
            }
        }
    }

    let bytes_after = world.host_sent(server).1 + world.host_sent(requester).1;
    let repaired = COUNT - missing.len() as u32;
    let bytes_per_shred = (bytes_after - bytes_before) / u64::from(COUNT.max(1));
    latencies_ms.sort_unstable();
    let percentile = |p: usize| -> u64 {
        if latencies_ms.is_empty() {
            return u64::MAX;
        }
        latencies_ms[(latencies_ms.len() * p / 100).min(latencies_ms.len() - 1)]
    };
    let (p50, p95) = (percentile(50), percentile(95));
    let max = latencies_ms.last().copied().unwrap_or(u64::MAX);

    let ok = missing.is_empty()
        && p50 <= P50_BOUND_MS
        && p95 <= P95_BOUND_MS
        && bytes_per_shred <= BYTES_PER_SHRED_BOUND;
    ScenarioOutcome {
        name: "repair-performance",
        seed,
        trace_hash: world.trace_hash(),
        events: world.trace.events(),
        ok,
        summary: format!(
            "repaired {repaired}/{COUNT}; latency ms p50={p50} p95={p95} max={max}; control-plane bytes/shred={bytes_per_shred}"
        ),
    }
}

//! Deterministic discrete-event simulator for the overlay
//! (nat-traversal.md §6.9, TigerBeetle-style): a single-threaded event loop
//! drives real `OverlayCore` + quinn-proto state machines under virtual
//! time, with seeded randomness everywhere, a per-link fault model
//! ([`net::LinkParams`]) and composable NAT boxes ([`nat::NatBox`]) on the
//! wire. One `(seed, scenario)` pair reproduces one execution; the trace
//! hash ([`trace::Trace`]) is the equality witness.
#![allow(dead_code)]

pub mod crypto;
pub mod nat;
pub mod net;
pub mod scenario;
pub mod trace;

#[cfg(test)]
mod tests;

use std::{
    cmp::Reverse,
    collections::{BTreeMap, BinaryHeap, VecDeque},
    hash::{Hash as _, Hasher},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};
use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};

use crate::types::{PacketInfo, PacketView};

use super::{
    config::{OverlayConfig, OverlayMode},
    env::{OverlayEnv, SocketId},
    identity::OverlayIdentity,
    service::{CoreEvent, OverlayCore},
    transport::{OverlayQuicTransport, OverlayTransport, TransportEvent, TransportOptions},
};

use nat::{NatBox, NatConfig, NatStats};
use net::LinkParams;
use trace::{Trace, TraceEvent};

const MAX_HOSTS: usize = 200;
const MAX_DELIVERED_SHREDS: usize = 65_536;
const MAX_PROBE_RECEIVED: usize = 8_192;
const EPHEMERAL_PORT_START: u16 = 49_152;
/// Timers never fire at or before the current instant; this keeps virtual
/// time strictly advancing even for already-due deadlines.
const TIMER_MIN_ADVANCE_NANOS: u64 = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HostId(pub u32);

#[derive(Clone, Debug)]
pub struct NodeOptions {
    pub mode: OverlayMode,
    pub static_peers: Vec<SocketAddr>,
    /// NAT chain, innermost first; empty = publicly routable host.
    pub nat: Vec<NatConfig>,
    pub bind_port: u16,
    pub fanout: usize,
    pub peer_ttl: Duration,
    pub shred_version: u16,
    /// `None` disables keepalives (the NAT-timeout control case).
    pub keep_alive_interval: Option<Duration>,
    pub max_idle_timeout: Option<Duration>,
    pub initial_mtu: Option<u16>,
}

impl Default for NodeOptions {
    fn default() -> Self {
        Self {
            mode: OverlayMode::Sink,
            static_peers: Vec::new(),
            nat: Vec::new(),
            bind_port: 65_410,
            fanout: 8,
            peer_ttl: Duration::from_secs(30),
            shred_version: 0,
            keep_alive_interval: Some(Duration::from_secs(10)),
            max_idle_timeout: Some(Duration::from_secs(30)),
            initial_mtu: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProbeDatagram {
    pub at_nanos: u64,
    pub socket: SocketId,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload: Vec<u8>,
}

struct HostEnvState {
    lan_ip: IpAddr,
    sockets: Vec<SocketAddr>,
    outbox: VecDeque<(SocketId, SocketAddr, Vec<u8>)>,
    rng: StdRng,
    next_ephemeral: u16,
}

impl HostEnvState {
    fn bind(&mut self, port: Option<u16>) -> Result<SocketId> {
        let port = match port {
            Some(port) => port,
            None => {
                let port = self.next_ephemeral;
                self.next_ephemeral = self.next_ephemeral.checked_add(1).unwrap_or(EPHEMERAL_PORT_START);
                port
            }
        };
        let addr = SocketAddr::new(self.lan_ip, port);
        if self.sockets.contains(&addr) {
            return Err(anyhow!("sim socket {addr} already bound"));
        }
        let id = SocketId(u32::try_from(self.sockets.len())?);
        self.sockets.push(addr);
        Ok(id)
    }
}

/// Per-call view implementing the low seam: virtual clock, seeded RNG, and
/// sends collected into the host outbox for the world to route.
struct SimEnv<'a> {
    now: Instant,
    state: &'a mut HostEnvState,
}

impl OverlayEnv for SimEnv<'_> {
    fn now(&self) -> Instant {
        self.now
    }

    fn rng(&mut self) -> &mut dyn RngCore {
        &mut self.state.rng
    }

    fn send(&mut self, from: SocketId, to: SocketAddr, datagram: &[u8]) {
        self.state.outbox.push_back((from, to, datagram.to_vec()));
    }

    fn bind(&mut self, port: Option<u16>) -> Result<SocketId> {
        self.state.bind(port)
    }
}

struct OverlayNode {
    core: OverlayCore<OverlayQuicTransport>,
    keypair: Keypair,
    pubkey: Pubkey,
    config: OverlayConfig,
    options: NodeOptions,
    delivered: Vec<Vec<u8>>,
}

struct ProbeNode {
    received: Vec<ProbeDatagram>,
}

/// A host driving `OverlayQuicTransport` directly, without an
/// `OverlayCore` on top: real QUIC connections but no gossip/advert
/// traffic, so scenarios can create genuinely idle connections (the NAT
/// keepalive tests need this — core-level nodes advert every 10s, which
/// itself refreshes NAT mappings).
struct TransportNode {
    transport: OverlayQuicTransport,
    keypair: Keypair,
    pubkey: Pubkey,
    received: Vec<(SocketAddr, Vec<u8>)>,
}

enum HostKind {
    Overlay(Box<OverlayNode>),
    Transport(Box<TransportNode>),
    Probe(ProbeNode),
}

struct Host {
    up: bool,
    nat_chain: Vec<NatBox>,
    env: HostEnvState,
    kind: HostKind,
    timer_generation: u64,
    next_timer: Option<u64>,
}

enum EventKind {
    Delivery {
        to_host: u32,
        src: SocketAddr,
        dst: SocketAddr,
        payload: Vec<u8>,
    },
    Timer {
        host: u32,
        generation: u64,
    },
}

struct QueuedEvent {
    at: u64,
    seq: u64,
    kind: EventKind,
}

impl PartialEq for QueuedEvent {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at && self.seq == other.seq
    }
}

impl Eq for QueuedEvent {}

impl PartialOrd for QueuedEvent {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QueuedEvent {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.at.cmp(&other.at).then(self.seq.cmp(&other.seq))
    }
}

pub struct SimWorld {
    seed: u64,
    base: Instant,
    now_nanos: u64,
    seq: u64,
    events: BinaryHeap<Reverse<QueuedEvent>>,
    hosts: Vec<Host>,
    default_link: LinkParams,
    links: BTreeMap<(u32, u32), LinkParams>,
    /// Latest scheduled delivery per directed host pair; FIFO links clamp
    /// new deliveries to arrive no earlier (bounded by the host count).
    link_horizon: BTreeMap<(u32, u32), u64>,
    ip_owner: BTreeMap<IpAddr, u32>,
    rng: StdRng,
    pub trace: Trace,
}

impl SimWorld {
    pub fn new(seed: u64) -> Self {
        Self::with_trace(seed, false)
    }

    pub fn with_trace(seed: u64, verbose: bool) -> Self {
        Self {
            seed,
            base: Instant::now(),
            now_nanos: 0,
            seq: 0,
            events: BinaryHeap::new(),
            hosts: Vec::new(),
            default_link: LinkParams::default(),
            links: BTreeMap::new(),
            link_horizon: BTreeMap::new(),
            ip_owner: BTreeMap::new(),
            rng: StdRng::seed_from_u64(seed),
            trace: Trace::new(verbose),
        }
    }

    pub fn seed(&self) -> u64 {
        self.seed
    }

    pub fn now_nanos(&self) -> u64 {
        self.now_nanos
    }

    fn virtual_now(&self) -> Instant {
        self.base + Duration::from_nanos(self.now_nanos)
    }

    fn host_ips(&mut self, id: u32, nat: &[NatConfig]) -> (IpAddr, Vec<IpAddr>) {
        assert!((id as usize) < MAX_HOSTS, "sim host limit is {MAX_HOSTS}");
        let octet = (id + 1) as u8;
        if nat.is_empty() {
            let ip = IpAddr::from([203, 0, 113, octet]);
            self.ip_owner.insert(ip, id);
            (ip, Vec::new())
        } else {
            let lan_ip = IpAddr::from([10, id as u8, 0, 2]);
            let externals: Vec<IpAddr> = (0..nat.len())
                .map(|level| IpAddr::from([198, 51, level as u8, octet]))
                .collect();
            // Only the outermost external address is publicly routable.
            self.ip_owner
                .insert(*externals.last().expect("nat chain non-empty"), id);
            (lan_ip, externals)
        }
    }

    fn transport_options(seed: u64, id: u32, options: &NodeOptions) -> TransportOptions {
        TransportOptions {
            keep_alive_interval: options.keep_alive_interval,
            max_idle_timeout: options.max_idle_timeout,
            initial_mtu: options.initial_mtu,
            rng_seed: Some(crypto::derive_bytes(seed, id, "quinn-rng")),
            cid_seed: Some(crypto::derive_u64(seed, id, "cid")),
            reset_key: Some(Arc::new(crypto::SeededResetKey::new(seed, id))),
            crypto_provider: Some(crypto::seeded_provider(seed, id)),
        }
    }

    fn env_state(&self, id: u32, lan_ip: IpAddr, sockets: Vec<SocketAddr>) -> HostEnvState {
        HostEnvState {
            lan_ip,
            sockets,
            outbox: VecDeque::new(),
            rng: StdRng::from_seed(crypto::derive_bytes(self.seed, id, "env-rng")),
            next_ephemeral: EPHEMERAL_PORT_START,
        }
    }

    fn nat_chain(&self, id: u32, nat: &[NatConfig], externals: &[IpAddr]) -> Vec<NatBox> {
        nat.iter()
            .zip(externals)
            .enumerate()
            .map(|(level, (config, &external_ip))| {
                NatBox::new(
                    config.clone(),
                    external_ip,
                    crypto::derive_u64(self.seed, id, &format!("nat-{level}")),
                )
            })
            .collect()
    }

    pub fn add_node(&mut self, options: NodeOptions) -> HostId {
        let id = self.hosts.len() as u32;
        let (host_ip, externals) = self.host_ips(id, &options.nat);
        let bind_addr = SocketAddr::new(host_ip, options.bind_port);
        let repair_port = if options.bind_port < u16::MAX {
            options.bind_port + 1
        } else {
            options.bind_port - 1
        };

        let config = OverlayConfig {
            enabled: true,
            mode: options.mode,
            bind_addr,
            advertised_addr: None,
            static_peers: options.static_peers.clone(),
            fanout: options.fanout,
            repair_addr: Some(SocketAddr::new(host_ip, repair_port)),
            shred_version: Some(options.shred_version),
            peer_ttl_ms: options.peer_ttl.as_millis() as u64,
        };

        let keypair = crypto::derive_keypair(self.seed, id);
        let identity =
            OverlayIdentity::from_keypair(&keypair).expect("sim identity always derivable");
        let transport_options = Self::transport_options(self.seed, id, &options);
        let transport =
            OverlayQuicTransport::new(SocketId::PRIMARY, &identity, &transport_options)
                .expect("sim transport construction is infallible");
        let core = OverlayCore::new(transport, &config, self.virtual_now());

        let host = Host {
            up: true,
            nat_chain: self.nat_chain(id, &options.nat, &externals),
            env: self.env_state(id, host_ip, vec![bind_addr]),
            kind: HostKind::Overlay(Box::new(OverlayNode {
                core,
                pubkey: keypair.pubkey(),
                keypair,
                config,
                options,
                delivered: Vec::new(),
            })),
            timer_generation: 0,
            next_timer: None,
        };
        self.hosts.push(host);
        self.reschedule_timer(id);
        HostId(id)
    }

    /// A host running only the QUIC transport (no core): dial with
    /// [`Self::transport_send`], read with [`Self::transport_received`].
    pub fn add_transport_node(&mut self, options: NodeOptions) -> HostId {
        let id = self.hosts.len() as u32;
        let (host_ip, externals) = self.host_ips(id, &options.nat);
        let bind_addr = SocketAddr::new(host_ip, options.bind_port);

        let keypair = crypto::derive_keypair(self.seed, id);
        let identity =
            OverlayIdentity::from_keypair(&keypair).expect("sim identity always derivable");
        let transport_options = Self::transport_options(self.seed, id, &options);
        let transport =
            OverlayQuicTransport::new(SocketId::PRIMARY, &identity, &transport_options)
                .expect("sim transport construction is infallible");

        let host = Host {
            up: true,
            nat_chain: self.nat_chain(id, &options.nat, &externals),
            env: self.env_state(id, host_ip, vec![bind_addr]),
            kind: HostKind::Transport(Box::new(TransportNode {
                transport,
                pubkey: keypair.pubkey(),
                keypair,
                received: Vec::new(),
            })),
            timer_generation: 0,
            next_timer: None,
        };
        self.hosts.push(host);
        self.reschedule_timer(id);
        HostId(id)
    }

    /// Queue an application datagram on a bare-transport host (dials `to`
    /// on first use).
    pub fn transport_send(&mut self, host: HostId, to: SocketAddr, payload: Vec<u8>) {
        self.with_host(host.0, |kind, env| {
            let HostKind::Transport(node) = kind else {
                panic!("host is not a transport node");
            };
            if let Err(e) = node.transport.queue_datagram(env, to, payload) {
                log::warn!("sim: transport_send failed: {e}");
            }
        });
        self.post_process(host.0);
    }

    pub fn transport_received(&self, host: HostId) -> &[(SocketAddr, Vec<u8>)] {
        match &self.hosts[host.0 as usize].kind {
            HostKind::Transport(node) => &node.received,
            _ => &[],
        }
    }

    /// quinn per-connection stats of a bare-transport host (diagnostics).
    pub fn transport_stats(&self, host: HostId) -> Vec<(SocketAddr, quinn_proto::ConnectionStats)> {
        match &self.hosts[host.0 as usize].kind {
            HostKind::Transport(node) => node.transport.connection_stats(),
            _ => Vec::new(),
        }
    }

    /// App-side queued datagrams of a bare-transport host (diagnostics).
    pub fn transport_pending(&self, host: HostId) -> usize {
        match &self.hosts[host.0 as usize].kind {
            HostKind::Transport(node) => node.transport.pending_datagrams(),
            _ => 0,
        }
    }

    /// A scriptable bare host (no overlay core): sends raw datagrams and
    /// records everything it receives. Public probes act as observation
    /// helpers; NATed probes are classification subjects (§6.2 tests).
    pub fn add_probe(&mut self, nat: Vec<NatConfig>) -> HostId {
        let id = self.hosts.len() as u32;
        let (host_ip, externals) = self.host_ips(id, &nat);
        let host = Host {
            up: true,
            nat_chain: self.nat_chain(id, &nat, &externals),
            env: self.env_state(id, host_ip, Vec::new()),
            kind: HostKind::Probe(ProbeNode {
                received: Vec::new(),
            }),
            timer_generation: 0,
            next_timer: None,
        };
        self.hosts.push(host);
        HostId(id)
    }

    pub fn probe_bind(&mut self, host: HostId, port: u16) -> SocketId {
        self.hosts[host.0 as usize]
            .env
            .bind(Some(port))
            .expect("probe bind")
    }

    pub fn probe_send(&mut self, host: HostId, socket: SocketId, to: SocketAddr, payload: Vec<u8>) {
        let from = self.hosts[host.0 as usize].env.sockets[socket.0 as usize];
        self.route(host.0, from, to, payload);
    }

    pub fn probe_received(&self, host: HostId) -> &[ProbeDatagram] {
        match &self.hosts[host.0 as usize].kind {
            HostKind::Probe(probe) => &probe.received,
            _ => &[],
        }
    }

    /// The dialable address of a public host. Panics for NATed hosts —
    /// they have no stable public name (that is the point of the design).
    pub fn public_addr(&self, host: HostId) -> SocketAddr {
        let entry = &self.hosts[host.0 as usize];
        assert!(
            entry.nat_chain.is_empty(),
            "host {host:?} is NATed and has no dialable public address"
        );
        entry.env.sockets[0]
    }

    pub fn local_addr(&self, host: HostId) -> SocketAddr {
        self.hosts[host.0 as usize].env.sockets[0]
    }

    pub fn overlay_pubkey(&self, host: HostId) -> Pubkey {
        match &self.hosts[host.0 as usize].kind {
            HostKind::Overlay(node) => node.pubkey,
            HostKind::Transport(node) => node.pubkey,
            HostKind::Probe(_) => panic!("host {host:?} is a probe"),
        }
    }

    pub fn delivered_shreds(&self, host: HostId) -> &[Vec<u8>] {
        match &self.hosts[host.0 as usize].kind {
            HostKind::Overlay(node) => &node.delivered,
            _ => &[],
        }
    }

    pub fn nat_stats(&self, host: HostId) -> Vec<NatStats> {
        self.hosts[host.0 as usize]
            .nat_chain
            .iter()
            .map(|nat| nat.stats)
            .collect()
    }

    pub fn external_ip(&self, host: HostId, level: usize) -> IpAddr {
        self.hosts[host.0 as usize].nat_chain[level].external_ip
    }

    pub fn set_default_link(&mut self, params: LinkParams) {
        self.default_link = params;
    }

    pub fn set_link(&mut self, from: HostId, to: HostId, params: LinkParams) {
        self.links.insert((from.0, to.0), params);
    }

    pub fn set_link_bidir(&mut self, a: HostId, b: HostId, params: LinkParams) {
        self.set_link(a, b, params);
        self.set_link(b, a, params);
    }

    pub fn set_host_up(&mut self, host: HostId, up: bool) {
        let now = self.now_nanos;
        {
            let entry = &mut self.hosts[host.0 as usize];
            if entry.up == up {
                return;
            }
            entry.up = up;
            if !up {
                entry.next_timer = None;
                entry.timer_generation += 1;
            }
        }
        let event = if up {
            TraceEvent::HostUp { host: host.0 }
        } else {
            TraceEvent::HostDown { host: host.0 }
        };
        self.trace.record(now, &event);
        if up {
            self.reschedule_timer(host.0);
        }
    }

    /// Churn without persisted overlay state: rebuild the node's core (same
    /// identity and config, fresh connections and gossip).
    pub fn restart_overlay_node(&mut self, host: HostId) {
        let now = self.virtual_now();
        let seed = self.seed;
        {
            let entry = &mut self.hosts[host.0 as usize];
            let HostKind::Overlay(node) = &mut entry.kind else {
                return;
            };
            let transport_options = Self::transport_options(seed, host.0, &node.options);
            let identity = OverlayIdentity::from_keypair(&node.keypair)
                .expect("sim identity always derivable");
            let transport =
                OverlayQuicTransport::new(SocketId::PRIMARY, &identity, &transport_options)
                    .expect("sim transport construction is infallible");
            node.core = OverlayCore::new(transport, &node.config, now);
            node.delivered.clear();
            entry.up = true;
        }
        self.reschedule_timer(host.0);
    }

    /// Feed a shred into a source-mode node, as the packet filter would.
    pub fn inject_shred(&mut self, host: HostId, payload: &[u8]) {
        let Ok(view) = PacketView::try_from(payload) else {
            panic!("sim shred payload exceeds PACKET_DATA_SIZE");
        };
        let packet = PacketInfo::new(view);
        self.with_overlay_node(host.0, |node, env| node.core.on_source_packet(env, packet));
        self.post_process(host.0);
    }

    pub fn run_for(&mut self, duration: Duration) {
        let target = self.now_nanos + duration.as_nanos() as u64;
        loop {
            let due = matches!(self.events.peek(), Some(Reverse(event)) if event.at <= target);
            if !due {
                break;
            }
            let Reverse(event) = self.events.pop().expect("peeked event exists");
            self.now_nanos = event.at.max(self.now_nanos);
            self.dispatch(event.kind);
        }
        self.now_nanos = target;
    }

    pub fn trace_hash(&self) -> String {
        self.trace.hash_hex()
    }

    fn push_event(&mut self, at: u64, kind: EventKind) {
        self.seq += 1;
        self.events.push(Reverse(QueuedEvent {
            at,
            seq: self.seq,
            kind,
        }));
    }

    fn with_host(&mut self, host: u32, f: impl FnOnce(&mut HostKind, &mut dyn OverlayEnv)) {
        let now = self.virtual_now();
        let entry = &mut self.hosts[host as usize];
        let mut env = SimEnv {
            now,
            state: &mut entry.env,
        };
        f(&mut entry.kind, &mut env);
    }

    fn with_overlay_node(
        &mut self,
        host: u32,
        f: impl FnOnce(&mut OverlayNode, &mut dyn OverlayEnv),
    ) {
        self.with_host(host, |kind, env| {
            if let HostKind::Overlay(node) = kind {
                f(node, env);
            }
        });
    }

    /// Drain a host's effects after any core call: sends route into the
    /// world, core events feed the trace, and the host timer is rescheduled.
    fn post_process(&mut self, host: u32) {
        let now = self.now_nanos;
        let mut outbox = Vec::new();
        {
            let Self { hosts, trace, .. } = self;
            let entry = &mut hosts[host as usize];
            while let Some((socket, to, bytes)) = entry.env.outbox.pop_front() {
                let Some(&from) = entry.env.sockets.get(socket.0 as usize) else {
                    continue;
                };
                outbox.push((from, to, bytes));
            }
            match &mut entry.kind {
                HostKind::Overlay(node) => {
                    while let Some(event) = node.core.poll_event() {
                        match event {
                            CoreEvent::ShredForFilter(packet) => {
                                trace.record(
                                    now,
                                    &TraceEvent::ShredDelivered {
                                        host,
                                        payload_hash: hash_bytes(packet.as_slice()),
                                    },
                                );
                                if node.delivered.len() < MAX_DELIVERED_SHREDS {
                                    node.delivered.push(packet.as_slice().to_vec());
                                }
                            }
                            CoreEvent::PeerConnected { peer, pubkey } => {
                                trace
                                    .record(now, &TraceEvent::PeerConnected { host, peer, pubkey });
                            }
                            CoreEvent::PeerDisconnected { peer, .. } => {
                                trace.record(now, &TraceEvent::PeerDisconnected { host, peer });
                            }
                        }
                    }
                }
                HostKind::Transport(node) => {
                    while let Some(event) = node.transport.poll_event() {
                        match event {
                            TransportEvent::Connected { peer, pubkey } => {
                                trace
                                    .record(now, &TraceEvent::PeerConnected { host, peer, pubkey });
                            }
                            TransportEvent::Disconnected { peer, .. } => {
                                trace.record(now, &TraceEvent::PeerDisconnected { host, peer });
                            }
                        }
                    }
                    while let Some((from, payload)) = node.transport.poll_inbound() {
                        trace.record(
                            now,
                            &TraceEvent::AppDatagram {
                                host,
                                from,
                                payload_hash: hash_bytes(&payload),
                            },
                        );
                        if node.received.len() < MAX_DELIVERED_SHREDS {
                            node.received.push((from, payload));
                        }
                    }
                }
                HostKind::Probe(_) => {}
            }
        }
        for (from, to, bytes) in outbox {
            self.route(host, from, to, bytes);
        }
        self.reschedule_timer(host);
    }

    /// Carry a datagram from a host socket toward `to`: outbound NAT
    /// traversal at send time, then link faults, then a delayed delivery
    /// event (inbound NAT filtering happens at delivery time, so mappings
    /// can expire mid-flight).
    fn route(&mut self, sender: u32, from: SocketAddr, to: SocketAddr, payload: Vec<u8>) {
        let now = self.now_nanos;
        let mut src = from;
        {
            let Self { hosts, trace, .. } = self;
            let entry = &mut hosts[sender as usize];
            for (level, nat) in entry.nat_chain.iter_mut().enumerate() {
                match nat.outbound(now, src, to) {
                    Ok(pass) => {
                        if pass.created {
                            trace.record(
                                now,
                                &TraceEvent::NatMapped {
                                    host: sender,
                                    level: level as u8,
                                    internal: src,
                                    external: pass.external,
                                },
                            );
                        }
                        src = pass.external;
                    }
                    Err(reason) => {
                        trace.record(
                            now,
                            &TraceEvent::NatDropped {
                                host: sender,
                                level: level as u8,
                                reason: reason.as_str(),
                            },
                        );
                        return;
                    }
                }
            }
        }

        let Some(&owner) = self.ip_owner.get(&to.ip()) else {
            self.trace
                .record(now, &TraceEvent::NoRoute { from: sender, to });
            return;
        };
        let params = self
            .links
            .get(&(sender, owner))
            .copied()
            .unwrap_or(self.default_link);
        if !params.up {
            self.trace.record(
                now,
                &TraceEvent::LinkDown {
                    from: sender,
                    to: owner,
                },
            );
            return;
        }
        if let Some(mtu) = params.mtu
            && payload.len() > mtu
        {
            self.trace.record(
                now,
                &TraceEvent::MtuDropped {
                    from: sender,
                    to: owner,
                    len: payload.len(),
                    mtu,
                },
            );
            return;
        }

        self.trace.record(
            now,
            &TraceEvent::HostSend {
                host: sender,
                from: src,
                to,
                len: payload.len(),
            },
        );
        if self.rng.random_bool(params.drop_probability) {
            self.trace.record(
                now,
                &TraceEvent::LinkDropped {
                    from: sender,
                    to: owner,
                    len: payload.len(),
                },
            );
            return;
        }
        let mut copies = 1;
        if params.duplicate_probability > 0.0 && self.rng.random_bool(params.duplicate_probability)
        {
            copies = 2;
            self.trace.record(
                now,
                &TraceEvent::LinkDuplicated {
                    from: sender,
                    to: owner,
                },
            );
        }
        for _ in 0..copies {
            let delay_min = params.delay_min.as_nanos() as u64;
            let delay_max = params.delay_max.as_nanos() as u64;
            let delay = if delay_max > delay_min {
                self.rng.random_range(delay_min..=delay_max)
            } else {
                delay_min
            };
            let mut at = now + delay;
            let reordered = params.reorder_probability > 0.0
                && self.rng.random_bool(params.reorder_probability);
            if !reordered {
                let horizon = self.link_horizon.entry((sender, owner)).or_insert(0);
                at = at.max(*horizon);
                *horizon = at;
            }
            self.push_event(
                at,
                EventKind::Delivery {
                    to_host: owner,
                    src,
                    dst: to,
                    payload: payload.clone(),
                },
            );
        }
    }

    fn dispatch(&mut self, kind: EventKind) {
        match kind {
            EventKind::Timer { host, generation } => {
                {
                    let entry = &mut self.hosts[host as usize];
                    if !entry.up || entry.timer_generation != generation {
                        return;
                    }
                    entry.next_timer = None;
                }
                self.with_host(host, |kind, env| match kind {
                    HostKind::Overlay(node) => node.core.on_timer(env),
                    HostKind::Transport(node) => node.transport.on_timer(env),
                    HostKind::Probe(_) => {}
                });
                self.post_process(host);
            }
            EventKind::Delivery {
                to_host,
                src,
                dst,
                payload,
            } => self.deliver(to_host, src, dst, payload),
        }
    }

    fn deliver(&mut self, to_host: u32, src: SocketAddr, dst: SocketAddr, payload: Vec<u8>) {
        let now = self.now_nanos;
        let delivery = {
            let Self { hosts, trace, .. } = self;
            let entry = &mut hosts[to_host as usize];
            if !entry.up {
                return;
            }
            let mut dst = dst;
            let mut admitted = true;
            for (level, nat) in entry.nat_chain.iter_mut().enumerate().rev() {
                if dst.ip() != nat.external_ip {
                    continue;
                }
                match nat.inbound(now, src, dst) {
                    Ok(internal) => dst = internal,
                    Err(reason) => {
                        trace.record(
                            now,
                            &TraceEvent::NatDropped {
                                host: to_host,
                                level: level as u8,
                                reason: reason.as_str(),
                            },
                        );
                        admitted = false;
                        break;
                    }
                }
            }
            if !admitted {
                None
            } else {
                match entry.env.sockets.iter().position(|&socket| socket == dst) {
                    Some(index) => Some((SocketId(index as u32), dst)),
                    None => {
                        trace.record(now, &TraceEvent::NoSocket { host: to_host, dst });
                        None
                    }
                }
            }
        };

        let Some((socket, final_dst)) = delivery else {
            return;
        };
        self.trace.record(
            now,
            &TraceEvent::Delivered {
                host: to_host,
                src,
                dst: final_dst,
                len: payload.len(),
            },
        );

        let is_probe = {
            let entry = &mut self.hosts[to_host as usize];
            if let HostKind::Probe(probe) = &mut entry.kind {
                if probe.received.len() < MAX_PROBE_RECEIVED {
                    probe.received.push(ProbeDatagram {
                        at_nanos: now,
                        socket,
                        src,
                        dst: final_dst,
                        payload: payload.clone(),
                    });
                }
                true
            } else {
                false
            }
        };
        if !is_probe {
            self.with_host(to_host, |kind, env| match kind {
                HostKind::Overlay(node) => node.core.on_datagram(env, socket, src, &payload),
                HostKind::Transport(node) => {
                    node.transport.on_datagram(env, socket, src, &payload)
                }
                HostKind::Probe(_) => {}
            });
            self.post_process(to_host);
        }
    }

    fn reschedule_timer(&mut self, host: u32) {
        let now = self.now_nanos;
        let base = self.base;
        let deadline = {
            let entry = &mut self.hosts[host as usize];
            if !entry.up {
                return;
            }
            let deadline = match &mut entry.kind {
                HostKind::Overlay(node) => node.core.poll_timeout(),
                HostKind::Transport(node) => node.transport.poll_timeout(),
                HostKind::Probe(_) => return,
            };
            match deadline {
                Some(deadline) => deadline.saturating_duration_since(base).as_nanos() as u64,
                None => {
                    entry.next_timer = None;
                    return;
                }
            }
        };
        let at = deadline.max(now + TIMER_MIN_ADVANCE_NANOS);
        let entry = &mut self.hosts[host as usize];
        if entry.next_timer == Some(at) {
            return;
        }
        entry.next_timer = Some(at);
        entry.timer_generation += 1;
        let generation = entry.timer_generation;
        self.push_event(at, EventKind::Timer { host, generation });
    }
}

fn hash_bytes(bytes: &[u8]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

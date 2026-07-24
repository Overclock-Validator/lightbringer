//! High-seam simulation tier (nat-traversal.md §6.9): the transport is an
//! in-memory authenticated fake, so hundreds-to-thousands of `OverlayCore`s
//! run gossip/advert/turbine logic cheaply — no QUIC, no TLS, no NAT. This
//! tier validates §6.1/§6.7 protocol logic and is where the P1 safety
//! oracles run; the low seam (`SimWorld`) covers the packet-level truth.
//!
//! Time advances in fixed one-second ticks. Datagrams sent during tick T
//! are delivered at the start of tick T+1 in deterministic order (sender
//! index, then send order); an optional seeded drop probability models
//! lossy links. Dials to a known listening address succeed instantly —
//! dialing *reality* (NATs, punching) is the low seam's job.

use std::{
    collections::{BTreeMap, VecDeque},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
use solana_sdk::{pubkey::Pubkey, signer::Signer};

use crate::overlay::{
    OverlayConfig, OverlayMode,
    env::{IpFamily, OverlayEnv, SocketId, TcpId},
    repair::RepairReq,
    service::{CoreEvent, OverlayCore},
    transport::{OverlayStreamId, OverlayTransport, ProbeEvent, ProbeId, StreamEvent, TransportEvent},
};

use super::{SimRepairEvent, SimShredStore, crypto, lookup_repair};

const TICK: Duration = Duration::from_secs(1);

/// A stream operation the harness carries between `MemTransport`s. Streams
/// mirror QUIC's *contract*: reliable and ordered, so ops are never dropped
/// by the fault model (on real QUIC, link loss shows up as stream latency,
/// never as stream data loss). A stream is globally named by
/// `(initiator, seq)`; `initiator_is_sender` says which side of that pair
/// sent this op.
#[derive(Clone, Debug)]
pub struct MemStreamOp {
    pub initiator_is_sender: bool,
    pub seq: u64,
    pub kind: MemStreamOpKind,
}

#[derive(Clone, Debug)]
pub enum MemStreamOpKind {
    Open,
    Data(Vec<u8>),
    Fin,
    Reset,
}

struct MemStream {
    peer: Pubkey,
    seq: u64,
    /// The remote side opened this stream.
    remote_initiated: bool,
    fin_sent: bool,
    fin_recvd: bool,
}

/// Dial-on-demand payloads buffered until the connection establishes, gated
/// on the identity they were addressed to (§6.2.3 F8, mirrors the QUIC
/// transport's `pending` + `expect_pubkey`).
struct PendingExpect {
    expected: Pubkey,
    payloads: Vec<Vec<u8>>,
}

/// In-memory authenticated transport: connections are (pubkey, addr) pairs
/// established by the harness, datagrams pass through untouched, and the
/// peer identity is simply asserted — the fake models QUIC's *contract*
/// (mutually authenticated, unreliable datagrams + reliable ordered bidi
/// streams), not its mechanics.
pub struct MemTransport {
    established: BTreeMap<Pubkey, SocketAddr>,
    by_addr: BTreeMap<SocketAddr, Pubkey>,
    inbound: VecDeque<(SocketAddr, Vec<u8>)>,
    events: VecDeque<TransportEvent>,
    next_stream: u64,
    streams: BTreeMap<OverlayStreamId, MemStream>,
    /// `(peer, seq, remote_initiated)` → local handle.
    stream_index: BTreeMap<(Pubkey, u64, bool), OverlayStreamId>,
    stream_events: VecDeque<StreamEvent>,
    /// Outbound ops the harness drains and delivers next tick.
    stream_ops: VecDeque<(Pubkey, MemStreamOp)>,
    /// Addresses to dial (from identity-gated dial-on-demand); the harness
    /// turns each into an established connection.
    dial_requests: VecDeque<SocketAddr>,
    /// Dial-on-demand payloads awaiting their connection, keyed by address.
    pending_expect: BTreeMap<SocketAddr, PendingExpect>,
    /// Payloads released on establish (identity matched), drained by the
    /// harness into the wire next tick.
    deferred_out: VecDeque<(SocketAddr, Vec<u8>)>,
}

impl MemTransport {
    pub fn new() -> Self {
        Self {
            established: BTreeMap::new(),
            by_addr: BTreeMap::new(),
            inbound: VecDeque::new(),
            events: VecDeque::new(),
            next_stream: 0,
            streams: BTreeMap::new(),
            stream_index: BTreeMap::new(),
            stream_events: VecDeque::new(),
            stream_ops: VecDeque::new(),
            dial_requests: VecDeque::new(),
            pending_expect: BTreeMap::new(),
            deferred_out: VecDeque::new(),
        }
    }

    /// Harness-side: pull the addresses to dial queued since the last drain.
    pub fn take_dial_requests(&mut self) -> Vec<SocketAddr> {
        std::mem::take(&mut self.dial_requests).into()
    }

    /// Harness-side: pull payloads released on establish (drained to the wire).
    pub fn take_deferred_out(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        std::mem::take(&mut self.deferred_out).into()
    }

    /// Harness-side: a connection to `pubkey`@`addr` is now established.
    pub fn establish(&mut self, pubkey: Pubkey, addr: SocketAddr) {
        if self.by_addr.contains_key(&addr) {
            return;
        }
        self.established.insert(pubkey, addr);
        self.by_addr.insert(addr, pubkey);
        self.events.push_back(TransportEvent::Connected {
            peer: addr,
            pubkey: Some(pubkey),
        });
        // §6.2.3 F8: release dial-on-demand payloads buffered for this
        // address, but only if the identity that answered matches what they
        // were addressed to; a mismatch (a lying advert) drops them.
        if let Some(pending) = self.pending_expect.remove(&addr)
            && pending.expected == pubkey
        {
            for payload in pending.payloads {
                self.deferred_out.push_back((addr, payload));
            }
        }
    }

    /// Harness-side: drop the connection with `pubkey`. Streams die with it.
    pub fn disconnect(&mut self, pubkey: &Pubkey) {
        if let Some(addr) = self.established.remove(pubkey) {
            self.by_addr.remove(&addr);
            self.events.push_back(TransportEvent::Disconnected {
                peer: addr,
                reason: "harness disconnect".to_string(),
            });
            let dead: Vec<OverlayStreamId> = self
                .streams
                .iter()
                .filter(|(_, stream)| stream.peer == *pubkey)
                .map(|(&handle, _)| handle)
                .collect();
            for handle in dead {
                self.drop_stream(handle);
                self.stream_events.push_back(StreamEvent::Failed { stream: handle });
            }
        }
    }

    pub fn is_connected_to(&self, pubkey: &Pubkey) -> bool {
        self.established.contains_key(pubkey)
    }

    /// Harness-side: pull the ops queued since the last drain.
    pub fn take_stream_ops(&mut self) -> Vec<(Pubkey, MemStreamOp)> {
        std::mem::take(&mut self.stream_ops).into()
    }

    /// Harness-side: deliver an op sent by `from`.
    pub fn deliver_stream_op(&mut self, from: Pubkey, op: MemStreamOp) {
        let key = (from, op.seq, op.initiator_is_sender);
        match op.kind {
            MemStreamOpKind::Open => {
                if self.stream_index.contains_key(&key) || !self.established.contains_key(&from) {
                    return;
                }
                let handle = OverlayStreamId(self.next_stream);
                self.next_stream += 1;
                self.stream_index.insert(key, handle);
                self.streams.insert(
                    handle,
                    MemStream {
                        peer: from,
                        seq: op.seq,
                        remote_initiated: true,
                        fin_sent: false,
                        fin_recvd: false,
                    },
                );
                self.stream_events
                    .push_back(StreamEvent::Opened { stream: handle, peer: from });
            }
            MemStreamOpKind::Data(bytes) => {
                if let Some(&handle) = self.stream_index.get(&key) {
                    self.stream_events
                        .push_back(StreamEvent::Data { stream: handle, bytes });
                }
            }
            MemStreamOpKind::Fin => {
                if let Some(&handle) = self.stream_index.get(&key) {
                    if let Some(stream) = self.streams.get_mut(&handle) {
                        stream.fin_recvd = true;
                    }
                    self.stream_events
                        .push_back(StreamEvent::Finished { stream: handle });
                    self.reap_stream(handle);
                }
            }
            MemStreamOpKind::Reset => {
                if let Some(&handle) = self.stream_index.get(&key) {
                    self.drop_stream(handle);
                    self.stream_events
                        .push_back(StreamEvent::Failed { stream: handle });
                }
            }
        }
    }

    fn push_op(&mut self, stream: &MemStream, kind: MemStreamOpKind) {
        self.stream_ops.push_back((
            stream.peer,
            MemStreamOp {
                initiator_is_sender: !stream.remote_initiated,
                seq: stream.seq,
                kind,
            },
        ));
    }

    fn drop_stream(&mut self, handle: OverlayStreamId) {
        if let Some(stream) = self.streams.remove(&handle) {
            self.stream_index
                .remove(&(stream.peer, stream.seq, stream.remote_initiated));
        }
    }

    fn reap_stream(&mut self, handle: OverlayStreamId) {
        let done = self
            .streams
            .get(&handle)
            .is_some_and(|stream| stream.fin_sent && stream.fin_recvd);
        if done {
            self.drop_stream(handle);
        }
    }
}

impl OverlayTransport for MemTransport {
    fn queue_datagram(
        &mut self,
        env: &mut dyn OverlayEnv,
        to: SocketAddr,
        payload: Vec<u8>,
    ) -> Result<()> {
        // Dial-on-demand: the harness establishes the connection (both
        // sides) when it routes a send to a not-yet-connected address.
        env.send(SocketId::PRIMARY, to, &payload);
        Ok(())
    }

    fn on_datagram(
        &mut self,
        _env: &mut dyn OverlayEnv,
        _socket: SocketId,
        from: SocketAddr,
        datagram: &[u8],
    ) {
        self.inbound.push_back((from, datagram.to_vec()));
    }

    fn on_timer(&mut self, _env: &mut dyn OverlayEnv) {}

    fn poll_timeout(&mut self) -> Option<Instant> {
        None
    }

    fn poll_inbound(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        self.inbound.pop_front()
    }

    fn poll_event(&mut self) -> Option<TransportEvent> {
        self.events.pop_front()
    }

    fn peer_identity(&self, peer: SocketAddr) -> Option<Pubkey> {
        self.by_addr.get(&peer).copied()
    }

    fn queue_datagram_to_peer(
        &mut self,
        env: &mut dyn OverlayEnv,
        pubkey: &Pubkey,
        payload: Vec<u8>,
    ) -> bool {
        let Some(&addr) = self.established.get(pubkey) else {
            return false;
        };
        env.send(SocketId::PRIMARY, addr, &payload);
        true
    }

    fn connection_addr(&self, pubkey: &Pubkey) -> Option<SocketAddr> {
        self.established.get(pubkey).copied()
    }

    fn connected_peers(&self) -> Vec<Pubkey> {
        self.established.keys().copied().collect()
    }

    fn connections(&self) -> Vec<(Pubkey, SocketAddr)> {
        self.established
            .iter()
            .map(|(&pubkey, &addr)| (pubkey, addr))
            .collect()
    }

    fn open_stream(&mut self, pubkey: &Pubkey) -> Option<OverlayStreamId> {
        if !self.established.contains_key(pubkey) {
            return None;
        }
        let handle = OverlayStreamId(self.next_stream);
        self.next_stream += 1;
        let stream = MemStream {
            peer: *pubkey,
            seq: handle.0,
            remote_initiated: false,
            fin_sent: false,
            fin_recvd: false,
        };
        self.stream_index
            .insert((*pubkey, handle.0, false), handle);
        self.push_op(&stream, MemStreamOpKind::Open);
        self.streams.insert(handle, stream);
        Some(handle)
    }

    fn write_stream(
        &mut self,
        _env: &mut dyn OverlayEnv,
        stream: OverlayStreamId,
        bytes: &[u8],
    ) -> bool {
        let Some(state) = self.streams.get(&stream) else {
            return false;
        };
        if state.fin_sent {
            return false;
        }
        let (peer, seq, remote_initiated) = (state.peer, state.seq, state.remote_initiated);
        self.stream_ops.push_back((
            peer,
            MemStreamOp {
                initiator_is_sender: !remote_initiated,
                seq,
                kind: MemStreamOpKind::Data(bytes.to_vec()),
            },
        ));
        true
    }

    fn finish_stream(&mut self, _env: &mut dyn OverlayEnv, stream: OverlayStreamId) {
        let Some(state) = self.streams.get_mut(&stream) else {
            return;
        };
        if state.fin_sent {
            return;
        }
        state.fin_sent = true;
        let (peer, seq, remote_initiated) = (state.peer, state.seq, state.remote_initiated);
        self.stream_ops.push_back((
            peer,
            MemStreamOp {
                initiator_is_sender: !remote_initiated,
                seq,
                kind: MemStreamOpKind::Fin,
            },
        ));
        self.reap_stream(stream);
    }

    fn reset_stream(&mut self, _env: &mut dyn OverlayEnv, stream: OverlayStreamId) {
        let Some(state) = self.streams.get(&stream) else {
            return;
        };
        let (peer, seq, remote_initiated) = (state.peer, state.seq, state.remote_initiated);
        self.stream_ops.push_back((
            peer,
            MemStreamOp {
                initiator_is_sender: !remote_initiated,
                seq,
                kind: MemStreamOpKind::Reset,
            },
        ));
        self.drop_stream(stream);
    }

    fn poll_stream_event(&mut self) -> Option<StreamEvent> {
        self.stream_events.pop_front()
    }

    fn queue_datagram_expecting(
        &mut self,
        env: &mut dyn OverlayEnv,
        to: SocketAddr,
        expected: Pubkey,
        payload: Vec<u8>,
    ) -> Result<()> {
        match self.by_addr.get(&to) {
            // Already connected: release only to the addressed identity.
            Some(&pubkey) if pubkey == expected => env.send(SocketId::PRIMARY, to, &payload),
            Some(_) => {}
            // Not connected: buffer and ask the harness to dial. The payload
            // is released on establish iff the identity matches.
            None => {
                self.pending_expect
                    .entry(to)
                    .or_insert_with(|| PendingExpect {
                        expected,
                        payloads: Vec::new(),
                    })
                    .payloads
                    .push(payload);
                self.dial_requests.push_back(to);
            }
        }
        Ok(())
    }

    fn start_probe(
        &mut self,
        _env: &mut dyn OverlayEnv,
        _socket: SocketId,
        _addr: SocketAddr,
    ) -> Result<ProbeId> {
        // The high seam has no real sockets; §6.2.3 dial-back outcomes are
        // harness-injected at the requester (advert-policy state machine).
        Err(anyhow::anyhow!("high-seam transport runs no dial-back probes"))
    }

    fn poll_probe_event(&mut self) -> Option<ProbeEvent> {
        None
    }

    fn close_probe(&mut self, _env: &mut dyn OverlayEnv, _probe: ProbeId) {}

    fn drop_connection(&mut self, _env: &mut dyn OverlayEnv, addr: SocketAddr) {
        let Some(pubkey) = self.by_addr.remove(&addr) else {
            return;
        };
        self.established.remove(&pubkey);
        let dead: Vec<OverlayStreamId> = self
            .streams
            .iter()
            .filter(|(_, stream)| stream.peer == pubkey)
            .map(|(&handle, _)| handle)
            .collect();
        for handle in dead {
            self.drop_stream(handle);
            self.stream_events
                .push_back(StreamEvent::Failed { stream: handle });
        }
    }
}

struct HighSeamEnv {
    now: Instant,
    rng: StdRng,
    outbox: VecDeque<(SocketAddr, Vec<u8>)>,
}

impl OverlayEnv for HighSeamEnv {
    fn now(&self) -> Instant {
        self.now
    }

    fn rng(&mut self) -> &mut dyn RngCore {
        &mut self.rng
    }

    fn send(&mut self, _from: SocketId, to: SocketAddr, datagram: &[u8]) {
        self.outbox.push_back((to, datagram.to_vec()));
    }

    fn bind(&mut self, _port: Option<u16>, _family: IpFamily) -> Result<SocketId> {
        Err(anyhow::anyhow!("high-seam harness has no helper sockets"))
    }

    fn close(&mut self, _socket: SocketId) {}

    fn tcp_connect(&mut self, _to: SocketAddr) -> Result<TcpId> {
        Err(anyhow::anyhow!("high-seam harness has no TCP streams"))
    }

    fn tcp_send(&mut self, _conn: TcpId, _bytes: &[u8]) {}

    fn tcp_close(&mut self, _conn: TcpId) {}
}

#[derive(Clone, Debug)]
pub struct HighSeamNodeOptions {
    pub mode: OverlayMode,
    pub static_peers: Vec<SocketAddr>,
    /// `true` advertises the node's address as `Reachability::Direct`;
    /// `false` models a NATed node (advertises `Coordinated`).
    pub direct: bool,
    pub fanout: usize,
    pub peer_ttl: Duration,
}

impl Default for HighSeamNodeOptions {
    fn default() -> Self {
        Self {
            mode: OverlayMode::Sink,
            static_peers: Vec::new(),
            direct: true,
            fanout: 8,
            peer_ttl: Duration::from_secs(30),
        }
    }
}

struct HighSeamNode {
    core: OverlayCore<MemTransport>,
    env: HighSeamEnv,
    pubkey: Pubkey,
    addr: SocketAddr,
    delivered: Vec<Vec<u8>>,
    store: SimShredStore,
    repair_events: Vec<SimRepairEvent>,
    up: bool,
}

/// Deterministic tick-driven harness over [`MemTransport`] nodes.
pub struct HighSeamNet {
    seed: u64,
    base: Instant,
    ticks: u64,
    nodes: Vec<HighSeamNode>,
    by_addr: BTreeMap<SocketAddr, usize>,
    by_pubkey: BTreeMap<Pubkey, usize>,
    in_flight: VecDeque<(SocketAddr, SocketAddr, Vec<u8>)>,
    /// Stream ops travel one tick like datagrams but are never dropped:
    /// streams model QUIC's reliable contract (loss = latency, not loss).
    in_flight_ops: VecDeque<(usize, Pubkey, MemStreamOp)>,
    /// No-payload §6.2.3 confirm-dials: `(dialer, target address)`. Resolved
    /// next tick to an established connection (with the real identity of the
    /// address's owner), or dropped if the address owns nothing.
    in_flight_dials: VecDeque<(usize, SocketAddr)>,
    drop_probability: f64,
    rng: StdRng,
}

impl HighSeamNet {
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            base: Instant::now(),
            ticks: 0,
            nodes: Vec::new(),
            by_addr: BTreeMap::new(),
            by_pubkey: BTreeMap::new(),
            in_flight: VecDeque::new(),
            in_flight_ops: VecDeque::new(),
            in_flight_dials: VecDeque::new(),
            drop_probability: 0.0,
            rng: StdRng::seed_from_u64(seed),
        }
    }

    pub fn set_drop_probability(&mut self, p: f64) {
        self.drop_probability = p;
    }

    fn now(&self) -> Instant {
        self.base + TICK * self.ticks as u32
    }

    /// Node addresses are `10.83.{i/250}.{i%250+1}:65410`, assigned in
    /// creation order, so tests can pre-compute static peer addresses with
    /// [`Self::addr_for`].
    pub fn addr_for(index: usize) -> SocketAddr {
        let high = (index / 250) as u8;
        let low = (index % 250) as u8 + 1;
        SocketAddr::from(([10, 83, high, low], 65_410))
    }

    pub fn add_node(&mut self, options: HighSeamNodeOptions) -> usize {
        let index = self.nodes.len();
        let addr = Self::addr_for(index);
        let keypair = Arc::new(crypto::derive_keypair(self.seed, index as u32));
        let pubkey = keypair.pubkey();
        let config = OverlayConfig {
            enabled: true,
            mode: options.mode,
            bind_addr: addr,
            bind_addr_v6: None,
            advertised_addr: options.direct.then_some(addr),
            advertised_addr_v6: None,
            gateway_addr: None,
            portmap_local_ip: None,
            static_peers: options.static_peers,
            fanout: options.fanout,
            repair_addr: None,
            shred_version: Some(0),
            peer_ttl_ms: options.peer_ttl.as_millis() as u64,
        };
        let core = OverlayCore::new(MemTransport::new(), &config, keypair, self.now());
        let env = HighSeamEnv {
            now: self.now(),
            rng: StdRng::from_seed(crypto::derive_bytes(self.seed, index as u32, "hs-env")),
            outbox: VecDeque::new(),
        };
        self.nodes.push(HighSeamNode {
            core,
            env,
            pubkey,
            addr,
            delivered: Vec::new(),
            store: SimShredStore::new(),
            repair_events: Vec::new(),
            up: true,
        });
        self.by_addr.insert(addr, index);
        self.by_pubkey.insert(pubkey, index);
        index
    }

    pub fn node_pubkey(&self, index: usize) -> Pubkey {
        self.nodes[index].pubkey
    }

    pub fn node_addr(&self, index: usize) -> SocketAddr {
        self.nodes[index].addr
    }

    pub fn core(&self, index: usize) -> &OverlayCore<MemTransport> {
        &self.nodes[index].core
    }

    pub fn core_mut(&mut self, index: usize) -> &mut OverlayCore<MemTransport> {
        &mut self.nodes[index].core
    }

    pub fn now_instant(&self) -> Instant {
        self.now()
    }

    pub fn delivered_shreds(&self, index: usize) -> &[Vec<u8>] {
        &self.nodes[index].delivered
    }

    /// Seed a node's in-memory shred store (the serve-repair source).
    pub fn store_insert(&mut self, index: usize, slot: u64, shred_index: u32, shred: Vec<u8>) {
        self.nodes[index].store.insert((slot, shred_index), shred);
    }

    /// Open a §6.4 repair stream from node `index` toward `peer`.
    pub fn request_repair(&mut self, index: usize, peer: Pubkey, request: RepairReq) -> Option<u64> {
        let now = self.now();
        let node = &mut self.nodes[index];
        node.env.now = now;
        let stream = node
            .core
            .request_repair(&mut node.env, peer, &request)
            .map(|id| id.0);
        self.drain_node(index);
        stream
    }

    /// Client-side repair outcomes node `index` observed, in order.
    pub fn repair_events(&self, index: usize) -> &[SimRepairEvent] {
        &self.nodes[index].repair_events
    }

    pub fn set_node_up(&mut self, index: usize, up: bool) {
        self.nodes[index].up = up;
    }

    /// Pre-establish a connection pair, as if a dial had completed.
    pub fn connect(&mut self, a: usize, b: usize) {
        let (a_pk, a_addr) = (self.nodes[a].pubkey, self.nodes[a].addr);
        let (b_pk, b_addr) = (self.nodes[b].pubkey, self.nodes[b].addr);
        self.nodes[a].core.transport_mut().establish(b_pk, b_addr);
        self.nodes[b].core.transport_mut().establish(a_pk, a_addr);
    }

    /// Deliver arbitrary bytes into a node as if they arrived from
    /// `from_addr` over an established connection — the adversarial
    /// injection point for forged/replayed frames.
    pub fn inject_datagram(&mut self, to: usize, from_addr: SocketAddr, bytes: &[u8]) {
        let now = self.now();
        let node = &mut self.nodes[to];
        node.env.now = now;
        node.core
            .on_datagram(&mut node.env, SocketId::PRIMARY, from_addr, bytes);
        self.drain_node(to);
    }

    /// Deliver a raw stream op into a node as if sent by `from` — the
    /// adversarial injection point for forged/garbage stream traffic.
    pub fn inject_stream_op(&mut self, to: usize, from: Pubkey, op: MemStreamOp) {
        let now = self.now();
        let node = &mut self.nodes[to];
        node.env.now = now;
        node.core.transport_mut().deliver_stream_op(from, op);
        node.core.on_transport_activity(&mut node.env);
        self.drain_node(to);
    }

    pub fn inject_shred(&mut self, index: usize, payload: &[u8]) {
        let view = crate::types::PacketView::try_from(payload).expect("payload fits a packet");
        let packet = crate::types::PacketInfo::new(view);
        let now = self.now();
        let node = &mut self.nodes[index];
        node.env.now = now;
        node.core.on_source_packet(&mut node.env, packet);
        self.drain_node(index);
    }

    /// One tick: fire every node's timer (adverts run on their own 10s
    /// deadline), then deliver last tick's datagrams.
    pub fn tick(&mut self) {
        self.ticks += 1;
        let now = self.now();
        for index in 0..self.nodes.len() {
            if !self.nodes[index].up {
                continue;
            }
            let node = &mut self.nodes[index];
            node.env.now = now;
            node.core.on_timer(&mut node.env);
            self.drain_node(index);
        }

        let deliveries = std::mem::take(&mut self.in_flight);
        for (from, to, bytes) in deliveries {
            if self.drop_probability > 0.0 && self.rng.random_bool(self.drop_probability) {
                continue;
            }
            let Some(&target) = self.by_addr.get(&to) else {
                continue;
            };
            if !self.nodes[target].up {
                continue;
            }
            // Dial-on-demand: sends to a not-yet-connected address
            // establish the connection pair before delivery.
            let source = self.by_addr.get(&from).copied();
            if let Some(source) = source
                && self.nodes[target]
                    .core
                    .transport()
                    .peer_identity(from)
                    .is_none()
            {
                self.connect(source, target);
            }
            let now = self.now();
            let node = &mut self.nodes[target];
            node.env.now = now;
            node.core
                .on_datagram(&mut node.env, SocketId::PRIMARY, from, &bytes);
            self.drain_node(target);
        }

        // Stream ops travel with the same one-tick latency but are never
        // dropped (QUIC streams are reliable); a down target loses them,
        // which the sender observes as a failed/timed-out stream.
        let ops = std::mem::take(&mut self.in_flight_ops);
        let mut touched = std::collections::BTreeSet::new();
        for (from, to, op) in ops {
            let Some(&target) = self.by_pubkey.get(&to) else {
                continue;
            };
            if !self.nodes[target].up {
                continue;
            }
            let from_pk = self.nodes[from].pubkey;
            self.nodes[target]
                .core
                .transport_mut()
                .deliver_stream_op(from_pk, op);
            touched.insert(target);
        }
        for target in touched {
            let now = self.now();
            let node = &mut self.nodes[target];
            node.env.now = now;
            node.core.on_transport_activity(&mut node.env);
            self.drain_node(target);
        }

        // §6.2.3 confirm-dials: establish the connection pair (with the
        // real identity of whoever owns the address) one tick later, exactly
        // like a completed handshake. A dial to an address no node owns
        // establishes nothing — the requester's confirm deadline expires and
        // it quarantines the advert.
        let dials = std::mem::take(&mut self.in_flight_dials);
        let mut dialed = std::collections::BTreeSet::new();
        for (from, addr) in dials {
            let Some(&target) = self.by_addr.get(&addr) else {
                continue;
            };
            if !self.nodes[target].up || from == target {
                continue;
            }
            if self.nodes[from].core.transport().peer_identity(addr).is_some() {
                continue;
            }
            self.connect(from, target);
            dialed.insert(from);
            dialed.insert(target);
        }
        for node in dialed {
            let now = self.now();
            let entry = &mut self.nodes[node];
            entry.env.now = now;
            // Pump the Connected event so identity-gated dials resolve
            // (confirm/quarantine) and deferred payloads flush.
            entry.core.on_transport_activity(&mut entry.env);
            self.drain_node(node);
        }
    }

    pub fn run_ticks(&mut self, count: u64) {
        for _ in 0..count {
            self.tick();
        }
    }

    /// Drain a node's effects, answering repair requests from its store
    /// (the §6.4 store-lookup seam) until quiescent.
    fn drain_node(&mut self, index: usize) {
        loop {
            let from = self.nodes[index].addr;
            while let Some((to, bytes)) = self.nodes[index].env.outbox.pop_front() {
                self.in_flight.push_back((from, to, bytes));
            }
            for (to, op) in self.nodes[index].core.transport_mut().take_stream_ops() {
                self.in_flight_ops.push_back((index, to, op));
            }
            for addr in self.nodes[index].core.transport_mut().take_dial_requests() {
                self.in_flight_dials.push_back((index, addr));
            }
            for (to, bytes) in self.nodes[index].core.transport_mut().take_deferred_out() {
                self.in_flight.push_back((from, to, bytes));
            }
            let mut lookups = Vec::new();
            let ticks = self.ticks;
            {
                let node = &mut self.nodes[index];
                while let Some(event) = node.core.poll_event() {
                    match event {
                        CoreEvent::ShredForFilter(packet) => {
                            node.delivered.push(packet.as_slice().to_vec());
                        }
                        CoreEvent::RepairRequest { stream, request, .. } => {
                            lookups.push((stream, request));
                        }
                        CoreEvent::RepairResponse { stream, peer, shred } => {
                            node.repair_events.push(SimRepairEvent::Response {
                                at_nanos: ticks,
                                stream: stream.0,
                                peer,
                                shred,
                            });
                        }
                        CoreEvent::RepairFailed { stream, peer } => {
                            node.repair_events.push(SimRepairEvent::Failed {
                                at_nanos: ticks,
                                stream: stream.0,
                                peer,
                            });
                        }
                        CoreEvent::PeerConnected { .. } | CoreEvent::PeerDisconnected { .. } => {}
                    }
                }
            }
            if lookups.is_empty() {
                return;
            }
            let now = self.now();
            for (stream, request) in lookups {
                let node = &mut self.nodes[index];
                node.env.now = now;
                let shred = lookup_repair(&node.store, &request);
                node.core.on_repair_response(&mut node.env, stream, shred);
            }
        }
    }

    /// Deterministic digest of the whole network's observable state:
    /// per-node gossip snapshots (pubkey + seq + reachability shape),
    /// connection sets, and counters. Equal digests ⇒ equal outcomes.
    pub fn state_digest(&self) -> String {
        let now = self.now();
        let mut state = [0u8; 32];
        for node in &self.nodes {
            let mut buf = Vec::new();
            buf.extend_from_slice(node.pubkey.as_ref());
            for advert in node.core.gossip_snapshot(now) {
                buf.extend_from_slice(advert.pubkey.as_ref());
                buf.extend_from_slice(&advert.advert_seq.to_le_bytes());
                buf.push(advert.direct_addrs().len() as u8);
            }
            for pubkey in node.core.transport().connected_peers() {
                buf.extend_from_slice(pubkey.as_ref());
            }
            buf.extend_from_slice(&node.core.dropped_unreachable().to_le_bytes());
            buf.extend_from_slice(&node.core.invalid_adverts().to_le_bytes());
            buf.extend_from_slice(&(node.delivered.len() as u64).to_le_bytes());
            state = solana_sha256_hasher::hashv(&[&state, &buf]).to_bytes();
        }
        let mut out = String::with_capacity(64);
        for byte in state {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

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
    env::{OverlayEnv, SocketId},
    service::{CoreEvent, OverlayCore},
    transport::{OverlayTransport, TransportEvent},
};

use super::crypto;

const TICK: Duration = Duration::from_secs(1);

/// In-memory authenticated transport: connections are (pubkey, addr) pairs
/// established by the harness, datagrams pass through untouched, and the
/// peer identity is simply asserted — the fake models QUIC's *contract*
/// (mutually authenticated, unreliable datagrams), not its mechanics.
pub struct MemTransport {
    established: BTreeMap<Pubkey, SocketAddr>,
    by_addr: BTreeMap<SocketAddr, Pubkey>,
    inbound: VecDeque<(SocketAddr, Vec<u8>)>,
    events: VecDeque<TransportEvent>,
}

impl MemTransport {
    fn new() -> Self {
        Self {
            established: BTreeMap::new(),
            by_addr: BTreeMap::new(),
            inbound: VecDeque::new(),
            events: VecDeque::new(),
        }
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
    }

    /// Harness-side: drop the connection with `pubkey`.
    pub fn disconnect(&mut self, pubkey: &Pubkey) {
        if let Some(addr) = self.established.remove(pubkey) {
            self.by_addr.remove(&addr);
            self.events.push_back(TransportEvent::Disconnected {
                peer: addr,
                reason: "harness disconnect".to_string(),
            });
        }
    }

    pub fn is_connected_to(&self, pubkey: &Pubkey) -> bool {
        self.established.contains_key(pubkey)
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

    fn bind(&mut self, _port: Option<u16>) -> Result<SocketId> {
        Err(anyhow::anyhow!("high-seam harness has no helper sockets"))
    }
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
    up: bool,
}

/// Deterministic tick-driven harness over [`MemTransport`] nodes.
pub struct HighSeamNet {
    seed: u64,
    base: Instant,
    ticks: u64,
    nodes: Vec<HighSeamNode>,
    by_addr: BTreeMap<SocketAddr, usize>,
    in_flight: VecDeque<(SocketAddr, SocketAddr, Vec<u8>)>,
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
            in_flight: VecDeque::new(),
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
            advertised_addr: options.direct.then_some(addr),
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
            up: true,
        });
        self.by_addr.insert(addr, index);
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
    }

    pub fn run_ticks(&mut self, count: u64) {
        for _ in 0..count {
            self.tick();
        }
    }

    fn drain_node(&mut self, index: usize) {
        let from = self.nodes[index].addr;
        while let Some((to, bytes)) = self.nodes[index].env.outbox.pop_front() {
            self.in_flight.push_back((from, to, bytes));
        }
        while let Some(event) = self.nodes[index].core.poll_event() {
            if let CoreEvent::ShredForFilter(packet) = event {
                self.nodes[index].delivered.push(packet.as_slice().to_vec());
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

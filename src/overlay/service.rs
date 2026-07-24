use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    hash::{Hash, Hasher},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use arrayvec::ArrayVec;
use lrumap::LruBTreeMap;
use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};

use crate::types::{PacketInfo, PacketView};

use super::{
    OverlayConfig, OverlayMode, TurbineTree,
    discovery::AddressDiscovery,
    env::{IpFamily, OverlayEnv, SocketId, TcpEvent},
    gossip::{
        AdvertOutcome, LightbringerGossip, MAX_ADVERT_ADDRS, MAX_ADVERT_VIA, PeerAdvert,
        PortTaggedAddr, Reachability, RepairEndpoint, SignedPeerAdvert,
    },
    nat::{AllocatorProfile, NatClass},
    packet::{OverlayFrame, PunchAssistKind},
    portmap::{PortMapConfig, PortMapper},
    punch::{ConnectRequest, ConnectResponse, MAX_PUNCH_CANDIDATES, NatProfile, PunchProbe},
    repair::{
        self, MAX_REPAIR_REQ_WIRE, MAX_REPAIR_REQUESTS_PER_SECOND, MAX_REPAIR_RESP_WIRE,
        RepairPeerEntry, RepairRateLimiter, RepairReq,
    },
    transport::{
        OverlayStreamId, OverlayTransport, ProbeEvent, ProbeId, PunchProbeEvent, StreamEvent,
        TransportEvent,
    },
};

const ADVERT_INTERVAL: Duration = Duration::from_secs(10);
const MAX_CORE_EVENTS: usize = 8192;
/// Recently seen shreds, for retransmit loop suppression: the v1 frame
/// carries no origin field, so a shred returning to a node that already
/// flooded it must be recognized and dropped here.
const SEEN_SHREDS_CAPACITY: usize = 32_768;
/// A repair stream that has neither concluded nor died by this deadline is
/// reclaimed. Requesters retry far sooner (the repair manager re-samples at
/// 200ms); this bound only reclaims state.
const REPAIR_STREAM_TIMEOUT: Duration = Duration::from_secs(3);
/// In-flight repair exchange caps, both roles. Inbound is additionally
/// bounded per connection by the transport's concurrent-stream limit.
const MAX_OUTBOUND_REPAIRS: usize = 1024;
const MAX_INBOUND_REPAIRS: usize = 1024;
/// A §6.2.3 dial-back (requester request or helper probe) that has not
/// concluded by this deadline is abandoned/failed.
const DIALBACK_TIMEOUT: Duration = Duration::from_secs(3);
/// Per-requester dial-back rate cap (§9: dial-back is a socket-exhaustion and
/// reflection lever). A node only needs to (re)confirm rarely.
const MAX_DIALBACK_PER_SECOND: u32 = 4;
/// Helper refuses to probe a candidate on a privileged port (§9).
const MIN_UNPRIVILEGED_PORT: u16 = 1024;
/// Concurrent helper probes this node will run (bounds fresh-socket binds).
const MAX_HELPER_PROBES: usize = 64;
/// A receiver-side identity confirm-dial (§6.2.3 F8 closure) that has not
/// connected by this deadline quarantines the advertised (pubkey→address).
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(3);
/// Quarantined lying-advert identities. Bounded; a superseding advert lifts
/// the quarantine so an honestly-moved node can re-confirm.
const MAX_QUARANTINE: usize = 4096;
/// P5 is strictly demand-driven; this caps all local live exchanges, so a
/// gossip flood cannot turn into a socket/probe flood.
const MAX_PUNCH_SESSIONS: usize = 128;
const MAX_PUNCH_FORWARDS: usize = 512;
const MAX_PUNCH_HELPERS: usize = 64;
const MAX_BRACKET_WIDTH: u16 = 32;
pub(crate) const BIRTHDAY_SOCKET_CAP: usize = 256;
pub(crate) const BIRTHDAY_SPRAY_CAP: usize = 1024;
pub(crate) const BIRTHDAY_DURATION: Duration = Duration::from_secs(20);
const BIRTHDAY_PORT_START: u16 = 40_000;
const BIRTHDAY_PORT_WIDTH: u16 = 20_000;
const MAX_PUNCH_OUTCOMES: usize = 4096;
const PUNCH_OUTCOME_TTL: Duration = Duration::from_secs(10 * 60);
const PUNCH_TIMEOUT: Duration = Duration::from_secs(5);
const PUNCH_PROBE_INTERVAL: Duration = Duration::from_millis(100);
/// §6.5's first-attempt policy: one bootstrap volley plus one prflx/assist
/// re-aim is enough. Further periodic retries only turn bad NAT pairs into a
/// sustained probe load and contradict the measured bimodal outcome.
const MAX_PUNCH_PROBE_ROUNDS: u8 = 2;
/// The via's independent initiator and target limits (§9). A small value is
/// enough because outcomes are cached after one attempt (rung 4).
const MAX_PUNCH_SIGNALS_PER_SECOND: u32 = 4;

fn packet_view(payload: Vec<u8>) -> Option<PacketView> {
    if payload.len() > solana_packet::PACKET_DATA_SIZE {
        return None;
    }
    ArrayVec::try_from(payload.as_slice()).ok()
}

fn shred_dedup_key(payload: &[u8]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    payload.hash(&mut hasher);
    hasher.finish()
}

/// Application-level outputs of the core, drained by the driver after every
/// event (the glommio driver forwards shreds into the packet filter channel;
/// the simulator records them).
#[derive(Clone, Debug)]
pub enum CoreEvent {
    ShredForFilter(PacketInfo),
    PeerConnected {
        peer: SocketAddr,
        pubkey: Option<Pubkey>,
    },
    PeerDisconnected {
        peer: SocketAddr,
        reason: String,
    },
    /// Inbound §6.4 repair request, parsed and rate-admitted. The driver
    /// owns the (blocking, fjall) store lookup and answers through
    /// [`OverlayCore::on_repair_response`]; the core stays sans-IO.
    RepairRequest {
        stream: OverlayStreamId,
        #[allow(dead_code)] // consumed by sim oracles; drivers answer by stream
        peer: Pubkey,
        request: RepairReq,
    },
    /// A repair stream this node opened concluded with the peer's answer
    /// (`None` = NotFound).
    RepairResponse {
        stream: OverlayStreamId,
        peer: Pubkey,
        shred: Option<Vec<u8>>,
    },
    /// A repair stream this node opened died without an answer (reset,
    /// disconnect, malformed response, or timeout).
    RepairFailed {
        stream: OverlayStreamId,
        peer: Pubkey,
    },
}

struct OutboundRepair {
    peer: Pubkey,
    buf: Vec<u8>,
    deadline: Instant,
}

/// Which Direct candidate a §6.2.3 dial-back is confirming (P4 grew the
/// candidate set beyond the P3 observed mapping, §6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CandidateKind {
    /// The observed consistent mapping (P3).
    Observed,
    /// The gateway-granted port at our observed external IP (§6.3).
    PortMapped,
    /// The observed v6 mapping, confirmed end-to-end over the v6 path
    /// (§6.3 step 2 — §4: naive v6 advertising measurably hurts).
    V6,
}

/// Peers dialed for v6 self-discovery per advert cycle (§6.3): two distinct
/// observer IPs are what classification needs; one spare covers churn.
const MAX_V6_PROBE_DIALS: usize = 3;

/// Requester side of a §6.2.3 dial-back: the candidate address we asked a
/// helper to confirm, awaiting its verdict.
struct DialBackPending {
    #[allow(dead_code)] // recorded for diagnostics; matched by nonce
    helper: Pubkey,
    kind: CandidateKind,
    candidate: SocketAddr,
    deadline: Instant,
}

/// Helper side of a §6.2.3 dial-back: a fresh-source probe in flight toward
/// the requester's own observed source, bound to its own short-lived socket.
struct HelperProbe {
    requester: Pubkey,
    nonce: u64,
    socket: SocketId,
    deadline: Instant,
}

/// Receiver-side identity confirm-dial in flight (§6.2.3 F8 closure): we are
/// dialing `expected`'s advertised address and will keep the connection only
/// if it authenticates as `expected`.
struct ConfirmDial {
    expected: Pubkey,
    deadline: Instant,
}

/// One active P5 exchange. Candidate addresses are only bootstrap hints; an
/// authenticated raw probe source is retained separately as the freshest
/// peer-reflexive address (§6.5).
struct PunchSession {
    peer: Pubkey,
    nonce: u64,
    via: Pubkey,
    candidates: ArrayVec<SocketAddr, MAX_PUNCH_CANDIDATES>,
    freshest: Option<SocketAddr>,
    remote_profile: NatProfile,
    local_profile: NatProfile,
    awaiting_response: bool,
    dial_started: bool,
    payload: Option<Vec<u8>>,
    birthday_sockets: Vec<SocketId>,
    birthday_started: bool,
    birthday_spray_sent: bool,
    deadline: Instant,
    next_probe: Instant,
    probe_rounds: u8,
    /// One bounded second volley is reserved for an authenticated helper
    /// result. It is part of the original exchange, not a retry loop.
    assist_followup_granted: bool,
    /// Rung 2's exact next mapping prediction. A sequential helper observes
    /// the last allocation X, so the reciprocal peer can open its filter
    /// toward X + stride while creating its own next mapping. When both
    /// endpoints are sequential, the two predictions compose: each side's
    /// first packet is addressed to the other's predicted next mapping.
    sequential_prediction: Option<SocketAddr>,
    /// Rung-2's receiver-side filter openers. These are separate from the
    /// four signed bootstrap candidates so a valid k≤32 bracket is never
    /// silently truncated by that smaller aiming-hint cap.
    bracket_candidates: ArrayVec<SocketAddr, { MAX_BRACKET_WIDTH as usize }>,
}

/// Bounded relay state: a `via` only routes a response for a request it
/// personally forwarded over authenticated connections.
struct PunchForward {
    target: Pubkey,
    origin_profile: NatProfile,
    origin_candidates: ArrayVec<SocketAddr, MAX_PUNCH_CANDIDATES>,
    deadline: Instant,
}

/// Short-lived helper socket allocated by a public via for rung 1 or 2. It
/// only ever observes a probe signed by the original initiator and reports
/// that source to the already-negotiated target; it never probes a third
/// party itself.
struct PunchHelper {
    origin: Pubkey,
    target: Pubkey,
    nonce: u64,
    socket: SocketId,
    kind: PunchAssistKind,
    deadline: Instant,
}

/// Rung-4 cache key. A changed observed external IP is a new NAT generation,
/// so it naturally misses this key and allows one fresh ladder attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct PunchOutcomeKey {
    peer: Pubkey,
    local_generation: Option<std::net::IpAddr>,
    remote_generation: Option<std::net::IpAddr>,
}

struct InboundRepair {
    peer: Pubkey,
    buf: Vec<u8>,
    /// Request parsed and handed to the driver; awaiting its lookup.
    awaiting_lookup: bool,
    deadline: Instant,
}

/// Sans-IO overlay state machine (nat-traversal.md §6.9): inbound datagrams
/// and timer expiries arrive as `on_*` events from a driver, outbound
/// datagrams leave through `OverlayEnv::send`, and everything else is polled.
///
/// Peers are identities (§6.1): gossip is keyed by pubkey, the turbine tree
/// shuffles pubkeys, and every send funnels through [`Self::send_to_peer`] —
/// prefer the established connection, dial only peers advertising
/// `Reachability::Direct`, otherwise drop and count. A node with no
/// operator-configured `advertised_addr` advertises `Coordinated` instead of
/// a useless bind address (fixes F1/F2).
pub struct OverlayCore<T> {
    mode: OverlayMode,
    transport: T,
    keypair: Arc<Keypair>,
    local_pubkey: Pubkey,
    gossip: LightbringerGossip,
    discovery: AddressDiscovery,
    /// v6-side observation store (§6.3): families never mix — a v6 mapping
    /// grouped with v4 observations would misclassify both.
    discovery_v6: Option<AddressDiscovery>,
    tree: TurbineTree,
    static_peers: Vec<SocketAddr>,
    advertised_addr: Option<SocketAddr>,
    advertised_addr_v6: Option<SocketAddr>,
    birthday_punch: bool,
    /// The v6 overlay socket's address, when dual-stack (§6.3).
    bind_v6: Option<SocketAddr>,
    repair: RepairEndpoint,
    advert_ttl_ms: u32,
    advert_seq: u64,
    next_advert: Instant,
    seen_shreds: LruBTreeMap<u64, ()>,
    outbound_repairs: BTreeMap<OverlayStreamId, OutboundRepair>,
    inbound_repairs: BTreeMap<OverlayStreamId, InboundRepair>,
    repair_rate: RepairRateLimiter,
    /// §6.2.3 dial-back confirmed candidate (requester side): the address a
    /// helper's fresh-source probe reached us on. Consumed by the auto-advert
    /// policy (P3) to advertise `Direct`.
    confirmed_direct: Option<SocketAddr>,
    /// §6.3 dial-back confirmed port-mapped candidate: the gateway granted
    /// it AND a fresh-source probe reached it (a grant alone proves nothing
    /// behind CGN or a lying gateway).
    confirmed_portmap: Option<SocketAddr>,
    /// §6.3 dial-back confirmed v6 address: a fresh-source probe completed a
    /// handshake over the end-to-end v6 path (pinhole or open firewall).
    confirmed_v6: Option<SocketAddr>,
    /// §6.3 port-mapping ladder client, when a gateway is configured.
    portmap: Option<PortMapper>,
    dialback_pending: BTreeMap<u64, DialBackPending>,
    next_dialback_nonce: u64,
    /// Helper side: probes in flight, keyed by transport probe handle.
    helper_probes: BTreeMap<ProbeId, HelperProbe>,
    dialback_rate: RepairRateLimiter,
    /// Receiver-side identity confirm-dials in flight, keyed by the address
    /// being confirmed (§6.2.3 F8 closure).
    confirming: BTreeMap<SocketAddr, ConfirmDial>,
    /// Advertised `Direct` addresses that answered as the wrong identity (or
    /// never answered). Any peer — Direct advert or an errant connection —
    /// resolving to a quarantined address is excluded from fan-out; a
    /// superseding advert for a *different* address is re-confirmable
    /// (§6.2.3 F8). Address-keyed so an innocent node that happens to answer
    /// at the lied-about address is never fanned to either.
    quarantined: LruBTreeMap<SocketAddr, ()>,
    punch_sessions: BTreeMap<u64, PunchSession>,
    punch_forwards: BTreeMap<(Pubkey, u64), PunchForward>,
    punch_helpers: BTreeMap<SocketId, PunchHelper>,
    punch_outcomes: LruBTreeMap<PunchOutcomeKey, Instant>,
    last_punch_profiles: LruBTreeMap<Pubkey, NatProfile>,
    punch_initiator_rate: RepairRateLimiter,
    punch_target_rate: RepairRateLimiter,
    punch_refused: u64,
    punch_attempts: u64,
    dropped_unreachable: u64,
    invalid_adverts: u64,
    repairs_refused: u64,
    repairs_malformed: u64,
    dialbacks_refused: u64,
    quarantined_count: u64,
    events: VecDeque<CoreEvent>,
}

impl<T: OverlayTransport> OverlayCore<T> {
    pub fn new(transport: T, config: &OverlayConfig, keypair: Arc<Keypair>, now: Instant) -> Self {
        let local_pubkey = keypair.pubkey();
        let portmap = config.gateway_addr.map(|gateway| {
            PortMapper::new(
                PortMapConfig {
                    gateway,
                    internal_port: config.bind_addr.port(),
                    internal_ip: config
                        .portmap_local_ip
                        .unwrap_or_else(|| config.bind_addr.ip()),
                    internal_v6: config.bind_addr_v6,
                },
                now,
            )
        });
        Self {
            mode: config.mode,
            transport,
            local_pubkey,
            keypair,
            gossip: LightbringerGossip::new(config.peer_ttl()),
            discovery: AddressDiscovery::new(config.bind_addr),
            discovery_v6: config.bind_addr_v6.map(AddressDiscovery::new),
            tree: TurbineTree::new(local_pubkey, config.fanout),
            static_peers: config.static_peers.clone(),
            advertised_addr: config.advertised_addr,
            advertised_addr_v6: config.advertised_addr_v6,
            birthday_punch: config.nat.birthday_punch,
            bind_v6: config.bind_addr_v6,
            repair: config
                .repair_addr
                .map(RepairEndpoint::Udp)
                .unwrap_or(RepairEndpoint::InConnection),
            advert_ttl_ms: config.peer_ttl().as_millis().min(u128::from(u32::MAX)) as u32,
            advert_seq: 0,
            next_advert: now + ADVERT_INTERVAL,
            seen_shreds: LruBTreeMap::new(SEEN_SHREDS_CAPACITY),
            outbound_repairs: BTreeMap::new(),
            inbound_repairs: BTreeMap::new(),
            repair_rate: RepairRateLimiter::new(MAX_REPAIR_REQUESTS_PER_SECOND),
            confirmed_direct: None,
            confirmed_portmap: None,
            confirmed_v6: None,
            portmap,
            dialback_pending: BTreeMap::new(),
            next_dialback_nonce: 0,
            helper_probes: BTreeMap::new(),
            dialback_rate: RepairRateLimiter::new(MAX_DIALBACK_PER_SECOND),
            confirming: BTreeMap::new(),
            quarantined: LruBTreeMap::new(MAX_QUARANTINE),
            punch_sessions: BTreeMap::new(),
            punch_forwards: BTreeMap::new(),
            punch_helpers: BTreeMap::new(),
            punch_outcomes: LruBTreeMap::new(MAX_PUNCH_OUTCOMES),
            last_punch_profiles: LruBTreeMap::new(MAX_PUNCH_OUTCOMES),
            punch_initiator_rate: RepairRateLimiter::new(MAX_PUNCH_SIGNALS_PER_SECOND),
            punch_target_rate: RepairRateLimiter::new(MAX_PUNCH_SIGNALS_PER_SECOND),
            punch_refused: 0,
            punch_attempts: 0,
            dropped_unreachable: 0,
            invalid_adverts: 0,
            repairs_refused: 0,
            repairs_malformed: 0,
            dialbacks_refused: 0,
            quarantined_count: 0,
            events: VecDeque::new(),
        }
    }

    pub fn on_datagram(
        &mut self,
        env: &mut dyn OverlayEnv,
        socket: SocketId,
        from: SocketAddr,
        datagram: &[u8],
    ) {
        // The port-map socket speaks PCP/NAT-PMP/SSDP, never QUIC (§6.3).
        if let Some(portmap) = &mut self.portmap
            && portmap.socket() == Some(socket)
        {
            portmap.on_datagram(env, from, datagram);
            return;
        }
        self.transport.on_datagram(env, socket, from, datagram);
        self.pump(env);
    }

    /// TCP stream event for the §6.3 UPnP gateway conversation, forwarded by
    /// the driver.
    pub fn on_tcp_event(&mut self, env: &mut dyn OverlayEnv, event: TcpEvent) {
        if let Some(portmap) = &mut self.portmap {
            portmap.on_tcp_event(env, event);
        }
    }

    /// Fire due deadlines. Safe to call early; deadlines are re-checked.
    pub fn on_timer(&mut self, env: &mut dyn OverlayEnv) {
        self.transport.on_timer(env);
        if let Some(portmap) = &mut self.portmap {
            portmap.on_timer(env);
        }
        let now = env.now();
        if now >= self.next_advert {
            self.next_advert = now + ADVERT_INTERVAL;
            let advert_raw = self.advertise(env);
            self.broadcast_observations(env);
            if let Some(advert_raw) = advert_raw {
                self.maybe_probe_v6(env, advert_raw);
            }
            self.maybe_request_dialback(env);
        }
        self.expire_repairs(env, now);
        self.expire_dialbacks(env, now);
        self.expire_confirms(now);
        self.advance_punches(env, now);
        self.expire_punch_forwards(now);
        self.expire_punch_helpers(env, now);
        self.pump(env);
    }

    /// Reclaim repair streams that neither concluded nor died in time.
    fn expire_repairs(&mut self, env: &mut dyn OverlayEnv, now: Instant) {
        let expired_out: Vec<OverlayStreamId> = self
            .outbound_repairs
            .iter()
            .filter(|(_, repair)| now >= repair.deadline)
            .map(|(&stream, _)| stream)
            .collect();
        for stream in expired_out {
            let repair = self.outbound_repairs.remove(&stream).expect("collected above");
            self.transport.reset_stream(env, stream);
            self.push_event(CoreEvent::RepairFailed {
                stream,
                peer: repair.peer,
            });
        }
        let expired_in: Vec<OverlayStreamId> = self
            .inbound_repairs
            .iter()
            .filter(|(_, repair)| now >= repair.deadline)
            .map(|(&stream, _)| stream)
            .collect();
        for stream in expired_in {
            self.inbound_repairs.remove(&stream);
            self.transport.reset_stream(env, stream);
        }
    }

    pub fn on_source_packet(&mut self, env: &mut dyn OverlayEnv, packet: PacketInfo) {
        if self.mode != OverlayMode::Source {
            return;
        }
        // Mark (not check) seen: repeated source injections still flood,
        // but our own shred coming back over the mesh is dropped.
        self.seen_shreds.push(shred_dedup_key(packet.as_slice()), ());
        let raw = match OverlayFrame::shred(packet.to_vec()).encode() {
            Ok(raw) => raw,
            Err(e) => {
                log::warn!("overlay: failed to encode source shred frame: {e}");
                return;
            }
        };
        let peers = self.usable_peers(env.now(), None);
        for target in self.tree.origin_peers(packet.as_slice(), &peers) {
            self.send_to_peer(env, target, raw.clone());
        }
        self.pump(env);
    }

    pub fn poll_timeout(&mut self) -> Option<Instant> {
        let mut deadline = match self.transport.poll_timeout() {
            Some(transport_deadline) => transport_deadline.min(self.next_advert),
            None => self.next_advert,
        };
        if let Some(portmap_deadline) = self.portmap.as_ref().and_then(|pm| pm.poll_timeout()) {
            deadline = deadline.min(portmap_deadline);
        }
        for repair in self.outbound_repairs.values() {
            deadline = deadline.min(repair.deadline);
        }
        for repair in self.inbound_repairs.values() {
            deadline = deadline.min(repair.deadline);
        }
        for pending in self.dialback_pending.values() {
            deadline = deadline.min(pending.deadline);
        }
        for probe in self.helper_probes.values() {
            deadline = deadline.min(probe.deadline);
        }
        for confirm in self.confirming.values() {
            deadline = deadline.min(confirm.deadline);
        }
        for session in self.punch_sessions.values() {
            deadline = deadline.min(session.deadline).min(session.next_probe);
        }
        for forward in self.punch_forwards.values() {
            deadline = deadline.min(forward.deadline);
        }
        for helper in self.punch_helpers.values() {
            deadline = deadline.min(helper.deadline);
        }
        Some(deadline)
    }

    pub fn poll_event(&mut self) -> Option<CoreEvent> {
        self.events.pop_front()
    }

    #[allow(dead_code)]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Simulator/oracle access to the transport (e.g. establishing fake
    /// connections in the high-seam harness).
    #[allow(dead_code)]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Process transport activity injected outside the datagram path (the
    /// high-seam harness feeds MemTransport stream ops directly).
    #[allow(dead_code)]
    pub fn on_transport_activity(&mut self, env: &mut dyn OverlayEnv) {
        self.pump(env);
    }

    /// Live gossip adverts, for simulator oracles.
    #[allow(dead_code)]
    pub fn gossip_snapshot(&self, now: Instant) -> Vec<PeerAdvert> {
        self.gossip.peers(now)
    }

    /// Sends dropped because the target was neither connected nor `Direct`.
    /// The flood path cannot reach this today — `usable_peers` pre-excludes
    /// `Coordinated`-only peers, which is §6.7's stricter guarantee — so it
    /// guards future by-identity callers (P2 repair targeting, P5 punch
    /// fallback) where the target is chosen before reachability is known.
    #[allow(dead_code)]
    pub fn dropped_unreachable(&self) -> u64 {
        self.dropped_unreachable
    }

    /// Adverts rejected for a bad signature.
    #[allow(dead_code)]
    pub fn invalid_adverts(&self) -> u64 {
        self.invalid_adverts
    }

    #[allow(dead_code)]
    pub fn gossip_len(&self) -> usize {
        self.gossip.len()
    }

    /// Repair requests refused by the per-pubkey rate limit or the
    /// in-flight cap.
    #[allow(dead_code)]
    pub fn repairs_refused(&self) -> u64 {
        self.repairs_refused
    }

    /// Malformed/truncated repair requests and responses dropped inertly.
    #[allow(dead_code)]
    pub fn repairs_malformed(&self) -> u64 {
        self.repairs_malformed
    }

    /// P5 oracle surface: in-flight demand-driven exchanges. This must stay
    /// bounded and, crucially, is never populated merely by gossip receipt.
    #[allow(dead_code)]
    pub fn active_punch_sessions(&self) -> usize {
        self.punch_sessions.len()
    }

    #[allow(dead_code)]
    pub fn active_punch_helpers(&self) -> usize {
        self.punch_helpers.len()
    }

    #[allow(dead_code)]
    pub fn active_punch_forwards(&self) -> usize {
        self.punch_forwards.len()
    }

    /// P5 oracle surface: relayed requests refused for signature, visibility,
    /// authenticated-route, capacity, or per-identity rate-limit reasons.
    #[allow(dead_code)]
    pub fn punch_refused(&self) -> u64 {
        self.punch_refused
    }

    /// P5 oracle surface: real ladder attempts admitted after the outcome
    /// cache. Repeated shreds must not make this climb for the same failed
    /// peer-pair/NAT-generation tuple.
    #[allow(dead_code)]
    pub fn punch_attempts(&self) -> u64 {
        self.punch_attempts
    }

    /// Explicit targeted reach-upgrade API. It intentionally does not alter
    /// the normal turbine or repair candidate sets: callers must name the
    /// Coordinated peer they want to reach (§6.5 trigger policy).
    #[allow(dead_code)]
    pub fn request_direct_path(&mut self, env: &mut dyn OverlayEnv, peer: Pubkey) -> bool {
        if self.transport.connection_addr(&peer).is_some() {
            return true;
        }
        // Public/dial-back-confirmed peers need no P5 signaling, but exposing
        // the same explicit API makes the reachability oracle compare a
        // direct dial and a coordinated punch uniformly.
        if let Some(addr) = self
            .gossip
            .get(&peer, env.now())
            .and_then(|advert| advert.direct_addrs().first().copied())
        {
            if self.transport.dial_expecting(env, addr, peer).is_ok() {
                self.confirming.entry(addr).or_insert(ConfirmDial {
                    expected: peer,
                    deadline: env.now() + CONFIRM_TIMEOUT,
                });
                return true;
            }
        }
        self.begin_punch(env, peer, None)
    }

    /// The repair peer view a requester samples (§6.4): every live gossip
    /// identity, its advertised repair endpoint, and whether an overlay
    /// connection currently exists. The driver republishes this to the
    /// repair manager's `RepairPeerSource`.
    pub fn repair_peer_view(&mut self, now: Instant) -> Vec<RepairPeerEntry> {
        let connected: BTreeSet<Pubkey> = self.transport.connected_peers().into_iter().collect();
        self.gossip
            .peers(now)
            .into_iter()
            .filter(|advert| advert.pubkey != self.local_pubkey)
            .map(|advert| RepairPeerEntry {
                pubkey: advert.pubkey,
                repair: advert.repair,
                connected: connected.contains(&advert.pubkey),
            })
            .collect()
    }

    /// Open a §6.4 repair stream toward `peer` over the existing overlay
    /// connection: encoded request, then FIN. Never dials — an unconnected
    /// target is dropped and counted (`dropped_unreachable`), and the
    /// requester's retry samples someone else.
    pub fn request_repair(
        &mut self,
        env: &mut dyn OverlayEnv,
        peer: Pubkey,
        request: &RepairReq,
    ) -> Option<OverlayStreamId> {
        if self.outbound_repairs.len() >= MAX_OUTBOUND_REPAIRS {
            log::debug!("overlay: outbound repair cap {MAX_OUTBOUND_REPAIRS} reached");
            return None;
        }
        let Some(stream) = self.transport.open_stream(&peer) else {
            self.dropped_unreachable += 1;
            log::debug!("overlay: no connection to {peer} for repair; dropped");
            return None;
        };
        self.transport
            .write_stream(env, stream, &repair::encode_request(request));
        self.transport.finish_stream(env, stream);
        self.outbound_repairs.insert(
            stream,
            OutboundRepair {
                peer,
                buf: Vec::new(),
                deadline: env.now() + REPAIR_STREAM_TIMEOUT,
            },
        );
        self.pump(env);
        Some(stream)
    }

    /// Driver-side answer to a [`CoreEvent::RepairRequest`]: the store
    /// lookup result (`None` = not found) is written back and the stream is
    /// FIN'd. Ignored when the stream already died.
    pub fn on_repair_response(
        &mut self,
        env: &mut dyn OverlayEnv,
        stream: OverlayStreamId,
        shred: Option<Vec<u8>>,
    ) {
        let Some(repair) = self.inbound_repairs.remove(&stream) else {
            return;
        };
        if !repair.awaiting_lookup {
            return;
        }
        let response = match shred {
            Some(bytes) => repair::RepairResp::Shred(bytes),
            None => repair::RepairResp::NotFound,
        };
        match repair::encode_response(&response) {
            Ok(raw) => {
                self.transport.write_stream(env, stream, &raw);
                self.transport.finish_stream(env, stream);
            }
            Err(e) => {
                log::warn!("overlay: failed to encode repair response: {e}");
                self.transport.reset_stream(env, stream);
            }
        }
        self.pump(env);
    }

    fn pump(&mut self, env: &mut dyn OverlayEnv) {
        let mut connected: Vec<(Pubkey, SocketAddr)> = Vec::new();
        while let Some(event) = self.transport.poll_event() {
            let event = match event {
                TransportEvent::Connected { peer, pubkey } => {
                    if let Some(pubkey) = pubkey {
                        connected.push((pubkey, peer));
                    }
                    CoreEvent::PeerConnected { peer, pubkey }
                }
                TransportEvent::Disconnected { peer, reason } => {
                    CoreEvent::PeerDisconnected { peer, reason }
                }
            };
            self.push_event(event);
        }
        for (pubkey, peer_addr) in connected {
            // §6.2.3 F8: a connection born from a confirm-dial is kept only if
            // it authenticates as the advertised identity; a mismatch drops it
            // and quarantines the liar.
            if self.resolve_confirm(env, peer_addr, pubkey) {
                self.complete_punch(env, pubkey);
                // §6.2 step 1: tell the peer the address we see it at, so it
                // can classify its own NAT from our vantage point.
                self.send_address_observation(env, &pubkey, peer_addr);
            }
        }
        while let Some((from, raw)) = self.transport.poll_inbound() {
            self.handle_frame(env, from, raw);
        }
        while let Some(event) = self.transport.poll_stream_event() {
            self.handle_stream_event(env, event);
        }
        while let Some(event) = self.transport.poll_probe_event() {
            self.on_probe_event(env, event);
        }
        while let Some(event) = self.transport.poll_punch_probe() {
            self.handle_punch_probe(env, event);
        }
    }

    fn handle_stream_event(&mut self, env: &mut dyn OverlayEnv, event: StreamEvent) {
        match event {
            StreamEvent::Opened { stream, peer } => {
                if self.inbound_repairs.len() >= MAX_INBOUND_REPAIRS {
                    self.repairs_refused += 1;
                    self.transport.reset_stream(env, stream);
                    return;
                }
                self.inbound_repairs.insert(
                    stream,
                    InboundRepair {
                        peer,
                        buf: Vec::new(),
                        awaiting_lookup: false,
                        deadline: env.now() + REPAIR_STREAM_TIMEOUT,
                    },
                );
            }
            StreamEvent::Data { stream, bytes } => {
                if let Some(repair) = self.inbound_repairs.get_mut(&stream) {
                    if repair.awaiting_lookup {
                        // Bytes after the FIN-delimited request are garbage.
                        self.repairs_malformed += 1;
                        self.inbound_repairs.remove(&stream);
                        self.transport.reset_stream(env, stream);
                        return;
                    }
                    repair.buf.extend_from_slice(&bytes);
                    if repair.buf.len() > MAX_REPAIR_REQ_WIRE {
                        self.repairs_malformed += 1;
                        self.inbound_repairs.remove(&stream);
                        self.transport.reset_stream(env, stream);
                    }
                } else if let Some(repair) = self.outbound_repairs.get_mut(&stream) {
                    repair.buf.extend_from_slice(&bytes);
                    if repair.buf.len() > MAX_REPAIR_RESP_WIRE {
                        self.repairs_malformed += 1;
                        let repair =
                            self.outbound_repairs.remove(&stream).expect("present above");
                        self.transport.reset_stream(env, stream);
                        self.push_event(CoreEvent::RepairFailed {
                            stream,
                            peer: repair.peer,
                        });
                    }
                }
            }
            StreamEvent::Finished { stream } => {
                if let Some(repair) = self.inbound_repairs.get_mut(&stream) {
                    if repair.awaiting_lookup {
                        return;
                    }
                    let peer = repair.peer;
                    match repair::decode_request(&repair.buf) {
                        Ok(request) => {
                            if self.repair_rate.check_and_increment(peer, env.now()) {
                                repair.awaiting_lookup = true;
                                repair.buf = Vec::new();
                                self.push_event(CoreEvent::RepairRequest {
                                    stream,
                                    peer,
                                    request,
                                });
                            } else {
                                self.repairs_refused += 1;
                                self.inbound_repairs.remove(&stream);
                                self.transport.reset_stream(env, stream);
                            }
                        }
                        Err(_) => {
                            self.repairs_malformed += 1;
                            self.inbound_repairs.remove(&stream);
                            self.transport.reset_stream(env, stream);
                        }
                    }
                } else if let Some(repair) = self.outbound_repairs.remove(&stream) {
                    match repair::decode_response(&repair.buf) {
                        Ok(repair::RepairResp::Shred(bytes)) => {
                            self.push_event(CoreEvent::RepairResponse {
                                stream,
                                peer: repair.peer,
                                shred: Some(bytes),
                            });
                        }
                        Ok(repair::RepairResp::NotFound) => {
                            self.push_event(CoreEvent::RepairResponse {
                                stream,
                                peer: repair.peer,
                                shred: None,
                            });
                        }
                        Err(_) => {
                            self.repairs_malformed += 1;
                            self.push_event(CoreEvent::RepairFailed {
                                stream,
                                peer: repair.peer,
                            });
                        }
                    }
                }
            }
            StreamEvent::Failed { stream } => {
                self.inbound_repairs.remove(&stream);
                if let Some(repair) = self.outbound_repairs.remove(&stream) {
                    self.push_event(CoreEvent::RepairFailed {
                        stream,
                        peer: repair.peer,
                    });
                }
            }
        }
    }

    fn handle_frame(&mut self, env: &mut dyn OverlayEnv, from: SocketAddr, raw: Vec<u8>) {
        let frame = match OverlayFrame::decode(&raw) {
            Ok(frame) => frame,
            Err(e) => {
                log::warn!("overlay: dropped invalid frame from {from}: {e}");
                return;
            }
        };

        match frame {
            OverlayFrame::Shred { payload } => {
                let key = shred_dedup_key(&payload);
                if self.seen_shreds.get(&key).is_some() {
                    return;
                }
                self.seen_shreds.push(key, ());

                if let Some(packet) = packet_view(payload.clone()) {
                    self.push_event(CoreEvent::ShredForFilter(PacketInfo::new(packet)));
                }

                let sender = self.transport.peer_identity(from);
                let peers = self.usable_peers(env.now(), sender);
                // The received bytes are already a valid shred frame;
                // retransmit them verbatim.
                for target in self.tree.retransmit_peers(&payload, &peers) {
                    self.send_to_peer(env, target, raw.clone());
                }
            }
            OverlayFrame::PeerAdvertisement { advert: signed } => {
                if signed.advert.pubkey == self.local_pubkey {
                    return;
                }
                if !signed.verify() {
                    self.invalid_adverts += 1;
                    log::warn!(
                        "overlay: dropped advert from {from} with invalid signature for {}",
                        signed.advert.pubkey
                    );
                    return;
                }
                let origin = signed.advert.pubkey;
                let outcome = self.gossip.upsert(signed.advert, env.now());
                if outcome != AdvertOutcome::Accepted {
                    return;
                }
                // Flood-forward the verified advert to connected peers,
                // skipping the sender and the advert's own origin.
                let sender = self.transport.peer_identity(from);
                for pubkey in self.transport.connected_peers() {
                    if pubkey == self.local_pubkey
                        || pubkey == origin
                        || Some(pubkey) == sender
                    {
                        continue;
                    }
                    self.transport
                        .queue_datagram_to_peer(env, &pubkey, raw.clone());
                }
            }
            OverlayFrame::AddressObservation { observed } => {
                // §6.2 step 1: a connected peer reports our public mapping.
                // Only an authenticated peer's observation is meaningful; the
                // identity keys the port-tagged store. Families never mix
                // (§6.3): the v6 mapping has its own store.
                if let Some(observer) = self.transport.peer_identity(from) {
                    if observed.is_ipv6() {
                        if let Some(discovery_v6) = &mut self.discovery_v6 {
                            discovery_v6.record(observer, from, observed);
                        }
                    } else {
                        self.discovery.record(observer, from, observed);
                    }
                }
            }
            OverlayFrame::DialBackRequest { nonce, probe_port } => {
                self.handle_dialback_request(env, from, nonce, probe_port);
            }
            OverlayFrame::DialBackResult { nonce, ok } => {
                self.handle_dialback_result(nonce, ok);
            }
            OverlayFrame::ConnectRequest { request } => {
                self.handle_connect_request(env, from, request);
            }
            OverlayFrame::ConnectResponse { response } => {
                self.handle_connect_response(env, from, response);
            }
            OverlayFrame::PunchAssist {
                nonce,
                origin,
                target,
                port,
                kind,
            } => self.handle_punch_assist(env, from, nonce, origin, target, port, kind),
            OverlayFrame::PunchObservation {
                nonce,
                origin,
                target,
                observed,
            } => self.handle_punch_observation(env, from, nonce, origin, target, observed),
            OverlayFrame::PunchBracket {
                nonce,
                origin,
                target,
                ip,
                start,
                end,
            } => self.handle_punch_bracket(env, from, nonce, origin, target, ip, start, end),
            OverlayFrame::PunchBirthday {
                nonce,
                origin,
                target,
            } => self.handle_punch_birthday(env, from, nonce, origin, target),
        }
    }

    /// §6.1's single send choke point, with the §6.2.3 F8 closure: an
    /// established (TLS-verified) connection takes the payload directly;
    /// otherwise a `Direct` advert alone does NOT authorize traffic — the send
    /// dials with the payload identity-gated, so the transport releases it only
    /// once the connection authenticates as the advertised identity. A lying
    /// advert therefore directs no sustained traffic at a victim: the mismatch
    /// drops the payload undelivered and quarantines the lied-about address.
    fn send_to_peer(&mut self, env: &mut dyn OverlayEnv, pubkey: Pubkey, raw: Vec<u8>) {
        if let Some(addr) = self.transport.connection_addr(&pubkey) {
            if self.is_quarantined(&addr) {
                self.dropped_unreachable += 1;
            } else {
                self.transport.queue_datagram_to_peer(env, &pubkey, raw);
            }
            return;
        }
        // §6.3: prefer the v6 Direct address when we can speak v6; fall back
        // to v4 rather than dropping when the preferred one is quarantined.
        let has_v6 = self.bind_v6.is_some();
        let advertised: Vec<SocketAddr> = self
            .gossip
            .get(&pubkey, env.now())
            .map(|advert| advert.direct_addrs().to_vec())
            .unwrap_or_default();
        let usable: Vec<SocketAddr> = advertised
            .into_iter()
            .filter(|addr| !self.is_quarantined(addr))
            .collect();
        let dial_addr = usable
            .iter()
            .find(|addr| addr.is_ipv6() && has_v6)
            .or_else(|| usable.iter().find(|addr| !addr.is_ipv6()))
            .copied();
        let Some(addr) = dial_addr else {
            // P5 trigger policy: this is the ONLY automatic trigger. It is
            // reached from an already-targeted send, never advert receipt,
            // fan-out membership, repair sampling, or a gossip sweep.
            if self.begin_punch(env, pubkey, Some(raw)) {
                return;
            }
            self.dropped_unreachable += 1;
            log::debug!("overlay: no route to {pubkey}; dropped");
            return;
        };
        // Identity-gated dial-on-demand (§6.2.3 F8): the payload rides the
        // dial but the transport releases it only once the connection
        // authenticates as `pubkey`; a mismatch drops it undelivered and the
        // liar is quarantined when the connection surfaces.
        if let Err(e) = self
            .transport
            .queue_datagram_expecting(env, addr, pubkey, raw)
        {
            log::warn!("overlay: failed to dial {pubkey} at {addr}: {e}");
            return;
        }
        self.confirming.entry(addr).or_insert(ConfirmDial {
            expected: pubkey,
            deadline: env.now() + CONFIRM_TIMEOUT,
        });
    }

    fn local_nat_profile(&mut self) -> NatProfile {
        NatProfile {
            class: self.discovery.classify(),
            allocator: self.discovery.calibrate(),
            birthday_punch: self.birthday_punch,
            generation: self.discovery.external_ip(),
        }
    }

    /// Local candidates for a signed request/response. They are aiming hints,
    /// not Direct authority: the raw probe and QUIC certificate still prove
    /// the actual path. IPv6 is included only when it was independently
    /// confirmed (or operator-configured), preserving P4's v6 invariant.
    fn local_punch_candidates(&self) -> ArrayVec<SocketAddr, MAX_PUNCH_CANDIDATES> {
        let mut candidates = ArrayVec::new();
        let mut add = |addr: Option<SocketAddr>| {
            if let Some(addr) = addr
                && !candidates.contains(&addr)
            {
                let _ = candidates.try_push(addr);
            }
        };
        // Preserve P4's preference: a usable v6 path avoids NAT mapping and
        // the punch merely opens both RFC 6092 firewalls.
        add(self.advertised_addr_v6);
        add(self.confirmed_v6);
        // Unlike a Direct advert, a P5 aiming hint need only be observed by
        // an authenticated peer over an established v6 connection. It is
        // still never accepted from unauthenticated traffic; this is the
        // confirmation that lets two otherwise default-deny RFC 6092
        // firewalls perform the coordinated volley (§6.5).
        if let Some(discovery_v6) = &self.discovery_v6 {
            for hint in discovery_v6.observed_hints() {
                add(Some(hint.mapping));
            }
        }
        add(self.advertised_addr);
        add(self.confirmed_direct);
        add(self.confirmed_portmap);
        for hint in self.discovery.observed_hints() {
            add(Some(hint.mapping));
        }
        candidates
    }

    /// Begin a single targeted P5 exchange. This intentionally does nothing
    /// for a `Direct` peer or a Coordinated advert without an *already
    /// connected* shared via: no eager gossip meshing and no relay fallback.
    fn begin_punch(
        &mut self,
        env: &mut dyn OverlayEnv,
        peer: Pubkey,
        payload: Option<Vec<u8>>,
    ) -> bool {
        if self.transport.connection_addr(&peer).is_some() {
            return true;
        }
        if let Some(session) = self.punch_sessions.values_mut().find(|s| s.peer == peer) {
            if session.payload.is_none() {
                session.payload = payload;
            }
            return true;
        }
        if self.punch_sessions.len() >= MAX_PUNCH_SESSIONS {
            return false;
        }
        let local_profile = self.local_nat_profile();
        if let Some(remote_profile) = self.last_punch_profiles.get_without_update(&peer).copied()
        {
            let key = PunchOutcomeKey {
                peer,
                local_generation: local_profile.generation,
                remote_generation: remote_profile.generation,
            };
            if self
                .punch_outcomes
                .get_without_update(&key)
                .is_some_and(|expiry| env.now() < *expiry)
            {
                return false;
            }
        }
        let via = self
            .gossip
            .get(&peer, env.now())
            .and_then(|advert| match &advert.reachability {
                Reachability::Coordinated { via, .. } => via
                    .iter()
                    .copied()
                    .find(|candidate| self.transport.connection_addr(candidate).is_some()),
                Reachability::Direct(_) => None,
            });
        let Some(via) = via else {
            return false;
        };
        let mut nonce = env.rng().next_u64();
        while self.punch_sessions.contains_key(&nonce) {
            nonce = env.rng().next_u64();
        }
        let request = match ConnectRequest::sign(
            nonce,
            peer,
            self.local_punch_candidates(),
            local_profile,
            self.keypair.as_ref(),
        ) {
            Ok(request) => request,
            Err(e) => {
                log::warn!("overlay: could not sign punch request for {peer}: {e}");
                return false;
            }
        };
        let raw = match OverlayFrame::connect_request(request).encode() {
            Ok(raw) => raw,
            Err(e) => {
                log::warn!("overlay: could not encode punch request for {peer}: {e}");
                return false;
            }
        };
        if !self.transport.queue_datagram_to_peer(env, &via, raw) {
            return false;
        }
        let now = env.now();
        self.punch_sessions.insert(
            nonce,
            PunchSession {
                peer,
                nonce,
                via,
                candidates: ArrayVec::new(),
                freshest: None,
                remote_profile: NatProfile::default(),
                local_profile,
                awaiting_response: true,
                dial_started: false,
                payload,
                birthday_sockets: Vec::new(),
                birthday_started: false,
                birthday_spray_sent: false,
                deadline: now + PUNCH_TIMEOUT,
                next_probe: now + PUNCH_PROBE_INTERVAL,
                probe_rounds: 0,
                assist_followup_granted: false,
                sequential_prediction: None,
                bracket_candidates: ArrayVec::new(),
            },
        );
        self.punch_attempts += 1;
        true
    }

    fn refuse_punch(&mut self, why: &str) {
        self.punch_refused += 1;
        log::debug!("overlay: refused punch signaling: {why}");
    }

    fn handle_connect_request(
        &mut self,
        env: &mut dyn OverlayEnv,
        from: SocketAddr,
        request: ConnectRequest,
    ) {
        let sender = self.transport.peer_identity(from);
        if !request.verify() || request.origin == self.local_pubkey {
            self.refuse_punch("bad request signature or self origin");
            return;
        }
        if request.target == self.local_pubkey {
            // Endpoint B only probes candidates supplied by an independently
            // signed request from an origin it can currently see in gossip.
            let Some(via) = sender else {
                self.refuse_punch("target received request off an authenticated connection");
                return;
            };
            if self.gossip.get(&request.origin, env.now()).is_none() {
                self.refuse_punch("request origin is not gossip-visible");
                return;
            }
            if self.punch_sessions.len() >= MAX_PUNCH_SESSIONS
                && !self.punch_sessions.contains_key(&request.nonce)
            {
                self.refuse_punch("session cap");
                return;
            }
            let now = env.now();
            let local_profile = self.local_nat_profile();
            self.punch_sessions.entry(request.nonce).or_insert(PunchSession {
                peer: request.origin,
                nonce: request.nonce,
                via,
                candidates: request.candidates.clone(),
                freshest: None,
                remote_profile: request.nat_profile,
                local_profile,
                awaiting_response: false,
                dial_started: false,
                payload: None,
                birthday_sockets: Vec::new(),
                birthday_started: false,
                birthday_spray_sent: false,
                deadline: now + PUNCH_TIMEOUT,
                next_probe: now,
                probe_rounds: 0,
                assist_followup_granted: false,
                sequential_prediction: None,
                bracket_candidates: ArrayVec::new(),
            });
            self.last_punch_profiles.push(request.origin, request.nat_profile);
            let birthday = self.birthday_punch
                && local_profile.birthday_punch
                && request.nat_profile.birthday_punch
                && matches!(local_profile.allocator, Some(AllocatorProfile::Random));
            if birthday {
                if let Some(session) = self.punch_sessions.get_mut(&request.nonce) {
                    session.deadline = now + BIRTHDAY_DURATION;
                }
            }
            let response = match ConnectResponse::sign(
                request.nonce,
                request.origin,
                self.local_punch_candidates(),
                self.local_nat_profile(),
                self.keypair.as_ref(),
            ) {
                Ok(response) => response,
                Err(e) => {
                    log::warn!("overlay: could not sign punch response: {e}");
                    return;
                }
            };
            if let Ok(raw) = OverlayFrame::connect_response(response).encode() {
                self.transport.queue_datagram_to_peer(env, &via, raw);
            }
            self.advance_punches(env, now);
            // Rung 3 belongs to the random-mapping side, which may be B.
            // Starting only after the signed response is queued preserves the
            // relay state the ready signal needs on its return path.
            if birthday {
                self.start_birthday(env, request.nonce);
            }
            return;
        }

        // We are the shared via. The initiating connection and the target
        // connection must both already be authenticated; no blind forwarding
        // or connection establishment is permitted here (§9).
        if sender != Some(request.origin)
            || self.transport.connection_addr(&request.target).is_none()
            || self.gossip.get(&request.target, env.now()).is_none()
        {
            self.refuse_punch("via route is not authenticated and gossip-visible");
            return;
        }
        if self.punch_forwards.len() >= MAX_PUNCH_FORWARDS
            || !self.punch_initiator_rate.check_and_increment(request.origin, env.now())
            || !self.punch_target_rate.check_and_increment(request.target, env.now())
        {
            self.refuse_punch("via rate or forwarding-state cap");
            return;
        }
        let key = (request.origin, request.nonce);
        if self.punch_forwards.contains_key(&key) {
            return;
        }
        let raw = match OverlayFrame::connect_request(request.clone()).encode() {
            Ok(raw) => raw,
            Err(e) => {
                log::debug!("overlay: malformed connect request cannot forward: {e}");
                return;
            }
        };
        if self
            .transport
            .queue_datagram_to_peer(env, &request.target, raw)
        {
            self.punch_forwards.insert(
                key,
                PunchForward {
                    target: request.target,
                    origin_profile: request.nat_profile,
                    origin_candidates: request.candidates,
                    deadline: env.now() + PUNCH_TIMEOUT,
                },
            );
        }
    }

    fn handle_connect_response(
        &mut self,
        env: &mut dyn OverlayEnv,
        from: SocketAddr,
        response: ConnectResponse,
    ) {
        let sender = self.transport.peer_identity(from);
        if !response.verify() {
            self.refuse_punch("bad response signature");
            return;
        }
        if response.target == self.local_pubkey {
            let Some(session) = self.punch_sessions.get_mut(&response.nonce) else {
                self.refuse_punch("response has no local session");
                return;
            };
            if !session.awaiting_response
                || session.peer != response.origin
                || sender != Some(session.via)
                || self.gossip.get(&response.origin, env.now()).is_none()
            {
                self.refuse_punch("response route or origin mismatch");
                return;
            }
            session.candidates = response.candidates;
            session.remote_profile = response.nat_profile;
            self.last_punch_profiles.push(response.origin, response.nat_profile);
            session.awaiting_response = false;
            let now = env.now();
            session.next_probe = now;
            let birthday = self.birthday_punch
                && session.local_profile.birthday_punch
                && matches!(session.local_profile.allocator, Some(AllocatorProfile::Random));
            if birthday {
                session.deadline = now + BIRTHDAY_DURATION;
            }
            let nonce = session.nonce;
            self.advance_punches(env, now);
            if birthday {
                self.start_birthday(env, nonce);
            }
            return;
        }

        // Relay response only if it matches a bounded request state that this
        // node created. The target is the original initiator.
        if sender != Some(response.origin) {
            self.refuse_punch("response was not sent by its signed origin");
            return;
        }
        let key = (response.target, response.nonce);
        let Some(forward) = self.punch_forwards.remove(&key) else {
            self.refuse_punch("response has no matching via state");
            return;
        };
        if forward.target != response.origin {
            self.refuse_punch("response target differs from forwarded request");
            return;
        }
        let response_profile = response.nat_profile;
        let response_candidates = response.candidates.clone();
        let response_origin = response.origin;
        if let Ok(raw) = OverlayFrame::connect_response(response).encode() {
            if !self
                .transport
                .queue_datagram_to_peer(env, &key.0, raw)
            {
                self.refuse_punch("initiator disconnected before response");
            }
        }
        self.maybe_start_assist(
            env,
            key.0,
            response_origin,
            key.1,
            forward.origin_profile,
            response_profile,
            &forward.origin_candidates,
            &response_candidates,
        );
    }

    /// Start the deterministic assisted rungs selected from both signed
    /// profiles. The observer side is the peer whose destination-sensitive
    /// mapping we need to create; the recipient gets the authenticated prflx
    /// observation or bracket. This makes the ladder work regardless of the
    /// caller's pubkey/initiator role. No helper is allocated for unsolicited
    /// gossip state.
    fn maybe_start_assist(
        &mut self,
        env: &mut dyn OverlayEnv,
        origin: Pubkey,
        target: Pubkey,
        nonce: u64,
        origin_profile: NatProfile,
        target_profile: NatProfile,
        origin_candidates: &ArrayVec<SocketAddr, MAX_PUNCH_CANDIDATES>,
        target_candidates: &ArrayVec<SocketAddr, MAX_PUNCH_CANDIDATES>,
    ) {
        // First observe the initiator against the target's exact candidate;
        // then mirror the operation for a destination-sensitive target.
        self.start_assist(
            env,
            origin,
            target,
            nonce,
            origin_profile,
            target_candidates.first().copied(),
        );
        self.start_assist(
            env,
            target,
            origin,
            nonce,
            target_profile,
            origin_candidates.first().copied(),
        );
    }

    fn start_assist(
        &mut self,
        env: &mut dyn OverlayEnv,
        observer: Pubkey,
        recipient: Pubkey,
        nonce: u64,
        profile: NatProfile,
        exact_candidate: Option<SocketAddr>,
    ) {
        if self.punch_helpers.len() >= MAX_PUNCH_HELPERS {
            return;
        }
        let Some(exact_candidate) = exact_candidate else {
            return;
        };
        let family = IpFamily::of(&exact_candidate);
        let mut kind = match profile.class {
            Some(NatClass::PortDependent) => PunchAssistKind::SamePortObservation,
            _ if matches!(profile.allocator, Some(AllocatorProfile::Sequential { .. })) => {
                PunchAssistKind::SequentialBracket
            }
            _ => return,
        };
        // Rung 1's defining operation: bind B's public destination port.
        // Rung 2 uses a random unprivileged helper port; its exact value is
        // communicated in the authenticated plan below.
        let mut requested_port = match kind {
            PunchAssistKind::SamePortObservation => exact_candidate.port(),
            PunchAssistKind::SequentialBracket => 49_152 + (env.rng().next_u32() % 16_384) as u16,
        };
        // Never ask the OS to bind a privileged port on a requester's
        // behalf. A calibrated sequential profile can still use rung 2;
        // otherwise the ladder cleanly falls through to its cached outcome.
        if requested_port < MIN_UNPRIVILEGED_PORT
            && matches!(kind, PunchAssistKind::SamePortObservation)
        {
            if matches!(profile.allocator, Some(AllocatorProfile::Sequential { .. })) {
                kind = PunchAssistKind::SequentialBracket;
                requested_port = 49_152 + (env.rng().next_u32() % 16_384) as u16;
            } else {
                return;
            }
        }
        let socket = match env.bind(Some(requested_port), family) {
            Ok(socket) => socket,
            Err(_) if matches!(kind, PunchAssistKind::SamePortObservation)
                && matches!(profile.allocator, Some(AllocatorProfile::Sequential { .. })) =>
            {
                // Busy/privileged same-port refusals fall to rung 2, never
                // retrying arbitrary binds (§6.5.1 / §9).
                kind = PunchAssistKind::SequentialBracket;
                requested_port = 49_152 + (env.rng().next_u32() % 16_384) as u16;
                match env.bind(Some(requested_port), family) {
                    Ok(socket) => socket,
                    Err(_) => return,
                }
            }
            Err(_) => return,
        };
        self.transport.register_punch_socket(socket);
        self.punch_helpers.insert(
            socket,
            PunchHelper {
                origin: observer,
                target: recipient,
                nonce,
                socket,
                kind,
                deadline: env.now() + PUNCH_TIMEOUT,
            },
        );
        if let Ok(raw) = OverlayFrame::punch_assist(
            nonce,
            observer,
            recipient,
            requested_port,
            kind,
        )
        .encode()
        {
            self.transport.queue_datagram_to_peer(env, &observer, raw);
        }
    }

    fn add_punch_candidate(session: &mut PunchSession, candidate: SocketAddr) {
        if !session.candidates.contains(&candidate) {
            let _ = session.candidates.try_push(candidate);
        }
    }

    /// A helper plan/result is authenticated by the negotiated via and
    /// belongs to the initial P5 exchange. Reserve exactly one fresh probe
    /// volley for it even if the bootstrap volley already completed; do not
    /// reset this more than once, so bad paths cannot turn into retries.
    fn schedule_assisted_followup(session: &mut PunchSession, now: Instant) {
        if !session.assist_followup_granted {
            session.assist_followup_granted = true;
            session.probe_rounds = 0;
        }
        session.next_probe = now;
    }

    fn handle_punch_assist(
        &mut self,
        env: &mut dyn OverlayEnv,
        from: SocketAddr,
        nonce: u64,
        origin: Pubkey,
        target: Pubkey,
        port: u16,
        _kind: PunchAssistKind,
    ) {
        let Some(via) = self.transport.peer_identity(from) else {
            self.refuse_punch("assist plan arrived unauthenticated");
            return;
        };
        let Some(session) = self.punch_sessions.get_mut(&nonce) else {
            self.refuse_punch("assist plan has no session");
            return;
        };
        if via != session.via
            || port < MIN_UNPRIVILEGED_PORT
        {
            self.refuse_punch("assist plan does not match negotiated via session");
            return;
        }
        if origin != self.local_pubkey || target != session.peer {
            self.refuse_punch("assist plan peers do not match negotiated session");
            return;
        }
        let Some(via_addr) = self.transport.connection_addr(&via) else {
            self.refuse_punch("assist via connection vanished");
            return;
        };
        let helper_addr = SocketAddr::new(via_addr.ip(), port);
        Self::add_punch_candidate(session, helper_addr);
        let local_is_sequential = matches!(
            session.local_profile.allocator,
            Some(AllocatorProfile::Sequential { .. })
        );
        let remote_is_sequential = matches!(
            session.remote_profile.allocator,
            Some(AllocatorProfile::Sequential { .. })
        );
        if local_is_sequential && !remote_is_sequential
            && let Some(position) = session
                .candidates
                .iter()
                .position(|candidate| *candidate == helper_addr)
        {
            // In the asymmetric rung-2 case, create the helper-observed X
            // first and the ordinary peer mapping X+stride immediately
            // after it. The recipient receives the X+stride prediction from
            // the helper and can open its filter toward a mapping that is
            // already live. For sequential↔sequential we retain the normal
            // ordering so the two reciprocal predictions compose instead.
            let helper_addr = session.candidates.remove(position);
            session.candidates.insert(0, helper_addr);
        }
        let now = env.now();
        // A helper plan is setup, not the assisted result: it must first
        // create/observe the special mapping. Preserve one fresh bounded
        // volley for the later authenticated observation or bracket, rather
        // than consuming it merely by probing the helper socket.
        session.probe_rounds = 0;
        session.next_probe = now;
        self.advance_punches(env, now);
    }

    fn handle_punch_observation(
        &mut self,
        env: &mut dyn OverlayEnv,
        from: SocketAddr,
        nonce: u64,
        origin: Pubkey,
        target: Pubkey,
        observed: SocketAddr,
    ) {
        let Some(via) = self.transport.peer_identity(from) else {
            self.refuse_punch("helper observation arrived unauthenticated");
            return;
        };
        let Some(session) = self.punch_sessions.get_mut(&nonce) else {
            self.refuse_punch("helper observation has no session");
            return;
        };
        if target != self.local_pubkey || session.peer != origin || session.via != via {
            self.refuse_punch("helper observation mismatches session");
            return;
        }
        Self::add_punch_candidate(session, observed);
        let now = env.now();
        Self::schedule_assisted_followup(session, now);
        self.advance_punches(env, now);
    }

    fn handle_punch_bracket(
        &mut self,
        env: &mut dyn OverlayEnv,
        from: SocketAddr,
        nonce: u64,
        origin: Pubkey,
        target: Pubkey,
        ip: std::net::IpAddr,
        start: u16,
        end: u16,
    ) {
        let Some(via) = self.transport.peer_identity(from) else {
            self.refuse_punch("bracket arrived unauthenticated");
            return;
        };
        let width = end.saturating_sub(start).saturating_add(1);
        if width == 0 || width > MAX_BRACKET_WIDTH {
            self.refuse_punch("bracket exceeds hard k<=32 cap");
            return;
        }
        let Some(session) = self.punch_sessions.get_mut(&nonce) else {
            self.refuse_punch("bracket has no session");
            return;
        };
        if target != self.local_pubkey || session.peer != origin || session.via != via {
            self.refuse_punch("bracket mismatches session");
            return;
        }
        if let Some(AllocatorProfile::Sequential { stride }) = session.remote_profile.allocator
            && let Some(predicted_port) = end.checked_add(stride)
        {
            // The helper's final observation is allocation X. Opening the
            // filter at X + stride creates this node's own next mapping; the
            // peer does the reciprocal calculation from our helper result.
            // That is the double-bracket composition for sequential↔
            // sequential without a range guess. Keep a bounded range only
            // as the conservative fallback when a prediction wraps.
            session.sequential_prediction = Some(SocketAddr::new(ip, predicted_port));
            session.bracket_candidates.clear();
        } else {
            for port in start..=end {
                let candidate = SocketAddr::new(ip, port);
                if !session.bracket_candidates.contains(&candidate) {
                    let _ = session.bracket_candidates.try_push(candidate);
                }
            }
        }
        let now = env.now();
        Self::schedule_assisted_followup(session, now);
        self.advance_punches(env, now);
    }

    /// Rung 3: bind exactly the configured cap of short-lived sockets and
    /// send one signed raw probe from each. Nothing happens unless the local
    /// operator opted in *and* advertised that opt-in in the signed profile.
    fn start_birthday(&mut self, env: &mut dyn OverlayEnv, nonce: u64) {
        let Some(session) = self.punch_sessions.get(&nonce) else {
            return;
        };
        if session.birthday_started
            || !self.birthday_punch
            || !session.local_profile.birthday_punch
            || !matches!(session.local_profile.allocator, Some(AllocatorProfile::Random))
        {
            return;
        }
        let Some(target) = session.candidates.first().copied() else {
            return;
        };
        let via = session.via;
        let peer = session.peer;
        let family = IpFamily::of(&target);
        let mut sockets = Vec::with_capacity(BIRTHDAY_SOCKET_CAP);
        for _ in 0..BIRTHDAY_SOCKET_CAP {
            let Ok(socket) = env.bind(None, family) else {
                break;
            };
            self.transport.register_punch_socket(socket);
            let probe = PunchProbe::sign(nonce, self.keypair.as_ref());
            if self
                .transport
                .send_punch_probe_from(env, socket, target, probe)
                .is_ok()
            {
                sockets.push(socket);
            } else {
                self.transport.unregister_punch_socket(socket);
                env.close(socket);
            }
        }
        if sockets.is_empty() {
            return;
        }
        if let Some(session) = self.punch_sessions.get_mut(&nonce) {
            session.birthday_started = true;
            session.birthday_sockets = sockets;
            session.deadline = env.now() + BIRTHDAY_DURATION;
        }
        // The target only starts its 1,024-probe spray after these mappings
        // exist. It is relayed like all P5 control traffic and is accepted
        // only by the negotiated session at the other end.
        if let Ok(raw) = (OverlayFrame::PunchBirthday {
            nonce,
            origin: self.local_pubkey,
            target: peer,
        })
        .encode()
        {
            self.transport.queue_datagram_to_peer(env, &via, raw);
        }
    }

    fn handle_punch_birthday(
        &mut self,
        env: &mut dyn OverlayEnv,
        from: SocketAddr,
        nonce: u64,
        origin: Pubkey,
        target: Pubkey,
    ) {
        let sender = self.transport.peer_identity(from);
        if target != self.local_pubkey {
            // A via forwards only an authenticated origin to a currently
            // connected target; unlike ConnectResponse it needs no extra
            // state because the target verifies its signed session profile.
            if sender == Some(origin)
                && self.transport.connection_addr(&target).is_some()
                && self.gossip.get(&target, env.now()).is_some()
            {
                if let Ok(raw) = (OverlayFrame::PunchBirthday {
                    nonce,
                    origin,
                    target,
                })
                .encode()
                {
                    self.transport.queue_datagram_to_peer(env, &target, raw);
                }
            } else {
                self.refuse_punch("birthday ready has no authenticated via route");
            }
            return;
        }
        let Some(via) = sender else {
            self.refuse_punch("birthday ready arrived unauthenticated");
            return;
        };
        let Some(session) = self.punch_sessions.get_mut(&nonce) else {
            self.refuse_punch("birthday ready has no session");
            return;
        };
        if session.peer != origin
            || session.via != via
            || session.birthday_spray_sent
            || !self.birthday_punch
            || !session.remote_profile.birthday_punch
            || !matches!(session.remote_profile.allocator, Some(AllocatorProfile::Random))
        {
            self.refuse_punch("birthday ready is not opt-in random session");
            return;
        }
        let Some(ip) = session.candidates.first().map(SocketAddr::ip) else {
            self.refuse_punch("birthday spray has no signed origin address");
            return;
        };
        session.birthday_spray_sent = true;
        session.deadline = env.now() + BIRTHDAY_DURATION;
        let probe = PunchProbe::sign(nonce, self.keypair.as_ref());
        for _ in 0..BIRTHDAY_SPRAY_CAP {
            let port = BIRTHDAY_PORT_START
                + (env.rng().next_u32() % u32::from(BIRTHDAY_PORT_WIDTH)) as u16;
            let _ = self
                .transport
                .send_punch_probe(env, SocketAddr::new(ip, port), probe.clone());
        }
    }

    /// Returns `true` when this raw probe belongs to a live helper socket and
    /// was therefore consumed before ordinary peer-session prflx handling.
    fn handle_punch_helper_probe(&mut self, env: &mut dyn OverlayEnv, event: &PunchProbeEvent) -> bool {
        let Some(helper) = self.punch_helpers.get(&event.socket) else {
            return false;
        };
        if !event.probe.verify()
            || event.probe.origin != helper.origin
            || event.probe.nonce != helper.nonce
        {
            return true;
        }
        let helper = PunchHelper {
            origin: helper.origin,
            target: helper.target,
            nonce: helper.nonce,
            socket: helper.socket,
            kind: helper.kind,
            deadline: helper.deadline,
        };
        match helper.kind {
            PunchAssistKind::SamePortObservation => {
                let frame = OverlayFrame::PunchObservation {
                    nonce: helper.nonce,
                    origin: helper.origin,
                    target: helper.target,
                    observed: event.from,
                };
                if let Ok(raw) = frame.encode() {
                    self.transport.queue_datagram_to_peer(env, &helper.target, raw);
                }
            }
            PunchAssistKind::SequentialBracket => {
                // X1 is the source of the existing authenticated connection
                // from A to the via; X2 is the helper probe source. The
                // symmetric target mapping P lies between them for a quiet
                // sequential allocator. Do not widen a noisy bracket.
                if let Some(first) = self.transport.connection_addr(&helper.origin)
                    && first.ip() == event.from.ip()
                {
                    let start = first.port().min(event.from.port());
                    let end = first.port().max(event.from.port());
                    if end.saturating_sub(start).saturating_add(1) <= MAX_BRACKET_WIDTH {
                        let frame = OverlayFrame::PunchBracket {
                            nonce: helper.nonce,
                            origin: helper.origin,
                            target: helper.target,
                            ip: event.from.ip(),
                            start,
                            end,
                        };
                        if let Ok(raw) = frame.encode() {
                            self.transport.queue_datagram_to_peer(env, &helper.target, raw);
                        }
                    }
                }
            }
        }
        true
    }

    fn advance_punches(&mut self, env: &mut dyn OverlayEnv, now: Instant) {
        let expired: Vec<u64> = self
            .punch_sessions
            .iter()
            .filter(|(_, session)| now >= session.deadline)
            .map(|(&nonce, _)| nonce)
            .collect();
        for nonce in expired {
            if let Some(session) = self.punch_sessions.remove(&nonce) {
                self.cache_punch_failure(&session, now);
                self.close_birthday_sockets(env, session.birthday_sockets, None);
            }
        }

        let mut sends: Vec<(SocketAddr, PunchProbe)> = Vec::new();
        for session in self.punch_sessions.values_mut() {
            if session.awaiting_response || now < session.next_probe {
                continue;
            }
            let random_mapping = matches!(
                session.local_profile.allocator,
                Some(AllocatorProfile::Random)
            ) || matches!(
                session.remote_profile.allocator,
                Some(AllocatorProfile::Random)
            );
            let has_public_side = matches!(session.local_profile.class, Some(NatClass::Public))
                || matches!(session.remote_profile.class, Some(NatClass::Public));
            if random_mapping
                && !has_public_side
                && !(self.birthday_punch
                    && session.local_profile.birthday_punch
                    && session.remote_profile.birthday_punch)
            {
                // Without a filtering classification we only take the
                // ordinary random-EDM path when a public endpoint is in the
                // exchange. Any restricted EIM peer needs the explicit
                // birthday opt-in; otherwise this terminates cleanly and is
                // cached instead of becoming a retry loop.
                session.next_probe = session.deadline;
                continue;
            }
            if session.probe_rounds >= MAX_PUNCH_PROBE_ROUNDS {
                // Never leave an already-due periodic deadline behind: it
                // would spin the simulator at TIMER_MIN_ADVANCE (§6.9).
                session.next_probe = session.deadline;
                continue;
            }
            session.probe_rounds += 1;
            session.next_probe = now + PUNCH_PROBE_INTERVAL;
            let probe = PunchProbe::sign(session.nonce, self.keypair.as_ref());
            if let Some(predicted) = session.sequential_prediction {
                // A sequential helper reports the last observed allocation;
                // this is the one reciprocal filter opener that matters. Do
                // not also fan over stale bootstrap hints here: every extra
                // mapping allocation would move a symmetric NAT's cursor and
                // invalidate the calibrated prediction. One packet is the
                // bounded rung-2 attempt; prflx supplies any re-aim.
                sends.push((predicted, probe));
                session.next_probe = session.deadline;
                continue;
            }
            if let Some(addr) = session.freshest {
                sends.push((addr, probe.clone()));
            }
            for &candidate in &session.candidates {
                if Some(candidate) != session.freshest {
                    sends.push((candidate, probe.clone()));
                }
            }
            for &candidate in &session.bracket_candidates {
                if Some(candidate) != session.freshest && !session.candidates.contains(&candidate) {
                    sends.push((candidate, probe.clone()));
                }
            }
        }
        for (to, probe) in sends {
            if let Err(e) = self.transport.send_punch_probe(env, to, probe) {
                log::debug!("overlay: raw punch probe to {to} failed: {e}");
            }
        }
    }

    fn handle_punch_probe(&mut self, env: &mut dyn OverlayEnv, event: PunchProbeEvent) {
        if self.handle_punch_helper_probe(env, &event) {
            return;
        }
        if !event.probe.verify() {
            self.refuse_punch("invalid raw probe signature");
            return;
        }
        let Some(session) = self.punch_sessions.get_mut(&event.probe.nonce) else {
            return;
        };
        if session.peer != event.probe.origin || session.awaiting_response {
            return;
        }
        session.freshest = Some(event.from);
        session.next_probe = env.now();
        let peer = session.peer;
        let deadline = session.deadline;
        let should_dial = self.local_pubkey < peer && !session.dial_started;
        let birthday_socket = session
            .birthday_sockets
            .contains(&event.socket)
            .then_some(event.socket);
        let payload = if should_dial && birthday_socket.is_none() {
            session.dial_started = true;
            session.payload.take()
        } else if should_dial {
            session.dial_started = true;
            None
        } else {
            None
        };
        // Reply immediately. A birthday collision must reply from the very
        // socket whose random mapping the peer just targeted; otherwise a
        // port-restricted peer only sees our unrelated primary mapping and
        // drops the crucial return probe.
        let reply = PunchProbe::sign(event.probe.nonce, self.keypair.as_ref());
        let _ = match birthday_socket {
            Some(socket) => self
                .transport
                .send_punch_probe_from(env, socket, event.from, reply),
            None => self.transport.send_punch_probe(env, event.from, reply),
        };
        if !should_dial {
            return;
        }
        let result = match (birthday_socket, payload) {
            (Some(socket), _) => self
                .transport
                .dial_expecting_from(env, socket, event.from, peer),
            (None, Some(payload)) => self
                .transport
                .queue_datagram_expecting(env, event.from, peer, payload),
            (None, None) => self.transport.dial_expecting(env, event.from, peer),
        };
        if result.is_ok() {
            self.confirming.entry(event.from).or_insert(ConfirmDial {
                expected: peer,
                deadline,
            });
        }
    }

    fn complete_punch(&mut self, env: &mut dyn OverlayEnv, peer: Pubkey) {
        let complete: Vec<u64> = self
            .punch_sessions
            .iter()
            .filter(|(_, session)| session.peer == peer)
            .map(|(&nonce, _)| nonce)
            .collect();
        for nonce in complete {
            if let Some(session) = self.punch_sessions.remove(&nonce) {
                if let Some(payload) = session.payload {
                    self.transport.queue_datagram_to_peer(env, &peer, payload);
                }
                let keep = self.transport.connection_socket(&peer);
                self.close_birthday_sockets(env, session.birthday_sockets, keep);
            }
        }
    }

    fn close_birthday_sockets(
        &mut self,
        env: &mut dyn OverlayEnv,
        sockets: Vec<SocketId>,
        keep: Option<SocketId>,
    ) {
        for socket in sockets {
            if Some(socket) == keep {
                continue;
            }
            self.transport.unregister_punch_socket(socket);
            env.close(socket);
        }
    }

    fn cache_punch_failure(&mut self, session: &PunchSession, now: Instant) {
        if session.awaiting_response {
            // No peer profile means signaling itself failed; do not cache a
            // transient via outage as a NAT verdict.
            return;
        }
        self.last_punch_profiles.push(session.peer, session.remote_profile);
        self.punch_outcomes.push(
            PunchOutcomeKey {
                peer: session.peer,
                local_generation: session.local_profile.generation,
                remote_generation: session.remote_profile.generation,
            },
            now + PUNCH_OUTCOME_TTL,
        );
    }

    fn expire_punch_forwards(&mut self, now: Instant) {
        self.punch_forwards.retain(|_, forward| now < forward.deadline);
    }

    fn expire_punch_helpers(&mut self, env: &mut dyn OverlayEnv, now: Instant) {
        let expired: Vec<SocketId> = self
            .punch_helpers
            .iter()
            .filter(|(_, helper)| now >= helper.deadline)
            .map(|(&socket, _)| socket)
            .collect();
        for socket in expired {
            if self.punch_helpers.remove(&socket).is_some() {
                self.transport.unregister_punch_socket(socket);
                env.close(socket);
            }
        }
    }

    fn is_quarantined(&self, addr: &SocketAddr) -> bool {
        self.quarantined.get_without_update(addr).is_some()
    }

    fn quarantine(&mut self, addr: SocketAddr) {
        if self.quarantined.get_without_update(&addr).is_none() {
            self.quarantined_count += 1;
        }
        self.quarantined.push(addr, ());
    }

    /// Resolve a completed connection against a pending dial-on-demand
    /// (§6.2.3 F8). Returns whether the connection was kept: a mismatch (the
    /// advertised address answered as a different identity — the advert lied)
    /// quarantines the lied-about address and drops the connection so it never
    /// becomes a fan-out target. The gated payload was already dropped
    /// undelivered by the transport's identity gate.
    fn resolve_confirm(
        &mut self,
        env: &mut dyn OverlayEnv,
        addr: SocketAddr,
        connected_pubkey: Pubkey,
    ) -> bool {
        match self.confirming.remove(&addr) {
            Some(confirm) if confirm.expected != connected_pubkey => {
                self.quarantine(addr);
                self.transport.drop_connection(env, addr);
                false
            }
            _ => true,
        }
    }

    /// Fail dial-on-demands that never connected: the advertised address did
    /// not answer, so quarantine the identity (§6.2.3).
    fn expire_confirms(&mut self, now: Instant) {
        let expired: Vec<SocketAddr> = self
            .confirming
            .iter()
            .filter(|(_, confirm)| now >= confirm.deadline)
            .map(|(&addr, _)| addr)
            .collect();
        for addr in expired {
            if self.confirming.remove(&addr).is_some() {
                self.quarantine(addr);
            }
        }
    }

    /// The node's usable peer set (§6.7): established connections plus
    /// `Direct` peers dialable on demand. `Coordinated` peers without a
    /// standing connection are excluded from this node's fan-out.
    fn usable_peers(&mut self, now: Instant, exclude: Option<Pubkey>) -> Vec<Pubkey> {
        let mut set: BTreeSet<Pubkey> = BTreeSet::new();
        for pubkey in self.transport.connected_peers() {
            // Exclude a connection at a quarantined address (§6.2.3 F8): an
            // errant connection born from a lying advert must never become a
            // fan-out target, even after the harness/QUIC re-forms it.
            match self.transport.connection_addr(&pubkey) {
                Some(addr) if self.is_quarantined(&addr) => {}
                _ => {
                    set.insert(pubkey);
                }
            }
        }
        for (pubkey, addr) in self.gossip.direct_peers(now) {
            // A `Direct` advert is a fan-out candidate only until its address
            // is proven a liar (§6.2.3 F8).
            if !self.is_quarantined(&addr) {
                set.insert(pubkey);
            }
        }
        set.remove(&self.local_pubkey);
        if let Some(exclude) = exclude {
            set.remove(&exclude);
        }
        set.into_iter().collect()
    }

    /// Send peer `pubkey` (seen at `peer_addr`) an `AddressObservation`
    /// reporting the address we observe it at (§6.2 step 1).
    fn send_address_observation(
        &mut self,
        env: &mut dyn OverlayEnv,
        pubkey: &Pubkey,
        peer_addr: SocketAddr,
    ) {
        match OverlayFrame::address_observation(peer_addr).encode() {
            Ok(raw) => {
                self.transport.queue_datagram_to_peer(env, pubkey, raw);
            }
            Err(e) => log::warn!("overlay: failed to encode address observation: {e}"),
        }
    }

    /// Re-send address observations to every connected peer (§6.2 step 1).
    /// Observations ride unreliable datagrams, so a periodic refresh covers
    /// loss and lets a peer that just connected converge its classification.
    fn broadcast_observations(&mut self, env: &mut dyn OverlayEnv) {
        for pubkey in self.transport.connected_peers() {
            if pubkey == self.local_pubkey {
                continue;
            }
            if let Some(addr) = self.transport.connection_addr(&pubkey) {
                self.send_address_observation(env, &pubkey, addr);
            }
        }
    }

    /// Requester side of §6.2.3/§6.3: run a dial-back for every Direct
    /// candidate not yet confirmed — the observed consistent mapping (P3)
    /// and the gateway-mapped port (P4). Operator-config `advertised_addr`
    /// needs no confirmation and clears any prior ones.
    fn maybe_request_dialback(&mut self, env: &mut dyn OverlayEnv) {
        if self.advertised_addr.is_some() {
            self.confirmed_direct = None;
            self.confirmed_portmap = None;
            return;
        }
        let observed = self.discovery.consistent_mapping();
        // Drop a stale confirmation when the candidate mapping changed or the
        // class is no longer endpoint-independent.
        if self.confirmed_direct != observed {
            self.confirmed_direct = None;
        }
        // §6.3: the port-mapped candidate is the granted port at our
        // OBSERVED external IP — the address the world routes to us. Behind
        // CGN the gateway's claimed IP is an inner hop; probing/advertising
        // it would be meaningless, so the observed IP is authoritative and
        // the fresh-source probe then refutes unreachable grants.
        let mut portmapped = self
            .portmap
            .as_ref()
            .and_then(|portmap| portmap.mapped_external(env.now()))
            .map(|mapped| {
                SocketAddr::new(
                    self.discovery.external_ip().unwrap_or_else(|| mapped.ip()),
                    mapped.port(),
                )
            });
        // Identical to the observed candidate ⇒ one confirmation suffices.
        if portmapped == observed {
            portmapped = None;
        }
        if self.confirmed_portmap != portmapped {
            self.confirmed_portmap = None;
        }
        if self.confirmed_direct.is_none() {
            self.request_dialback(env, CandidateKind::Observed, observed, None);
        }
        if self.confirmed_portmap.is_none() {
            let probe_port = portmapped.map(|addr| addr.port());
            self.request_dialback(env, CandidateKind::PortMapped, portmapped, probe_port);
        }
        self.maybe_request_dialback_v6(env);
    }

    /// §6.3 step 2: dial peers advertising a v6 `Direct` address over our v6
    /// socket, so they observe (and later fresh-source-probe) our v6 source.
    /// Identity-gated exactly like every dial (§6.2.3 F8); the payload is
    /// this cycle's signed advert. Stops once the v6 path is confirmed.
    fn maybe_probe_v6(&mut self, env: &mut dyn OverlayEnv, advert_raw: Vec<u8>) {
        if self.bind_v6.is_none()
            || self.advertised_addr_v6.is_some()
            || self.confirmed_v6.is_some()
        {
            return;
        }
        let now = env.now();
        let connected_v6: BTreeSet<SocketAddr> = self
            .transport
            .connections()
            .into_iter()
            .filter(|(_, addr)| addr.is_ipv6())
            .map(|(_, addr)| addr)
            .collect();
        let targets: Vec<(Pubkey, SocketAddr)> = self
            .gossip
            .peers(now)
            .into_iter()
            .filter(|advert| advert.pubkey != self.local_pubkey)
            .filter_map(|advert| {
                advert
                    .direct_addrs()
                    .iter()
                    .find(|addr| addr.is_ipv6())
                    .map(|addr| (advert.pubkey, *addr))
            })
            .filter(|(_, addr)| !connected_v6.contains(addr) && !self.is_quarantined(addr))
            .take(MAX_V6_PROBE_DIALS)
            .collect();
        for (pubkey, addr) in targets {
            if self
                .transport
                .queue_datagram_expecting(env, addr, pubkey, advert_raw.clone())
                .is_err()
            {
                continue;
            }
            self.confirming.entry(addr).or_insert(ConfirmDial {
                expected: pubkey,
                deadline: now + CONFIRM_TIMEOUT,
            });
        }
    }

    /// §6.3 v6 candidate: the consistent v6 mapping our peers observe,
    /// confirmed through a helper we hold a *v6* connection to — the request
    /// rides that connection so the helper probes our v6 source fresh.
    fn maybe_request_dialback_v6(&mut self, env: &mut dyn OverlayEnv) {
        if self.advertised_addr_v6.is_some() {
            self.confirmed_v6 = None;
            return;
        }
        let candidate = self
            .discovery_v6
            .as_ref()
            .and_then(|discovery| discovery.consistent_mapping());
        if self.confirmed_v6 != candidate {
            self.confirmed_v6 = None;
        }
        if self.confirmed_v6.is_some() {
            return;
        }
        let Some(candidate) = candidate else {
            return;
        };
        if self
            .dialback_pending
            .values()
            .any(|pending| pending.kind == CandidateKind::V6)
        {
            return;
        }
        let Some((helper, helper_addr)) = self
            .transport
            .connections()
            .into_iter()
            .find(|(pubkey, addr)| addr.is_ipv6() && *pubkey != self.local_pubkey)
        else {
            return;
        };
        let nonce = self.next_dialback_nonce;
        self.next_dialback_nonce += 1;
        match OverlayFrame::dialback_request(nonce, None).encode() {
            Ok(raw) => {
                // Address-directed so it rides the v6 connection, not the
                // identity-indexed (possibly v4) one.
                if self.transport.queue_datagram(env, helper_addr, raw).is_ok() {
                    self.dialback_pending.insert(
                        nonce,
                        DialBackPending {
                            helper,
                            kind: CandidateKind::V6,
                            candidate,
                            deadline: env.now() + DIALBACK_TIMEOUT,
                        },
                    );
                }
            }
            Err(e) => log::warn!("overlay: failed to encode v6 dial-back request: {e}"),
        }
    }

    /// Ask a connected helper to fresh-source-probe `candidate` (§6.2.3).
    /// At most one in-flight confirmation per candidate kind.
    fn request_dialback(
        &mut self,
        env: &mut dyn OverlayEnv,
        kind: CandidateKind,
        candidate: Option<SocketAddr>,
        probe_port: Option<u16>,
    ) {
        let Some(candidate) = candidate else {
            return;
        };
        if self.dialback_pending.values().any(|pending| pending.kind == kind) {
            return;
        }
        let Some(helper) = self
            .transport
            .connected_peers()
            .into_iter()
            .find(|pubkey| *pubkey != self.local_pubkey)
        else {
            return;
        };
        let nonce = self.next_dialback_nonce;
        self.next_dialback_nonce += 1;
        match OverlayFrame::dialback_request(nonce, probe_port).encode() {
            Ok(raw) => {
                if self.transport.queue_datagram_to_peer(env, &helper, raw) {
                    self.dialback_pending.insert(
                        nonce,
                        DialBackPending {
                            helper,
                            kind,
                            candidate,
                            deadline: env.now() + DIALBACK_TIMEOUT,
                        },
                    );
                }
            }
            Err(e) => log::warn!("overlay: failed to encode dial-back request: {e}"),
        }
    }

    /// Helper side of §6.2.3: dial the requester's *own* observed source from
    /// a fresh short-lived socket, so its restricted filtering is genuinely
    /// exercised. Hardened per §9: per-requester rate limit, no privileged
    /// ports, and — because the target IP is pinned to the source of this
    /// very request (only the port may be overridden for a §6.3 gateway-
    /// mapped candidate on that same NAT) — no reflection at third parties.
    fn handle_dialback_request(
        &mut self,
        env: &mut dyn OverlayEnv,
        from: SocketAddr,
        nonce: u64,
        probe_port: Option<u16>,
    ) {
        let Some(requester) = self.transport.peer_identity(from) else {
            return;
        };
        let now = env.now();
        if !self.dialback_rate.check_and_increment(requester, now)
            || self.helper_probes.len() >= MAX_HELPER_PROBES
        {
            self.dialbacks_refused += 1;
            self.send_dialback_result(env, &requester, nonce, false);
            return;
        }
        // Reflection-safe: probing the request's own source address; a port
        // override stays on that host. Using `from` (not the pubkey-indexed
        // connection) keeps multi-connection peers correct — a request over
        // the v6 connection targets the v6 source (§6.3).
        let target = SocketAddr::new(from.ip(), probe_port.unwrap_or_else(|| from.port()));
        if target.port() < MIN_UNPRIVILEGED_PORT {
            self.dialbacks_refused += 1;
            self.send_dialback_result(env, &requester, nonce, false);
            return;
        }
        let socket = match env.bind(None, IpFamily::of(&target)) {
            Ok(socket) => socket,
            Err(e) => {
                log::debug!("overlay: dial-back helper bind failed: {e}");
                self.send_dialback_result(env, &requester, nonce, false);
                return;
            }
        };
        match self.transport.start_probe(env, socket, target) {
            Ok(probe) => {
                self.helper_probes.insert(
                    probe,
                    HelperProbe {
                        requester,
                        nonce,
                        socket,
                        deadline: now + DIALBACK_TIMEOUT,
                    },
                );
            }
            Err(e) => {
                log::debug!("overlay: dial-back probe start failed: {e}");
                env.close(socket);
                self.send_dialback_result(env, &requester, nonce, false);
            }
        }
    }

    /// A helper probe concluded: report success only when the candidate
    /// answered with the requester's expected identity (§6.2.3), then reclaim
    /// the short-lived socket (§9).
    fn on_probe_event(&mut self, env: &mut dyn OverlayEnv, event: ProbeEvent) {
        let Some(probe) = self.helper_probes.remove(&event.probe) else {
            return;
        };
        let ok = event.identity == Some(probe.requester);
        log::debug!("overlay: dial-back probe to {} resolved ok={ok}", event.addr);
        self.send_dialback_result(env, &probe.requester, probe.nonce, ok);
        self.transport.close_probe(env, event.probe);
        env.close(probe.socket);
    }

    /// Requester side: record a helper's verdict. A success confirms the
    /// probed candidate as a Direct address of its kind.
    fn handle_dialback_result(&mut self, nonce: u64, ok: bool) {
        if let Some(pending) = self.dialback_pending.remove(&nonce)
            && ok
        {
            match pending.kind {
                CandidateKind::Observed => self.confirmed_direct = Some(pending.candidate),
                CandidateKind::PortMapped => self.confirmed_portmap = Some(pending.candidate),
                CandidateKind::V6 => self.confirmed_v6 = Some(pending.candidate),
            }
        }
    }

    fn send_dialback_result(
        &mut self,
        env: &mut dyn OverlayEnv,
        requester: &Pubkey,
        nonce: u64,
        ok: bool,
    ) {
        match OverlayFrame::dialback_result(nonce, ok).encode() {
            Ok(raw) => {
                self.transport.queue_datagram_to_peer(env, requester, raw);
            }
            Err(e) => log::warn!("overlay: failed to encode dial-back result: {e}"),
        }
    }

    /// Reclaim timed-out dial-backs on both sides (§6.9 deadline discipline).
    fn expire_dialbacks(&mut self, env: &mut dyn OverlayEnv, now: Instant) {
        let expired: Vec<u64> = self
            .dialback_pending
            .iter()
            .filter(|(_, pending)| now >= pending.deadline)
            .map(|(&nonce, _)| nonce)
            .collect();
        for nonce in expired {
            self.dialback_pending.remove(&nonce);
        }
        let expired_probes: Vec<ProbeId> = self
            .helper_probes
            .iter()
            .filter(|(_, probe)| now >= probe.deadline)
            .map(|(&id, _)| id)
            .collect();
        for probe in expired_probes {
            let helper = self.helper_probes.remove(&probe).expect("collected above");
            self.send_dialback_result(env, &helper.requester, helper.nonce, false);
            self.transport.close_probe(env, probe);
            env.close(helper.socket);
        }
    }

    /// The §6.2.3 dial-back-confirmed Direct candidate, if any. Oracle surface.
    #[allow(dead_code)]
    pub fn confirmed_direct(&self) -> Option<SocketAddr> {
        self.confirmed_direct
    }

    /// The §6.3 dial-back-confirmed port-mapped candidate. Oracle surface.
    #[allow(dead_code)]
    pub fn confirmed_portmap(&self) -> Option<SocketAddr> {
        self.confirmed_portmap
    }

    /// The §6.3 dial-back-confirmed v6 address. Oracle surface.
    #[allow(dead_code)]
    pub fn confirmed_v6(&self) -> Option<SocketAddr> {
        self.confirmed_v6
    }

    /// The gateway-granted external mapping (unconfirmed), if a lease is
    /// live. Oracle surface.
    #[allow(dead_code)]
    pub fn portmap_mapped(&self, now: Instant) -> Option<SocketAddr> {
        self.portmap
            .as_ref()
            .and_then(|portmap| portmap.mapped_external(now))
    }

    /// A live §6.3 v6 pinhole lease exists. Oracle surface.
    #[allow(dead_code)]
    pub fn portmap_pinhole_active(&self, now: Instant) -> bool {
        self.portmap
            .as_ref()
            .is_some_and(|portmap| portmap.pinhole_active(now))
    }

    /// (malformed gateway responses dropped, gateway denials). Oracle surface.
    #[allow(dead_code)]
    pub fn portmap_counters(&self) -> (u64, u64) {
        self.portmap
            .as_ref()
            .map(|portmap| (portmap.malformed_responses, portmap.denials))
            .unwrap_or((0, 0))
    }

    /// Dial-back requests this node refused as a helper (rate/port/caps, §9).
    #[allow(dead_code)]
    pub fn dialbacks_refused(&self) -> u64 {
        self.dialbacks_refused
    }

    /// Fresh-source helper probes currently in flight. Oracle surface for the
    /// short-lived-socket bound (§9).
    #[allow(dead_code)]
    pub fn active_helper_probes(&self) -> usize {
        self.helper_probes.len()
    }

    /// Identities quarantined for a lying `Direct` advert (§6.2.3 F8).
    /// Oracle surface.
    #[allow(dead_code)]
    pub fn quarantined_count(&self) -> u64 {
        self.quarantined_count
    }

    /// The §6.2 NAT class inferred from peer observations, or `None` while
    /// observations cannot yet discriminate. Oracle/diagnostic surface.
    #[allow(dead_code)]
    pub fn nat_class(&self) -> Option<NatClass> {
        self.discovery.classify()
    }

    /// The §6.2 allocator-discipline calibration for the current NAT
    /// generation (recorded for P5; nothing consumes it in P3).
    #[allow(dead_code)]
    pub fn calibrated_allocator(&mut self) -> Option<AllocatorProfile> {
        self.discovery.calibrate()
    }

    /// The port-tagged `observed` hints this node would advertise in a
    /// `Coordinated` reachability (§6.1/§12-Q3). Oracle surface.
    #[allow(dead_code)]
    pub fn observed_hints(&self) -> ArrayVec<PortTaggedAddr, MAX_ADVERT_ADDRS> {
        self.discovery.observed_hints()
    }

    /// The reachability this node advertises (nat-traversal.md
    /// §6.1/§6.2/§6.3/§7):
    ///  - operator-configured `advertised_addr` wins;
    ///  - else a dial-back-confirmed candidate advertises `Direct` — the
    ///    observed mapping (Public confirms its bind, full-cone its
    ///    external) or, failing that, the confirmed port-mapped address
    ///    (§6.3 upgrades restricted/symmetric homes with a working gateway);
    ///  - else `Coordinated`, whose `observed` hints follow the §12-Q3 flavor
    ///    policy: fully symmetric advertises none (per-destination ports are
    ///    noise), every other flavor advertises port-tagged hints; `via`
    ///    carries connected public peers.
    fn compute_reachability(&self) -> Reachability {
        let v4 = self
            .advertised_addr
            .or(self.confirmed_direct)
            .or(self.confirmed_portmap);
        // §6.3: the v6 address rides alongside v4, listed first — peers
        // prefer the NAT-free path. Never an unconfirmed v6 (§4 caution).
        let v6 = self.advertised_addr_v6.or(self.confirmed_v6);
        if v4.is_some() || v6.is_some() {
            let mut addrs = ArrayVec::new();
            addrs.extend(v6);
            addrs.extend(v4);
            return Reachability::Direct(addrs);
        }
        let observed = match self.discovery.classify() {
            Some(NatClass::Symmetric) => ArrayVec::new(),
            _ => self.discovery.observed_hints(),
        };
        let mut via = ArrayVec::new();
        for pubkey in self.transport.connected_peers() {
            if pubkey != self.local_pubkey && via.len() < MAX_ADVERT_VIA {
                via.push(pubkey);
            }
        }
        Reachability::Coordinated { observed, via }
    }

    /// Sign and flood this cycle's advert; returns the encoded frame so the
    /// v6 self-discovery dial can carry it as its payload (§6.3).
    fn advertise(&mut self, env: &mut dyn OverlayEnv) -> Option<Vec<u8>> {
        self.advert_seq += 1;
        let reachability = self.compute_reachability();
        let advert = PeerAdvert {
            pubkey: self.local_pubkey,
            advert_seq: self.advert_seq,
            ttl_ms: self.advert_ttl_ms,
            reachability,
            repair: self.repair,
        };
        let signed = match SignedPeerAdvert::sign(advert, &self.keypair) {
            Ok(signed) => signed,
            Err(e) => {
                log::warn!("overlay: failed to sign advert: {e}");
                return None;
            }
        };
        let raw = match OverlayFrame::peer_advertisement(signed).encode() {
            Ok(raw) => raw,
            Err(e) => {
                log::warn!("overlay: failed to encode advert: {e}");
                return None;
            }
        };

        for pubkey in self.transport.connected_peers() {
            if pubkey != self.local_pubkey {
                self.transport
                    .queue_datagram_to_peer(env, &pubkey, raw.clone());
            }
        }
        // Bootstrap: static peers are dialed by address until the handshake
        // yields their identity (§6.2: static peers must be Direct nodes).
        for addr in self.static_peers.clone() {
            if self.transport.peer_identity(addr).is_none()
                && let Err(e) = self.transport.queue_datagram(env, addr, raw.clone())
            {
                log::warn!("overlay: failed to reach static peer {addr}: {e}");
            }
        }
        Some(raw)
    }

    fn push_event(&mut self, event: CoreEvent) {
        if self.events.len() >= MAX_CORE_EVENTS {
            self.events.pop_front();
            log::debug!("overlay: core event queue full ({MAX_CORE_EVENTS}); dropping oldest");
        }
        self.events.push_back(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn punch_outcome_cache_is_keyed_by_both_nat_generations() {
        let peer = Pubkey::new_unique();
        let old = PunchOutcomeKey {
            peer,
            local_generation: Some("198.51.100.10".parse().unwrap()),
            remote_generation: Some("198.51.100.11".parse().unwrap()),
        };
        let local_rebound = PunchOutcomeKey {
            local_generation: Some("198.51.100.12".parse().unwrap()),
            ..old
        };
        let remote_rebound = PunchOutcomeKey {
            remote_generation: Some("198.51.100.13".parse().unwrap()),
            ..old
        };
        let mut cache = LruBTreeMap::new(4);
        cache.push(old, Instant::now() + PUNCH_OUTCOME_TTL);

        assert!(cache.get_without_update(&old).is_some());
        assert!(cache.get_without_update(&local_rebound).is_none());
        assert!(cache.get_without_update(&remote_rebound).is_none());
    }
}

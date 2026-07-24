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
    packet::OverlayFrame,
    portmap::{PortMapConfig, PortMapper},
    repair::{
        self, MAX_REPAIR_REQ_WIRE, MAX_REPAIR_REQUESTS_PER_SECOND, MAX_REPAIR_RESP_WIRE,
        RepairPeerEntry, RepairRateLimiter, RepairReq,
    },
    transport::{
        OverlayStreamId, OverlayTransport, ProbeEvent, ProbeId, StreamEvent, TransportEvent,
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

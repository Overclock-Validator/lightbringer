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
    env::{OverlayEnv, SocketId},
    gossip::{
        AdvertOutcome, LightbringerGossip, MAX_ADVERT_VIA, PeerAdvert, Reachability,
        RepairEndpoint, SignedPeerAdvert,
    },
    packet::OverlayFrame,
    repair::{
        self, MAX_REPAIR_REQ_WIRE, MAX_REPAIR_REQUESTS_PER_SECOND, MAX_REPAIR_RESP_WIRE,
        RepairPeerEntry, RepairRateLimiter, RepairReq,
    },
    transport::{OverlayStreamId, OverlayTransport, StreamEvent, TransportEvent},
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
    tree: TurbineTree,
    static_peers: Vec<SocketAddr>,
    advertised_addr: Option<SocketAddr>,
    repair: RepairEndpoint,
    advert_ttl_ms: u32,
    advert_seq: u64,
    next_advert: Instant,
    seen_shreds: LruBTreeMap<u64, ()>,
    outbound_repairs: BTreeMap<OverlayStreamId, OutboundRepair>,
    inbound_repairs: BTreeMap<OverlayStreamId, InboundRepair>,
    repair_rate: RepairRateLimiter,
    dropped_unreachable: u64,
    invalid_adverts: u64,
    repairs_refused: u64,
    repairs_malformed: u64,
    events: VecDeque<CoreEvent>,
}

impl<T: OverlayTransport> OverlayCore<T> {
    pub fn new(transport: T, config: &OverlayConfig, keypair: Arc<Keypair>, now: Instant) -> Self {
        let local_pubkey = keypair.pubkey();
        Self {
            mode: config.mode,
            transport,
            local_pubkey,
            keypair,
            gossip: LightbringerGossip::new(config.peer_ttl()),
            tree: TurbineTree::new(local_pubkey, config.fanout),
            static_peers: config.static_peers.clone(),
            advertised_addr: config.advertised_addr,
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
            dropped_unreachable: 0,
            invalid_adverts: 0,
            repairs_refused: 0,
            repairs_malformed: 0,
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
        self.transport.on_datagram(env, socket, from, datagram);
        self.pump(env);
    }

    /// Fire due deadlines. Safe to call early; deadlines are re-checked.
    pub fn on_timer(&mut self, env: &mut dyn OverlayEnv) {
        self.transport.on_timer(env);
        let now = env.now();
        if now >= self.next_advert {
            self.next_advert = now + ADVERT_INTERVAL;
            self.advertise(env);
        }
        self.expire_repairs(env, now);
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
        for repair in self.outbound_repairs.values() {
            deadline = deadline.min(repair.deadline);
        }
        for repair in self.inbound_repairs.values() {
            deadline = deadline.min(repair.deadline);
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
        while let Some(event) = self.transport.poll_event() {
            let event = match event {
                TransportEvent::Connected { peer, pubkey } => {
                    CoreEvent::PeerConnected { peer, pubkey }
                }
                TransportEvent::Disconnected { peer, reason } => {
                    CoreEvent::PeerDisconnected { peer, reason }
                }
            };
            self.push_event(event);
        }
        while let Some((from, raw)) = self.transport.poll_inbound() {
            self.handle_frame(env, from, raw);
        }
        while let Some(event) = self.transport.poll_stream_event() {
            self.handle_stream_event(env, event);
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
        }
    }

    /// §6.1's single send choke point: an existing connection is always
    /// preferred; otherwise only `Reachability::Direct` peers are dialed;
    /// everything else is dropped and counted. Nothing in the overlay dials
    /// an address that was not either configured or advertised as dialable.
    fn send_to_peer(&mut self, env: &mut dyn OverlayEnv, pubkey: Pubkey, raw: Vec<u8>) {
        if self.transport.connection_addr(&pubkey).is_some() {
            self.transport.queue_datagram_to_peer(env, &pubkey, raw);
            return;
        }
        let dial_addr = self
            .gossip
            .get(&pubkey, env.now())
            .and_then(|advert| advert.direct_addrs().first().copied());
        match dial_addr {
            Some(addr) => {
                if let Err(e) = self.transport.queue_datagram(env, addr, raw) {
                    log::warn!("overlay: failed to dial {pubkey} at {addr}: {e}");
                }
            }
            None => {
                self.dropped_unreachable += 1;
                log::debug!("overlay: no route to {pubkey}; dropped");
            }
        }
    }

    /// The node's usable peer set (§6.7): established connections plus
    /// `Direct` peers dialable on demand. `Coordinated` peers without a
    /// standing connection are excluded from this node's fan-out.
    fn usable_peers(&mut self, now: Instant, exclude: Option<Pubkey>) -> Vec<Pubkey> {
        let mut set: BTreeSet<Pubkey> = self.transport.connected_peers().into_iter().collect();
        for (pubkey, _) in self.gossip.direct_peers(now) {
            set.insert(pubkey);
        }
        set.remove(&self.local_pubkey);
        if let Some(exclude) = exclude {
            set.remove(&exclude);
        }
        set.into_iter().collect()
    }

    fn advertise(&mut self, env: &mut dyn OverlayEnv) {
        self.advert_seq += 1;
        let reachability = match self.advertised_addr {
            Some(addr) => {
                let mut addrs = ArrayVec::new();
                addrs.push(addr);
                Reachability::Direct(addrs)
            }
            None => {
                let mut via = ArrayVec::new();
                for pubkey in self.transport.connected_peers() {
                    if pubkey != self.local_pubkey && via.len() < MAX_ADVERT_VIA {
                        via.push(pubkey);
                    }
                }
                Reachability::Coordinated {
                    observed: ArrayVec::new(),
                    via,
                }
            }
        };
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
                return;
            }
        };
        let raw = match OverlayFrame::peer_advertisement(signed).encode() {
            Ok(raw) => raw,
            Err(e) => {
                log::warn!("overlay: failed to encode advert: {e}");
                return;
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
    }

    fn push_event(&mut self, event: CoreEvent) {
        if self.events.len() >= MAX_CORE_EVENTS {
            self.events.pop_front();
            log::debug!("overlay: core event queue full ({MAX_CORE_EVENTS}); dropping oldest");
        }
        self.events.push_back(event);
    }
}

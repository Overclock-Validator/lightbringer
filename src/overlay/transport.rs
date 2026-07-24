use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    fmt,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use bytes::{Bytes, BytesMut};
use quinn_proto::{
    ClientConfig as QuicClientConfig, Connection, ConnectionEvent, ConnectionHandle,
    ConnectionIdGenerator, DatagramEvent, Dir, Endpoint, EndpointConfig, Event, IdleTimeout,
    ReadError, ServerConfig as QuicServerConfig, Transmit, TransportConfig, VarInt,
    WriteError, crypto::HmacKey,
};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use rustls::{
    DigitallySignedStruct, DistinguishedName, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use solana_sdk::pubkey::Pubkey;

use super::{
    env::{OverlayEnv, SocketId},
    identity::{OverlayIdentity, pubkey_from_certificate},
};

const MAX_DATAGRAMS_PER_TRANSMIT: usize = 1;
const UDP_BUFFER_SIZE: usize = 65_535;
const OVERLAY_SERVER_NAME: &str = "localhost";
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Fixed QUIC path MTU (MTU discovery is disabled): the IPv6 minimum, safe
/// on any path. The resulting datagram budget is 1280 − 38 (QUIC 1-RTT +
/// datagram-frame overhead) = 1242 B, which carries a merkle *data* shred
/// (1203 B payload → 1227 B v1 frame) but NOT the 1228 B shred maximum
/// (coding shreds → 1252 B frame; those need ≥1290). See nat-traversal.md
/// §8 and the sim MTU regression tests.
pub const OVERLAY_INITIAL_MTU: u16 = 1280;
const MAX_CONNECTIONS: usize = 1024;
const MAX_PENDING_DATAGRAMS: usize = 1024;
const MAX_INBOUND_FRAMES: usize = 8192;
const MAX_TRANSPORT_EVENTS: usize = 1024;
const MAX_STREAM_EVENTS: usize = 8192;
/// Total live stream handles across all connections; per-connection inbound
/// concurrency is additionally capped by [`MAX_CONCURRENT_BIDI_STREAMS`].
const MAX_STREAM_STATES: usize = 4096;
/// Per-connection inbound bidi stream cap (QUIC flow control refuses the
/// excess remotely, before it costs us state).
const MAX_CONCURRENT_BIDI_STREAMS: u32 = 64;
/// Live §6.2.3 dial-back probes across all helper sockets. Small: the core
/// rate-limits helper binds per requester and reclaims each probe promptly.
const MAX_PROBES: usize = 256;
const MAX_PROBE_EVENTS: usize = 1024;
const SEEDED_CID_LEN: usize = 8;

/// Construction-time knobs for the QUIC transport. Production uses
/// `TransportOptions::default()`; the simulator overrides the seeding fields
/// so every source of transport randomness derives from the run seed
/// (nat-traversal.md §6.9) and the timing fields for NAT-timeout scenarios.
pub struct TransportOptions {
    /// QUIC keepalive; holds NAT mappings (and thus a home node's entire
    /// participation) alive. See nat-traversal.md §6.6 (fixes F7).
    pub keep_alive_interval: Option<Duration>,
    pub max_idle_timeout: Option<Duration>,
    /// Fixed path MTU (MTU discovery is disabled). Defaults to
    /// [`OVERLAY_INITIAL_MTU`]; `None` keeps quinn's 1200-byte default.
    pub initial_mtu: Option<u16>,
    /// Seeds quinn's endpoint-internal RNG.
    pub rng_seed: Option<[u8; 32]>,
    /// Seeds local connection-id generation.
    pub cid_seed: Option<u64>,
    /// Deterministic stateless-reset key.
    pub reset_key: Option<Arc<dyn HmacKey>>,
    /// rustls provider override (seeded `SecureRandom` in the simulator).
    pub crypto_provider: Option<Arc<CryptoProvider>>,
}

impl Default for TransportOptions {
    fn default() -> Self {
        Self {
            keep_alive_interval: Some(KEEP_ALIVE_INTERVAL),
            max_idle_timeout: Some(MAX_IDLE_TIMEOUT),
            initial_mtu: Some(OVERLAY_INITIAL_MTU),
            rng_seed: None,
            cid_seed: None,
            reset_key: None,
            crypto_provider: None,
        }
    }
}

#[derive(Clone, Debug)]
pub enum TransportEvent {
    Connected {
        peer: SocketAddr,
        pubkey: Option<Pubkey>,
    },
    Disconnected {
        peer: SocketAddr,
        reason: String,
    },
}

/// Handle for a §6.2.3 fresh-source dial-back probe, unique for the life of
/// the transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProbeId(pub u64);

/// Outcome of a fresh-source dial-back probe (nat-traversal.md §6.2.3): the
/// candidate answered with `identity` (success only when it matches the
/// expected node) or the handshake never completed (`None`).
#[derive(Clone, Copy, Debug)]
pub struct ProbeEvent {
    pub probe: ProbeId,
    pub addr: SocketAddr,
    pub identity: Option<Pubkey>,
}

/// Handle for a bidirectional stream, unique for the life of the transport
/// (never reused, even across reconnects to the same peer).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OverlayStreamId(pub u64);

impl fmt::Display for OverlayStreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stream#{}", self.0)
    }
}

/// Stream lifecycle, polled sans-IO like every other transport output
/// (nat-traversal.md §6.4/§6.9). Data arrives ordered; a `Finished` event
/// means every byte of the peer's send side has already been surfaced.
#[derive(Clone, Debug)]
pub enum StreamEvent {
    /// The remote peer opened a bidirectional stream toward us.
    Opened {
        stream: OverlayStreamId,
        peer: Pubkey,
    },
    /// Ordered bytes received on the stream.
    Data {
        stream: OverlayStreamId,
        bytes: Vec<u8>,
    },
    /// Clean remote FIN.
    Finished { stream: OverlayStreamId },
    /// The stream (or its connection) died without a clean remote FIN.
    Failed { stream: OverlayStreamId },
}

/// High seam per nat-traversal.md §6.9: the connection/datagram/stream
/// surface the overlay core programs against. `OverlayQuicTransport` is the
/// real implementation; protocol-scale simulation substitutes an in-memory
/// fake (`sim::highseam::MemTransport`). Bidirectional streams carry the
/// overlay repair sub-protocol (§6.4); datagrams carry everything else.
pub trait OverlayTransport {
    /// Queue an unreliable datagram to `to`, dialing if no connection exists.
    fn queue_datagram(&mut self, env: &mut dyn OverlayEnv, to: SocketAddr, payload: Vec<u8>)
    -> Result<()>;
    /// Feed a UDP datagram received on local socket `socket`.
    fn on_datagram(
        &mut self,
        env: &mut dyn OverlayEnv,
        socket: SocketId,
        from: SocketAddr,
        datagram: &[u8],
    );
    /// Fire due timers. Safe to call early; expiry deadlines are re-checked.
    fn on_timer(&mut self, env: &mut dyn OverlayEnv);
    fn poll_timeout(&mut self) -> Option<Instant>;
    /// Pop the next application datagram received from a peer.
    fn poll_inbound(&mut self) -> Option<(SocketAddr, Vec<u8>)>;
    fn poll_event(&mut self) -> Option<TransportEvent>;
    /// TLS-verified Ed25519 identity bound to the connection with `peer`.
    fn peer_identity(&self, peer: SocketAddr) -> Option<Pubkey>;
    /// Queue a datagram on the established connection with `pubkey`.
    /// Returns false (without dialing) when no such connection exists —
    /// dialing is the caller's decision, gated on `Reachability::Direct`
    /// (the §6.1 send_to_peer choke point lives in the core).
    fn queue_datagram_to_peer(
        &mut self,
        env: &mut dyn OverlayEnv,
        pubkey: &Pubkey,
        payload: Vec<u8>,
    ) -> bool;
    /// Address of the established connection with `pubkey`, if any.
    fn connection_addr(&self, pubkey: &Pubkey) -> Option<SocketAddr>;
    /// TLS-verified identities of all established connections.
    fn connected_peers(&self) -> Vec<Pubkey>;
    /// Open a bidirectional stream on the established connection with
    /// `pubkey` (overlay repair, §6.4). Returns `None` when no connection
    /// exists or stream limits are exhausted — dialing is never implied.
    fn open_stream(&mut self, pubkey: &Pubkey) -> Option<OverlayStreamId>;
    /// Queue bytes on the stream's send side; flushed as flow control
    /// allows. Returns false when the handle is no longer live.
    fn write_stream(
        &mut self,
        env: &mut dyn OverlayEnv,
        stream: OverlayStreamId,
        bytes: &[u8],
    ) -> bool;
    /// FIN the send side once every queued byte has flushed.
    fn finish_stream(&mut self, env: &mut dyn OverlayEnv, stream: OverlayStreamId);
    /// Tear the stream down in both directions (refusals, timeouts). No
    /// event is emitted for a locally reset stream.
    fn reset_stream(&mut self, env: &mut dyn OverlayEnv, stream: OverlayStreamId);
    fn poll_stream_event(&mut self) -> Option<StreamEvent>;
    /// Identity-gated dial-on-demand (§6.2.3 F8 closure): dial `to` and queue
    /// `payload`, but release it only once the connection authenticates as
    /// `expected`. A mismatch (a lying `Direct` advert) drops the payload
    /// undelivered, so it never reaches the victim — the send choke point can
    /// dial an advertised address without trusting the advert's identity
    /// claim. Used for the first send to an unconnected `Direct` peer;
    /// established connections take payload directly via
    /// [`Self::queue_datagram_to_peer`].
    fn queue_datagram_expecting(
        &mut self,
        env: &mut dyn OverlayEnv,
        to: SocketAddr,
        expected: Pubkey,
        payload: Vec<u8>,
    ) -> Result<()>;
    /// Start a §6.2.3 fresh-source dial-back probe: a one-shot QUIC handshake
    /// to `addr` egressing from helper socket `socket` (bound fresh, so a
    /// candidate's restricted filtering is genuinely exercised). Isolated
    /// from the main connection table so it coexists with an existing
    /// connection to the same address. The outcome arrives via
    /// [`Self::poll_probe_event`].
    fn start_probe(
        &mut self,
        env: &mut dyn OverlayEnv,
        socket: SocketId,
        addr: SocketAddr,
    ) -> Result<ProbeId>;
    fn poll_probe_event(&mut self) -> Option<ProbeEvent>;
    /// Tear down a probe connection; the caller closes its socket separately.
    fn close_probe(&mut self, env: &mut dyn OverlayEnv, probe: ProbeId);
    /// Drop the connection at `addr` without emitting a `Disconnected` event
    /// (a §6.2.3 identity-mismatch on a receiver-side confirm-dial: the peer
    /// that answered is not the advertised identity, so we must not keep it
    /// as a fan-out target). A no-op if no such connection exists.
    fn drop_connection(&mut self, env: &mut dyn OverlayEnv, addr: SocketAddr);
}

pub struct OverlayQuicTransport {
    socket: SocketId,
    endpoint: Endpoint,
    client_config: QuicClientConfig,
    connections: BTreeMap<SocketAddr, QuicConnection>,
    /// Established connections indexed by TLS-verified identity; ordered so
    /// peer walks are deterministic under simulation.
    by_pubkey: BTreeMap<Pubkey, SocketAddr>,
    handles: HashMap<ConnectionHandle, SocketAddr>,
    inbound_frames: VecDeque<(SocketAddr, Vec<u8>)>,
    events: VecDeque<TransportEvent>,
    stream_events: VecDeque<StreamEvent>,
    stream_states: BTreeMap<OverlayStreamId, StreamState>,
    next_stream: u64,
    /// §6.2.3 fresh-source dial-back probes, isolated from `connections` so a
    /// probe can target an address we already hold a connection to. Each
    /// egresses from its own helper socket.
    probes: BTreeMap<ProbeId, ProbeConn>,
    probe_handles: HashMap<ConnectionHandle, ProbeId>,
    probe_sockets: BTreeSet<SocketId>,
    probe_events: VecDeque<ProbeEvent>,
    next_probe: u64,
    endpoint_buf: Vec<u8>,
    transmit_buf: Vec<u8>,
}

/// An isolated dial-back probe connection (§6.2.3). Egresses from `socket`
/// (a fresh helper bind) so the candidate's filtering is exercised against a
/// source it has never been primed with.
struct ProbeConn {
    handle: ConnectionHandle,
    conn: Connection,
    socket: SocketId,
    remote: SocketAddr,
    /// A terminal outcome has already been reported.
    resolved: bool,
}

struct QuicConnection {
    handle: ConnectionHandle,
    conn: Connection,
    established: bool,
    peer_pubkey: Option<Pubkey>,
    pending: VecDeque<Vec<u8>>,
    /// §6.2.3 F8 identity gate: when set, `pending` is released only if the
    /// verified peer identity matches; a mismatch drops it (a lying advert).
    expect_pubkey: Option<Pubkey>,
    /// Live streams on this connection, quinn id → transport handle.
    streams: BTreeMap<quinn_proto::StreamId, OverlayStreamId>,
}

struct StreamState {
    peer_addr: SocketAddr,
    quic_id: quinn_proto::StreamId,
    /// Send-side bytes quinn refused (flow control); retried on `Writable`.
    send_buf: Vec<u8>,
    /// FIN requested; applied once `send_buf` drains.
    fin_pending: bool,
    /// FIN handed to quinn (delivery from here on is quinn's problem).
    fin_done: bool,
    /// Remote send side finished or failed; no more inbound bytes.
    recv_done: bool,
}

impl OverlayQuicTransport {
    pub fn new(
        socket: SocketId,
        identity: &OverlayIdentity,
        options: &TransportOptions,
    ) -> Result<Self> {
        let transport_config = overlay_transport_config(options);
        let server_config = overlay_server_config(identity, options, transport_config.clone())?;
        let client_config = overlay_client_config(identity, options, transport_config)?;

        Ok(Self {
            socket,
            endpoint: Endpoint::new(
                Arc::new(overlay_endpoint_config(options)),
                Some(Arc::new(server_config)),
                false,
                options.rng_seed,
            ),
            client_config,
            connections: BTreeMap::new(),
            by_pubkey: BTreeMap::new(),
            handles: HashMap::new(),
            inbound_frames: VecDeque::new(),
            events: VecDeque::new(),
            stream_events: VecDeque::new(),
            stream_states: BTreeMap::new(),
            next_stream: 0,
            probes: BTreeMap::new(),
            probe_handles: HashMap::new(),
            probe_sockets: BTreeSet::new(),
            probe_events: VecDeque::new(),
            next_probe: 0,
            endpoint_buf: Vec::with_capacity(UDP_BUFFER_SIZE),
            transmit_buf: Vec::with_capacity(UDP_BUFFER_SIZE),
        })
    }

    fn ensure_connection(&mut self, now: Instant, peer: SocketAddr) -> Result<()> {
        if self.connections.contains_key(&peer) {
            return Ok(());
        }
        if self.connections.len() >= MAX_CONNECTIONS {
            return Err(anyhow!(
                "overlay QUIC connection limit reached ({MAX_CONNECTIONS}); not dialing {peer}"
            ));
        }

        let (handle, conn) = self
            .endpoint
            .connect(now, self.client_config.clone(), peer, OVERLAY_SERVER_NAME)
            .map_err(|e| anyhow!("failed to start overlay QUIC connection to {peer}: {e}"))?;
        self.handles.insert(handle, peer);
        self.connections.insert(
            peer,
            QuicConnection {
                handle,
                conn,
                established: false,
                peer_pubkey: None,
                pending: VecDeque::new(),
                expect_pubkey: None,
                streams: BTreeMap::new(),
            },
        );
        Ok(())
    }

    fn handle_datagram_event(
        &mut self,
        env: &mut dyn OverlayEnv,
        event: Option<DatagramEvent>,
    ) {
        match event {
            Some(DatagramEvent::ConnectionEvent(handle, event)) => {
                self.handle_connection_event_for_handle(handle, event);
            }
            Some(DatagramEvent::NewConnection(incoming)) => {
                let peer = incoming.remote_address();
                let now = env.now();
                self.endpoint_buf.clear();
                if self.connections.len() >= MAX_CONNECTIONS {
                    log::warn!(
                        "overlay: refusing QUIC connection from {peer}: limit {MAX_CONNECTIONS} reached"
                    );
                    let transmit = self.endpoint.refuse(incoming, &mut self.endpoint_buf);
                    let bytes = std::mem::take(&mut self.endpoint_buf);
                    send_transmit(env, self.socket, &transmit, &bytes);
                    self.endpoint_buf = bytes;
                    return;
                }
                match self
                    .endpoint
                    .accept(incoming, now, &mut self.endpoint_buf, None)
                {
                    Ok((handle, conn)) => {
                        self.handles.insert(handle, peer);
                        self.connections.insert(
                            peer,
                            QuicConnection {
                                handle,
                                conn,
                                established: false,
                                peer_pubkey: None,
                                pending: VecDeque::new(),
                                expect_pubkey: None,
                                streams: BTreeMap::new(),
                            },
                        );
                    }
                    Err(error) => {
                        if let Some(transmit) = error.response {
                            let bytes = std::mem::take(&mut self.endpoint_buf);
                            send_transmit(env, self.socket, &transmit, &bytes[..transmit.size]);
                            self.endpoint_buf = bytes;
                        }
                        log::warn!(
                            "overlay: failed to accept QUIC connection from {peer}: {}",
                            error.cause
                        );
                    }
                }
            }
            Some(DatagramEvent::Response(transmit)) => {
                let bytes = std::mem::take(&mut self.endpoint_buf);
                send_transmit(env, self.socket, &transmit, &bytes[..transmit.size]);
                self.endpoint_buf = bytes;
            }
            None => {}
        }
    }

    /// Pump connection/endpoint state machines and flush resulting transmits
    /// through the environment. Never blocks.
    fn drive(&mut self, env: &mut dyn OverlayEnv) {
        let mut endpoint_events = Vec::new();
        let mut app_events = Vec::new();
        for (peer, connection) in self.connections.iter_mut() {
            flush_pending(connection);
            while let Some(event) = connection.conn.poll() {
                app_events.push((*peer, event));
            }
            while let Some(event) = connection.conn.poll_endpoint_events() {
                endpoint_events.push((connection.handle, event));
            }
        }

        for (peer, event) in app_events {
            self.handle_connection_event(peer, event);
        }

        for (handle, event) in endpoint_events {
            if let Some(connection_event) = self.endpoint.handle_event(handle, event) {
                self.handle_connection_event_for_handle(handle, connection_event);
            }
        }

        self.flush_transmits(env);
    }

    fn handle_connection_event(&mut self, peer: SocketAddr, event: Event) {
        if let Event::Stream(stream_event) = event {
            self.handle_stream_event(peer, stream_event);
            return;
        }
        let mut remove = false;
        if let Some(connection) = self.connections.get_mut(&peer) {
            match event {
                Event::HandshakeDataReady => {
                    connection.peer_pubkey = peer_pubkey(&connection.conn);
                }
                Event::Connected => {
                    connection.established = true;
                    if connection.peer_pubkey.is_none() {
                        connection.peer_pubkey = peer_pubkey(&connection.conn);
                    }
                    log::debug!(
                        "overlay: QUIC peer {peer} connected, identity {:?}",
                        connection.peer_pubkey
                    );
                    if let Some(pubkey) = connection.peer_pubkey {
                        // Keep the first live connection per identity: a
                        // second connection for the same pubkey (e.g. an
                        // inbound §6.2.3 dial-back probe from a peer we
                        // already hold) must not repoint the mapping, or its
                        // teardown would orphan the primary connection.
                        self.by_pubkey.entry(pubkey).or_insert(peer);
                    }
                    push_bounded(
                        &mut self.events,
                        TransportEvent::Connected {
                            peer,
                            pubkey: connection.peer_pubkey,
                        },
                        MAX_TRANSPORT_EVENTS,
                        "transport events",
                    );
                    flush_pending(connection);
                }
                Event::DatagramReceived => {
                    let mut datagrams = connection.conn.datagrams();
                    while let Some(datagram) = datagrams.recv() {
                        push_bounded(
                            &mut self.inbound_frames,
                            (peer, datagram.to_vec()),
                            MAX_INBOUND_FRAMES,
                            "inbound frames",
                        );
                    }
                }
                Event::DatagramsUnblocked => flush_pending(connection),
                Event::ConnectionLost { reason } => {
                    log::debug!("overlay: QUIC connection to {peer} closed: {reason}");
                    push_bounded(
                        &mut self.events,
                        TransportEvent::Disconnected {
                            peer,
                            reason: reason.to_string(),
                        },
                        MAX_TRANSPORT_EVENTS,
                        "transport events",
                    );
                    remove = true;
                }
                Event::Stream(_) => unreachable!("stream events handled above"),
            }
        }

        if remove && let Some(connection) = self.connections.remove(&peer) {
            self.handles.remove(&connection.handle);
            if let Some(pubkey) = connection.peer_pubkey
                && self.by_pubkey.get(&pubkey) == Some(&peer)
            {
                self.by_pubkey.remove(&pubkey);
            }
            // Every stream on the connection dies with it.
            for (_, stream) in connection.streams {
                if self.stream_states.remove(&stream).is_some() {
                    push_bounded(
                        &mut self.stream_events,
                        StreamEvent::Failed { stream },
                        MAX_STREAM_EVENTS,
                        "stream events",
                    );
                }
            }
        }
    }

    fn handle_stream_event(&mut self, peer: SocketAddr, event: quinn_proto::StreamEvent) {
        match event {
            quinn_proto::StreamEvent::Opened { dir: Dir::Bi } => self.accept_streams(peer),
            quinn_proto::StreamEvent::Opened { dir: Dir::Uni } => {
                // The overlay speaks no unidirectional streams; drain and
                // refuse them so they cost no state.
                if let Some(connection) = self.connections.get_mut(&peer) {
                    while let Some(id) = connection.conn.streams().accept(Dir::Uni) {
                        _ = connection.conn.recv_stream(id).stop(VarInt::from_u32(0));
                    }
                }
            }
            quinn_proto::StreamEvent::Readable { id } => self.read_stream(peer, id),
            quinn_proto::StreamEvent::Writable { id } => {
                if let Some(stream) = self
                    .connections
                    .get(&peer)
                    .and_then(|connection| connection.streams.get(&id))
                    .copied()
                {
                    self.flush_stream(stream);
                }
            }
            // Send side fully acknowledged; delivery was already quinn's
            // problem the moment finish() succeeded.
            quinn_proto::StreamEvent::Finished { id: _ } => {}
            quinn_proto::StreamEvent::Stopped { id, error_code: _ } => {
                self.fail_stream(peer, id);
            }
            quinn_proto::StreamEvent::Available { .. } => {}
        }
    }

    fn accept_streams(&mut self, peer: SocketAddr) {
        loop {
            let Some(connection) = self.connections.get_mut(&peer) else {
                return;
            };
            let Some(id) = connection.conn.streams().accept(Dir::Bi) else {
                return;
            };
            let Some(pubkey) = connection.peer_pubkey else {
                // No verified identity, no stream (cannot happen after the
                // handshake, but refuse rather than trust).
                _ = connection.conn.recv_stream(id).stop(VarInt::from_u32(0));
                _ = connection.conn.send_stream(id).reset(VarInt::from_u32(0));
                continue;
            };
            if self.stream_states.len() >= MAX_STREAM_STATES {
                log::debug!("overlay: stream limit {MAX_STREAM_STATES} reached; refusing inbound");
                _ = connection.conn.recv_stream(id).stop(VarInt::from_u32(0));
                _ = connection.conn.send_stream(id).reset(VarInt::from_u32(0));
                continue;
            }
            let stream = OverlayStreamId(self.next_stream);
            self.next_stream += 1;
            connection.streams.insert(id, stream);
            self.stream_states.insert(
                stream,
                StreamState {
                    peer_addr: peer,
                    quic_id: id,
                    send_buf: Vec::new(),
                    fin_pending: false,
                    fin_done: false,
                    recv_done: false,
                },
            );
            push_bounded(
                &mut self.stream_events,
                StreamEvent::Opened { stream, peer: pubkey },
                MAX_STREAM_EVENTS,
                "stream events",
            );
        }
    }

    fn read_stream(&mut self, peer: SocketAddr, id: quinn_proto::StreamId) {
        let Some(connection) = self.connections.get_mut(&peer) else {
            return;
        };
        let Some(&stream) = connection.streams.get(&id) else {
            return;
        };
        let mut recv = connection.conn.recv_stream(id);
        let mut chunks = match recv.read(true) {
            Ok(chunks) => chunks,
            Err(_) => return,
        };
        let mut bytes = Vec::new();
        let mut outcome = None;
        loop {
            match chunks.next(usize::MAX) {
                Ok(Some(chunk)) => bytes.extend_from_slice(&chunk.bytes),
                Ok(None) => {
                    outcome = Some(StreamEvent::Finished { stream });
                    break;
                }
                Err(ReadError::Blocked) => break,
                Err(ReadError::Reset(_)) => {
                    outcome = Some(StreamEvent::Failed { stream });
                    break;
                }
            }
        }
        // Flow-control frames this read released go out with the caller's
        // drive().
        _ = chunks.finalize();
        if !bytes.is_empty() {
            push_bounded(
                &mut self.stream_events,
                StreamEvent::Data { stream, bytes },
                MAX_STREAM_EVENTS,
                "stream events",
            );
        }
        if let Some(event) = outcome {
            if let Some(state) = self.stream_states.get_mut(&stream) {
                state.recv_done = true;
            }
            push_bounded(
                &mut self.stream_events,
                event,
                MAX_STREAM_EVENTS,
                "stream events",
            );
            self.reap_stream(stream);
        }
    }

    /// The peer refused our send side (STOP_SENDING) — the exchange is dead.
    fn fail_stream(&mut self, peer: SocketAddr, id: quinn_proto::StreamId) {
        let Some(connection) = self.connections.get_mut(&peer) else {
            return;
        };
        let Some(stream) = connection.streams.remove(&id) else {
            return;
        };
        _ = connection.conn.recv_stream(id).stop(VarInt::from_u32(0));
        if self.stream_states.remove(&stream).is_some() {
            push_bounded(
                &mut self.stream_events,
                StreamEvent::Failed { stream },
                MAX_STREAM_EVENTS,
                "stream events",
            );
        }
    }

    /// Flush buffered send bytes and any pending FIN; quinn signals
    /// `Writable` when a `Blocked` write is worth retrying.
    fn flush_stream(&mut self, stream: OverlayStreamId) {
        let Some(state) = self.stream_states.get_mut(&stream) else {
            return;
        };
        let Some(connection) = self.connections.get_mut(&state.peer_addr) else {
            return;
        };
        while !state.send_buf.is_empty() {
            match connection.conn.send_stream(state.quic_id).write(&state.send_buf) {
                Ok(written) => {
                    state.send_buf.drain(..written);
                }
                Err(WriteError::Blocked) => return,
                Err(_) => {
                    // Stopped/closed; the Stopped event path emits Failed.
                    state.send_buf.clear();
                    return;
                }
            }
        }
        if state.fin_pending && !state.fin_done {
            // A stopped stream surfaces through the Stopped event; either
            // way no more sends happen here.
            _ = connection.conn.send_stream(state.quic_id).finish();
            state.fin_done = true;
            self.reap_stream(stream);
        }
    }

    /// Drop bookkeeping once both directions are done. quinn keeps
    /// retransmitting finished data on its own.
    fn reap_stream(&mut self, stream: OverlayStreamId) {
        let done = self
            .stream_states
            .get(&stream)
            .is_some_and(|state| state.recv_done && state.fin_done);
        if !done {
            return;
        }
        if let Some(state) = self.stream_states.remove(&stream)
            && let Some(connection) = self.connections.get_mut(&state.peer_addr)
        {
            connection.streams.remove(&state.quic_id);
        }
    }

    fn handle_connection_event_for_handle(
        &mut self,
        handle: ConnectionHandle,
        event: ConnectionEvent,
    ) {
        if let Some(peer) = self.handles.get(&handle).copied() {
            if let Some(connection) = self.connections.get_mut(&peer) {
                connection.conn.handle_event(event);
            }
        } else if let Some(&probe) = self.probe_handles.get(&handle)
            && let Some(conn) = self.probes.get_mut(&probe)
        {
            conn.conn.handle_event(event);
        }
    }

    /// Pump probe connection state machines (§6.2.3) and flush their
    /// transmits through the helper socket each was bound to.
    fn drive_probes(&mut self, env: &mut dyn OverlayEnv) {
        if self.probes.is_empty() {
            return;
        }
        let mut endpoint_events = Vec::new();
        let mut app_events = Vec::new();
        for (&probe, conn) in self.probes.iter_mut() {
            while let Some(event) = conn.conn.poll() {
                app_events.push((probe, event));
            }
            while let Some(event) = conn.conn.poll_endpoint_events() {
                endpoint_events.push((conn.handle, event));
            }
        }
        for (probe, event) in app_events {
            self.handle_probe_event(probe, event);
        }
        for (handle, event) in endpoint_events {
            if let Some(connection_event) = self.endpoint.handle_event(handle, event) {
                self.handle_connection_event_for_handle(handle, connection_event);
            }
        }
        self.flush_probe_transmits(env);
    }

    fn handle_probe_event(&mut self, probe: ProbeId, event: Event) {
        let outcome = {
            let Some(conn) = self.probes.get_mut(&probe) else {
                return;
            };
            match event {
                Event::Connected if !conn.resolved => {
                    conn.resolved = true;
                    Some(ProbeEvent {
                        probe,
                        addr: conn.remote,
                        identity: peer_pubkey(&conn.conn),
                    })
                }
                Event::ConnectionLost { .. } if !conn.resolved => {
                    conn.resolved = true;
                    Some(ProbeEvent {
                        probe,
                        addr: conn.remote,
                        identity: None,
                    })
                }
                // A probe carries no application data; drain any stray
                // datagrams and ignore streams.
                Event::DatagramReceived => {
                    let mut datagrams = conn.conn.datagrams();
                    while datagrams.recv().is_some() {}
                    None
                }
                _ => None,
            }
        };
        if let Some(event) = outcome {
            push_bounded(
                &mut self.probe_events,
                event,
                MAX_PROBE_EVENTS,
                "probe events",
            );
        }
    }

    fn flush_probe_transmits(&mut self, env: &mut dyn OverlayEnv) {
        loop {
            let now = env.now();
            let mut transmits = Vec::new();
            for conn in self.probes.values_mut() {
                while let Some(transmit) = conn.conn.poll_transmit(
                    now,
                    MAX_DATAGRAMS_PER_TRANSMIT,
                    &mut self.transmit_buf,
                ) {
                    let bytes = self.transmit_buf[..transmit.size].to_vec();
                    self.transmit_buf.clear();
                    transmits.push((conn.socket, transmit, bytes));
                }
            }
            if transmits.is_empty() {
                return;
            }
            for (socket, transmit, bytes) in transmits {
                send_transmit(env, socket, &transmit, &bytes);
            }
        }
    }

    fn flush_transmits(&mut self, env: &mut dyn OverlayEnv) {
        loop {
            let now = env.now();
            let mut transmits = Vec::new();
            for connection in self.connections.values_mut() {
                while let Some(transmit) = connection.conn.poll_transmit(
                    now,
                    MAX_DATAGRAMS_PER_TRANSMIT,
                    &mut self.transmit_buf,
                ) {
                    let bytes = self.transmit_buf[..transmit.size].to_vec();
                    self.transmit_buf.clear();
                    transmits.push((transmit, bytes));
                }
            }

            if transmits.is_empty() {
                return;
            }

            for (transmit, bytes) in transmits {
                send_transmit(env, self.socket, &transmit, &bytes);
            }
        }
    }

    fn handle_timeouts(&mut self, now: Instant) {
        for connection in self.connections.values_mut() {
            if connection.conn.poll_timeout().is_some_and(|due| due <= now) {
                connection.conn.handle_timeout(now);
            }
        }
        for conn in self.probes.values_mut() {
            if conn.conn.poll_timeout().is_some_and(|due| due <= now) {
                conn.conn.handle_timeout(now);
            }
        }
    }
}

impl OverlayTransport for OverlayQuicTransport {
    fn queue_datagram(
        &mut self,
        env: &mut dyn OverlayEnv,
        to: SocketAddr,
        payload: Vec<u8>,
    ) -> Result<()> {
        self.ensure_connection(env.now(), to)?;
        if let Some(connection) = self.connections.get_mut(&to) {
            push_bounded(
                &mut connection.pending,
                payload,
                MAX_PENDING_DATAGRAMS,
                "pending datagrams",
            );
        }
        self.drive(env);
        Ok(())
    }

    fn on_datagram(
        &mut self,
        env: &mut dyn OverlayEnv,
        socket: SocketId,
        from: SocketAddr,
        datagram: &[u8],
    ) {
        if socket != self.socket && !self.probe_sockets.contains(&socket) {
            log::debug!("overlay: dropping datagram from {from} on unexpected {socket}");
            return;
        }
        self.endpoint_buf.clear();
        let event = self.endpoint.handle(
            env.now(),
            from,
            None,
            None,
            BytesMut::from(datagram),
            &mut self.endpoint_buf,
        );
        self.handle_datagram_event(env, event);
        self.drive(env);
        self.drive_probes(env);
    }

    fn on_timer(&mut self, env: &mut dyn OverlayEnv) {
        self.handle_timeouts(env.now());
        self.drive(env);
        self.drive_probes(env);
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.connections
            .values_mut()
            .filter_map(|connection| connection.conn.poll_timeout())
            .chain(
                self.probes
                    .values_mut()
                    .filter_map(|conn| conn.conn.poll_timeout()),
            )
            .min()
    }

    fn poll_inbound(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        self.inbound_frames.pop_front()
    }

    fn poll_event(&mut self) -> Option<TransportEvent> {
        self.events.pop_front()
    }

    fn peer_identity(&self, peer: SocketAddr) -> Option<Pubkey> {
        self.connections.get(&peer)?.peer_pubkey
    }

    fn queue_datagram_to_peer(
        &mut self,
        env: &mut dyn OverlayEnv,
        pubkey: &Pubkey,
        payload: Vec<u8>,
    ) -> bool {
        let Some(&addr) = self.by_pubkey.get(pubkey) else {
            return false;
        };
        let Some(connection) = self.connections.get_mut(&addr) else {
            return false;
        };
        push_bounded(
            &mut connection.pending,
            payload,
            MAX_PENDING_DATAGRAMS,
            "pending datagrams",
        );
        self.drive(env);
        true
    }

    fn connection_addr(&self, pubkey: &Pubkey) -> Option<SocketAddr> {
        self.by_pubkey.get(pubkey).copied()
    }

    fn connected_peers(&self) -> Vec<Pubkey> {
        self.by_pubkey.keys().copied().collect()
    }

    fn open_stream(&mut self, pubkey: &Pubkey) -> Option<OverlayStreamId> {
        if self.stream_states.len() >= MAX_STREAM_STATES {
            return None;
        }
        let addr = *self.by_pubkey.get(pubkey)?;
        let connection = self.connections.get_mut(&addr)?;
        if !connection.established {
            return None;
        }
        let id = connection.conn.streams().open(Dir::Bi)?;
        let stream = OverlayStreamId(self.next_stream);
        self.next_stream += 1;
        connection.streams.insert(id, stream);
        self.stream_states.insert(
            stream,
            StreamState {
                peer_addr: addr,
                quic_id: id,
                send_buf: Vec::new(),
                fin_pending: false,
                fin_done: false,
                recv_done: false,
            },
        );
        Some(stream)
    }

    fn write_stream(
        &mut self,
        env: &mut dyn OverlayEnv,
        stream: OverlayStreamId,
        bytes: &[u8],
    ) -> bool {
        let Some(state) = self.stream_states.get_mut(&stream) else {
            return false;
        };
        if state.fin_pending {
            return false;
        }
        state.send_buf.extend_from_slice(bytes);
        self.flush_stream(stream);
        self.drive(env);
        true
    }

    fn finish_stream(&mut self, env: &mut dyn OverlayEnv, stream: OverlayStreamId) {
        let Some(state) = self.stream_states.get_mut(&stream) else {
            return;
        };
        state.fin_pending = true;
        self.flush_stream(stream);
        self.drive(env);
    }

    fn reset_stream(&mut self, env: &mut dyn OverlayEnv, stream: OverlayStreamId) {
        if let Some(state) = self.stream_states.remove(&stream)
            && let Some(connection) = self.connections.get_mut(&state.peer_addr)
        {
            connection.streams.remove(&state.quic_id);
            _ = connection
                .conn
                .send_stream(state.quic_id)
                .reset(VarInt::from_u32(0));
            _ = connection
                .conn
                .recv_stream(state.quic_id)
                .stop(VarInt::from_u32(0));
            self.drive(env);
        }
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
        self.ensure_connection(env.now(), to)?;
        if let Some(connection) = self.connections.get_mut(&to) {
            // First expectation wins; a connection is dialed for one identity.
            connection.expect_pubkey.get_or_insert(expected);
            push_bounded(
                &mut connection.pending,
                payload,
                MAX_PENDING_DATAGRAMS,
                "pending datagrams",
            );
        }
        self.drive(env);
        Ok(())
    }

    fn start_probe(
        &mut self,
        env: &mut dyn OverlayEnv,
        socket: SocketId,
        addr: SocketAddr,
    ) -> Result<ProbeId> {
        if self.probes.len() >= MAX_PROBES {
            return Err(anyhow!("overlay dial-back probe limit reached ({MAX_PROBES})"));
        }
        let now = env.now();
        let (handle, conn) = self
            .endpoint
            .connect(now, self.client_config.clone(), addr, OVERLAY_SERVER_NAME)
            .map_err(|e| anyhow!("failed to start dial-back probe to {addr}: {e}"))?;
        let probe = ProbeId(self.next_probe);
        self.next_probe += 1;
        self.probe_handles.insert(handle, probe);
        self.probe_sockets.insert(socket);
        self.probes.insert(
            probe,
            ProbeConn {
                handle,
                conn,
                socket,
                remote: addr,
                resolved: false,
            },
        );
        self.drive_probes(env);
        Ok(probe)
    }

    fn poll_probe_event(&mut self) -> Option<ProbeEvent> {
        self.probe_events.pop_front()
    }

    fn close_probe(&mut self, _env: &mut dyn OverlayEnv, probe: ProbeId) {
        if let Some(conn) = self.probes.remove(&probe) {
            self.probe_handles.remove(&conn.handle);
            // Stop accepting inbound on the (about-to-be-closed) helper
            // socket; the core releases it via OverlayEnv::close.
            self.probe_sockets.remove(&conn.socket);
        }
    }

    fn drop_connection(&mut self, _env: &mut dyn OverlayEnv, addr: SocketAddr) {
        if let Some(connection) = self.connections.remove(&addr) {
            self.handles.remove(&connection.handle);
            if let Some(pubkey) = connection.peer_pubkey
                && self.by_pubkey.get(&pubkey) == Some(&addr)
            {
                self.by_pubkey.remove(&pubkey);
            }
            for (_, stream) in connection.streams {
                if self.stream_states.remove(&stream).is_some() {
                    push_bounded(
                        &mut self.stream_events,
                        StreamEvent::Failed { stream },
                        MAX_STREAM_EVENTS,
                        "stream events",
                    );
                }
            }
        }
    }
}

#[cfg(feature = "sim")]
impl OverlayQuicTransport {
    /// quinn's own per-connection counters, for simulator diagnostics.
    pub fn connection_stats(&self) -> Vec<(SocketAddr, quinn_proto::ConnectionStats)> {
        self.connections
            .iter()
            .map(|(peer, connection)| (*peer, connection.conn.stats()))
            .collect()
    }

    /// Datagrams still queued app-side (not yet handed to quinn).
    pub fn pending_datagrams(&self) -> usize {
        self.connections
            .values()
            .map(|connection| connection.pending.len())
            .sum()
    }
}

fn send_transmit(env: &mut dyn OverlayEnv, socket: SocketId, transmit: &Transmit, bytes: &[u8]) {
    if let Some(segment_size) = transmit.segment_size {
        for chunk in bytes.chunks(segment_size) {
            env.send(socket, transmit.destination, chunk);
        }
    } else {
        env.send(socket, transmit.destination, bytes);
    }
}

fn push_bounded<T>(queue: &mut VecDeque<T>, value: T, cap: usize, what: &str) {
    if queue.len() >= cap {
        queue.pop_front();
        log::debug!("overlay: {what} queue full ({cap}); dropping oldest");
    }
    queue.push_back(value);
}

fn flush_pending(connection: &mut QuicConnection) {
    if !connection.established {
        return;
    }
    // §6.2.3 F8 identity gate: a dial-on-demand payload is released only to
    // the identity it was addressed to. A mismatch (a lying `Direct` advert
    // that resolves to a different node) drops it undelivered.
    if let Some(expected) = connection.expect_pubkey
        && connection.peer_pubkey != Some(expected)
    {
        connection.pending.clear();
        return;
    }

    while let Some(payload) = connection.pending.pop_front() {
        match connection.conn.datagrams().send(Bytes::from(payload), true) {
            Ok(()) => {}
            Err(quinn_proto::SendDatagramError::Blocked(payload)) => {
                connection.pending.push_front(payload.to_vec());
                break;
            }
            Err(e) => {
                log::debug!("overlay: failed to queue QUIC datagram: {e}");
            }
        }
    }
}

/// Local connection ids drawn from a seeded RNG so QUIC headers are
/// reproducible under simulation (nat-traversal.md §6.9).
struct SeededCidGenerator {
    rng: StdRng,
}

impl SeededCidGenerator {
    fn new(seed: u64) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
        }
    }
}

impl ConnectionIdGenerator for SeededCidGenerator {
    fn generate_cid(&mut self) -> quinn_proto::ConnectionId {
        let mut bytes = [0u8; SEEDED_CID_LEN];
        self.rng.fill_bytes(&mut bytes);
        quinn_proto::ConnectionId::new(&bytes)
    }

    fn cid_len(&self) -> usize {
        SEEDED_CID_LEN
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

fn overlay_endpoint_config(options: &TransportOptions) -> EndpointConfig {
    let mut config = match &options.reset_key {
        Some(key) => EndpointConfig::new(key.clone()),
        None => EndpointConfig::default(),
    };
    config.rng_seed(options.rng_seed);
    if let Some(seed) = options.cid_seed {
        config.cid_generator(move || Box::new(SeededCidGenerator::new(seed)));
    }
    config
}

fn crypto_provider(options: &TransportOptions) -> Arc<CryptoProvider> {
    options
        .crypto_provider
        .clone()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()))
}

fn overlay_transport_config(options: &TransportOptions) -> Arc<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(8 * 1024 * 1024));
    transport.datagram_send_buffer_size(8 * 1024 * 1024);
    transport.max_concurrent_bidi_streams(MAX_CONCURRENT_BIDI_STREAMS.into());
    transport.max_concurrent_uni_streams(0u32.into());
    transport.keep_alive_interval(options.keep_alive_interval);
    let max_idle = options.max_idle_timeout.map(|timeout| {
        IdleTimeout::try_from(timeout).expect("overlay max_idle_timeout out of range")
    });
    transport.max_idle_timeout(max_idle);
    if let Some(mtu) = options.initial_mtu {
        transport.initial_mtu(mtu);
    }
    Arc::new(transport)
}

fn overlay_server_config(
    identity: &OverlayIdentity,
    options: &TransportOptions,
    transport_config: Arc<TransportConfig>,
) -> Result<QuicServerConfig> {
    let provider = crypto_provider(options);
    let verifier = Arc::new(OverlayClientVerifier::new(&provider));
    let mut tls_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("failed to configure overlay QUIC TLS 1.3 server")?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![identity.cert.clone()], identity.key.clone_key())
        .context("failed to build overlay QUIC server TLS config")?;
    tls_config.max_early_data_size = u32::MAX;

    let crypto = quinn_proto::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls_config))
        .context("failed to convert rustls server config to QUIC server config")?;
    let mut server_config = QuicServerConfig::with_crypto(Arc::new(crypto));
    server_config.transport_config(transport_config);
    Ok(server_config)
}

fn overlay_client_config(
    identity: &OverlayIdentity,
    options: &TransportOptions,
    transport_config: Arc<TransportConfig>,
) -> Result<QuicClientConfig> {
    let provider = crypto_provider(options);
    let verifier = Arc::new(OverlayServerVerifier::new(&provider));
    let mut tls_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("failed to configure overlay QUIC TLS 1.3 client")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![identity.cert.clone()], identity.key.clone_key())
        .context("failed to build overlay QUIC client TLS config")?;
    tls_config.enable_early_data = true;

    let crypto = quinn_proto::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls_config))
        .context("failed to convert rustls client config to QUIC client config")?;
    let mut client_config = QuicClientConfig::new(Arc::new(crypto));
    client_config.transport_config(transport_config);
    Ok(client_config)
}

fn peer_pubkey(connection: &Connection) -> Option<Pubkey> {
    let certs = connection
        .crypto_session()
        .peer_identity()?
        .downcast::<Vec<CertificateDer<'static>>>()
        .ok()?;
    pubkey_from_certificate(certs.first()?)
}

#[derive(Debug)]
struct OverlayServerVerifier {
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl OverlayServerVerifier {
    fn new(provider: &CryptoProvider) -> Self {
        Self {
            supported: provider.signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for OverlayServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        pubkey_from_certificate(end_entity).ok_or_else(|| {
            rustls::Error::General("missing Solana pubkey in overlay cert".into())
        })?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

#[derive(Debug)]
struct OverlayClientVerifier {
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl OverlayClientVerifier {
    fn new(provider: &CryptoProvider) -> Self {
        Self {
            supported: provider.signature_verification_algorithms,
        }
    }
}

impl ClientCertVerifier for OverlayClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        pubkey_from_certificate(end_entity).ok_or_else(|| {
            rustls::Error::General("missing Solana pubkey in overlay cert".into())
        })?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

impl fmt::Debug for OverlayQuicTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OverlayQuicTransport")
            .field("connections", &self.connections.len())
            .field("inbound_frames", &self.inbound_frames.len())
            .finish()
    }
}

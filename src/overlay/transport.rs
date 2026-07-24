use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fmt,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use bytes::{Bytes, BytesMut};
use quinn_proto::{
    ClientConfig as QuicClientConfig, Connection, ConnectionEvent, ConnectionHandle,
    ConnectionIdGenerator, DatagramEvent, Endpoint, EndpointConfig, Event, IdleTimeout,
    ServerConfig as QuicServerConfig, Transmit, TransportConfig, crypto::HmacKey,
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
const MAX_CONNECTIONS: usize = 1024;
const MAX_PENDING_DATAGRAMS: usize = 1024;
const MAX_INBOUND_FRAMES: usize = 8192;
const MAX_TRANSPORT_EVENTS: usize = 1024;
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

/// High seam per nat-traversal.md §6.9: the connection/datagram surface the
/// overlay core programs against. `OverlayQuicTransport` is the real
/// implementation; protocol-scale simulation can substitute an in-memory
/// fake. Streams join this trait with overlay repair (P2).
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
}

pub struct OverlayQuicTransport {
    socket: SocketId,
    endpoint: Endpoint,
    client_config: QuicClientConfig,
    connections: BTreeMap<SocketAddr, QuicConnection>,
    handles: HashMap<ConnectionHandle, SocketAddr>,
    inbound_frames: VecDeque<(SocketAddr, Vec<u8>)>,
    events: VecDeque<TransportEvent>,
    endpoint_buf: Vec<u8>,
    transmit_buf: Vec<u8>,
}

struct QuicConnection {
    handle: ConnectionHandle,
    conn: Connection,
    established: bool,
    peer_pubkey: Option<Pubkey>,
    pending: VecDeque<Vec<u8>>,
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
            handles: HashMap::new(),
            inbound_frames: VecDeque::new(),
            events: VecDeque::new(),
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
                Event::Stream(_) => {}
            }
        }

        if remove && let Some(connection) = self.connections.remove(&peer) {
            self.handles.remove(&connection.handle);
        }
    }

    fn handle_connection_event_for_handle(
        &mut self,
        handle: ConnectionHandle,
        event: ConnectionEvent,
    ) {
        if let Some(peer) = self.handles.get(&handle).copied()
            && let Some(connection) = self.connections.get_mut(&peer)
        {
            connection.conn.handle_event(event);
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
        if socket != self.socket {
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
    }

    fn on_timer(&mut self, env: &mut dyn OverlayEnv) {
        self.handle_timeouts(env.now());
        self.drive(env);
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.connections
            .values_mut()
            .filter_map(|connection| connection.conn.poll_timeout())
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
    transport.keep_alive_interval(options.keep_alive_interval);
    let max_idle = options.max_idle_timeout.map(|timeout| {
        IdleTimeout::try_from(timeout).expect("overlay max_idle_timeout out of range")
    });
    transport.max_idle_timeout(max_idle);
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

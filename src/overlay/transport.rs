use std::{
    collections::{HashMap, VecDeque},
    fmt,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use bytes::{Bytes, BytesMut};
use glommio::{net::UdpSocket, timer::timeout};
use quinn_proto::{
    ClientConfig as QuicClientConfig, Connection, ConnectionEvent, ConnectionHandle, DatagramEvent,
    Endpoint, EndpointConfig, Event, ServerConfig as QuicServerConfig, Transmit, TransportConfig,
};
use rustls::{
    DigitallySignedStruct, DistinguishedName, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};

use super::identity::{OverlayIdentity, pubkey_from_certificate};

const MAX_DATAGRAMS_PER_TRANSMIT: usize = 1;
const UDP_BUFFER_SIZE: usize = 65_535;
const POLL_GRANULARITY: Duration = Duration::from_millis(10);
const OVERLAY_SERVER_NAME: &str = "localhost";

pub struct OverlayQuicTransport {
    socket: UdpSocket,
    endpoint: Endpoint,
    client_config: QuicClientConfig,
    connections: HashMap<SocketAddr, QuicConnection>,
    handles: HashMap<ConnectionHandle, SocketAddr>,
    inbound_frames: VecDeque<(SocketAddr, Vec<u8>)>,
    endpoint_buf: Vec<u8>,
    transmit_buf: Vec<u8>,
}

struct QuicConnection {
    handle: ConnectionHandle,
    conn: Connection,
    established: bool,
    pending: VecDeque<Vec<u8>>,
}

impl OverlayQuicTransport {
    pub fn bind(addr: SocketAddr, identity: &OverlayIdentity) -> Result<Self> {
        let socket = UdpSocket::bind(addr)
            .map_err(|e| anyhow!("failed to bind overlay QUIC socket {addr}: {e}"))?;
        let transport_config = overlay_transport_config();
        let server_config = overlay_server_config(identity, transport_config.clone())?;
        let client_config = overlay_client_config(identity, transport_config)?;

        Ok(Self {
            socket,
            endpoint: Endpoint::new(
                Arc::new(EndpointConfig::default()),
                Some(Arc::new(server_config)),
                false,
                None,
            ),
            client_config,
            connections: HashMap::new(),
            handles: HashMap::new(),
            inbound_frames: VecDeque::new(),
            endpoint_buf: Vec::with_capacity(UDP_BUFFER_SIZE),
            transmit_buf: Vec::with_capacity(UDP_BUFFER_SIZE),
        })
    }

    pub async fn send_to(&mut self, payload: Vec<u8>, peer: SocketAddr) -> Result<()> {
        self.ensure_connection(peer)?;
        if let Some(connection) = self.connections.get_mut(&peer) {
            connection.pending.push_back(payload);
        }
        self.drive().await
    }

    pub async fn recv_for(&mut self, max_wait: Duration) -> Result<Option<(SocketAddr, Vec<u8>)>> {
        if let Some(frame) = self.inbound_frames.pop_front() {
            return Ok(Some(frame));
        }

        self.drive().await?;

        let wait = self.next_wait().min(max_wait);
        let mut buffer = BytesMut::zeroed(UDP_BUFFER_SIZE);
        match timeout(wait, self.socket.recv_from(&mut buffer)).await {
            Ok((len, from)) => {
                buffer.truncate(len);
                self.handle_udp_datagram(from, buffer).await?;
                self.drive().await?;
                Ok(self.inbound_frames.pop_front())
            }
            Err(_) => {
                self.handle_timeouts();
                self.drive().await?;
                Ok(self.inbound_frames.pop_front())
            }
        }
    }

    pub async fn poll(&mut self) -> Result<()> {
        self.drive().await
    }

    fn ensure_connection(&mut self, peer: SocketAddr) -> Result<()> {
        if self.connections.contains_key(&peer) {
            return Ok(());
        }

        let (handle, conn) = self
            .endpoint
            .connect(
                Instant::now(),
                self.client_config.clone(),
                peer,
                OVERLAY_SERVER_NAME,
            )
            .map_err(|e| anyhow!("failed to start overlay QUIC connection to {peer}: {e}"))?;
        self.handles.insert(handle, peer);
        self.connections.insert(
            peer,
            QuicConnection {
                handle,
                conn,
                established: false,
                pending: VecDeque::new(),
            },
        );
        Ok(())
    }

    async fn handle_udp_datagram(&mut self, from: SocketAddr, datagram: BytesMut) -> Result<()> {
        self.endpoint_buf.clear();
        let event = self.endpoint.handle(
            Instant::now(),
            from,
            None,
            None,
            datagram,
            &mut self.endpoint_buf,
        );
        self.handle_datagram_event(event).await
    }

    async fn handle_datagram_event(&mut self, event: Option<DatagramEvent>) -> Result<()> {
        match event {
            Some(DatagramEvent::ConnectionEvent(handle, event)) => {
                if let Some(peer) = self.handles.get(&handle).copied()
                    && let Some(connection) = self.connections.get_mut(&peer)
                {
                    connection.conn.handle_event(event);
                }
            }
            Some(DatagramEvent::NewConnection(incoming)) => {
                let peer = incoming.remote_address();
                self.endpoint_buf.clear();
                match self
                    .endpoint
                    .accept(incoming, Instant::now(), &mut self.endpoint_buf, None)
                {
                    Ok((handle, conn)) => {
                        self.handles.insert(handle, peer);
                        self.connections.insert(
                            peer,
                            QuicConnection {
                                handle,
                                conn,
                                established: false,
                                pending: VecDeque::new(),
                            },
                        );
                    }
                    Err(error) => {
                        if let Some(transmit) = error.response {
                            let bytes = self.endpoint_buf[..transmit.size].to_vec();
                            self.send_transmit(transmit, &bytes).await?;
                        }
                        return Err(anyhow!(
                            "failed to accept overlay QUIC connection from {peer}: {}",
                            error.cause
                        ));
                    }
                }
            }
            Some(DatagramEvent::Response(transmit)) => {
                let bytes = self.endpoint_buf[..transmit.size].to_vec();
                self.send_transmit(transmit, &bytes).await?;
            }
            None => {}
        }
        Ok(())
    }

    async fn drive(&mut self) -> Result<()> {
        self.handle_timeouts();

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

        self.flush_transmits().await
    }

    fn handle_connection_event(&mut self, peer: SocketAddr, event: Event) {
        let mut remove = false;
        if let Some(connection) = self.connections.get_mut(&peer) {
            match event {
                Event::HandshakeDataReady => {
                    if let Some(pubkey) = peer_pubkey(&connection.conn) {
                        log::debug!("overlay: QUIC peer {peer} identity {pubkey}");
                    }
                }
                Event::Connected => {
                    connection.established = true;
                    flush_pending(connection);
                }
                Event::DatagramReceived => {
                    let mut datagrams = connection.conn.datagrams();
                    while let Some(datagram) = datagrams.recv() {
                        self.inbound_frames.push_back((peer, datagram.to_vec()));
                    }
                }
                Event::DatagramsUnblocked => flush_pending(connection),
                Event::ConnectionLost { reason } => {
                    log::debug!("overlay: QUIC connection to {peer} closed: {reason}");
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

    async fn flush_transmits(&mut self) -> Result<()> {
        loop {
            let now = Instant::now();
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
                return Ok(());
            }

            for (transmit, bytes) in transmits {
                self.send_transmit(transmit, &bytes).await?;
            }
        }
    }

    async fn send_transmit(&self, transmit: Transmit, bytes: &[u8]) -> Result<()> {
        if let Some(segment_size) = transmit.segment_size {
            for chunk in bytes.chunks(segment_size) {
                self.socket
                    .send_to(chunk, transmit.destination)
                    .await
                    .map_err(|e| anyhow!("failed to send segmented overlay QUIC datagram: {e}"))?;
            }
        } else {
            self.socket
                .send_to(bytes, transmit.destination)
                .await
                .map_err(|e| anyhow!("failed to send overlay QUIC datagram: {e}"))?;
        }
        Ok(())
    }

    fn handle_timeouts(&mut self) {
        let now = Instant::now();
        for connection in self.connections.values_mut() {
            if connection.conn.poll_timeout().is_some_and(|due| due <= now) {
                connection.conn.handle_timeout(now);
            }
        }
    }

    fn next_wait(&mut self) -> Duration {
        let now = Instant::now();
        self.connections
            .values_mut()
            .filter_map(|connection| connection.conn.poll_timeout())
            .map(|due| due.saturating_duration_since(now))
            .min()
            .unwrap_or(POLL_GRANULARITY)
            .min(POLL_GRANULARITY)
    }
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

fn overlay_transport_config() -> Arc<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(8 * 1024 * 1024));
    transport.datagram_send_buffer_size(8 * 1024 * 1024);
    Arc::new(transport)
}

fn overlay_server_config(
    identity: &OverlayIdentity,
    transport_config: Arc<TransportConfig>,
) -> Result<QuicServerConfig> {
    let verifier = Arc::new(OverlayClientVerifier::new());
    let mut tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
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
    transport_config: Arc<TransportConfig>,
) -> Result<QuicClientConfig> {
    let verifier = Arc::new(OverlayServerVerifier::new());
    let mut tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
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

fn peer_pubkey(connection: &Connection) -> Option<solana_sdk::pubkey::Pubkey> {
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
    fn new() -> Self {
        Self {
            supported: rustls::crypto::ring::default_provider().signature_verification_algorithms,
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
    fn new() -> Self {
        Self {
            supported: rustls::crypto::ring::default_provider().signature_verification_algorithms,
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

//! §6.3 port-mapping ladder client: **PCP → NAT-PMP → UPnP IGD**, in that
//! order, against the configured LAN gateway — plus the PCP v6 pinhole for
//! the dual-stack path. Sans-IO throughout (nat-traversal.md §6.9): PCP and
//! NAT-PMP ride UDP datagrams through the existing `OverlayEnv` seam
//! (`bind`/`send`/`on_datagram`), SSDP is one more datagram exchange, and the
//! UPnP HTTP/SOAP conversation rides the env's TCP byte-stream lane — the
//! driver owns every socket, this module owns every byte and deadline, and
//! the simulator's `sim::gateway` model answers on the wire.
//!
//! A granted mapping is NEVER advertised from here: the core must
//! dial-back-confirm the mapped port through a fresh-source probe first
//! (§6.2.3 — a gateway that grants a port the world cannot reach, e.g.
//! behind CGN, must leave the node `Coordinated`). Leases are renewed at
//! half-life; a mapping that cannot be renewed expires and the candidate is
//! withdrawn. All state is a handful of scalars — nothing here grows.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use super::env::{IpFamily, OverlayEnv, SocketId, TcpEvent, TcpId};

/// Per-step response deadline before a retransmit / the next rung.
const STEP_TIMEOUT: Duration = Duration::from_secs(2);
/// Datagram sends per rung before falling through to the next.
const STEP_ATTEMPTS: u8 = 2;
/// Deadline for one TCP request/response exchange (UPnP).
const TCP_TIMEOUT: Duration = Duration::from_secs(4);
/// After the whole ladder fails, retry from the top this much later.
const LADDER_RETRY: Duration = Duration::from_secs(60);
/// Mapping lifetime requested from the gateway (it clamps downward).
const REQUEST_LIFETIME_SECS: u32 = 3600;
/// A granted lease shorter than this is useless churn; treat as refusal.
const MIN_LEASE: Duration = Duration::from_secs(15);
/// Bound on a buffered HTTP response (device descriptions are a few KB).
const MAX_HTTP_RESPONSE: usize = 64 * 1024;

const PCP_VERSION: u8 = 2;
const PCP_OP_MAP: u8 = 1;
const PCP_UDP: u8 = 17;
const NATPMP_VERSION: u8 = 0;
const NATPMP_OP_EXTERNAL: u8 = 0;
const NATPMP_OP_MAP_UDP: u8 = 1;
pub const SSDP_MULTICAST: SocketAddr = SocketAddr::new(
    IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)),
    1900,
);

/// What the port mapper needs to know about its host (assembled by the core
/// from `OverlayConfig`; the driver resolves auto-discoverable fields).
#[derive(Clone, Debug)]
pub struct PortMapConfig {
    /// The LAN gateway's PCP/NAT-PMP endpoint (normally `<gateway>:5351`).
    pub gateway: SocketAddr,
    /// The overlay port to map (`overlay.bind_addr`'s port, §6.3).
    pub internal_port: u16,
    /// Our LAN address, as the gateway must see it (PCP client IP, UPnP
    /// `NewInternalClient`). An unspecified IP degrades PCP/UPnP on strict
    /// gateways; the production driver resolves it before core start.
    pub internal_ip: IpAddr,
    /// Our v6 overlay socket, if dual-stack: a PCP pinhole is requested for
    /// its port (§6.3 step 2).
    pub internal_v6: Option<SocketAddr>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapProtocol {
    Pcp,
    NatPmp,
    Upnp,
}

#[derive(Clone, Copy, Debug)]
struct Mapped {
    protocol: MapProtocol,
    external: SocketAddr,
    lease: Duration,
    granted_at: Instant,
}

impl Mapped {
    fn expired(&self, now: Instant) -> bool {
        now >= self.granted_at + self.lease
    }
}

/// The ladder conversation in flight. `Idle` doubles as the scheduler: it
/// holds the next time anything should happen (ladder restart or renewal).
enum Phase {
    Idle { at: Instant },
    Pcp { attempt: u8, deadline: Instant },
    NatPmpExternal { attempt: u8, deadline: Instant },
    NatPmpMap { attempt: u8, deadline: Instant, external_ip: IpAddr },
    Ssdp { attempt: u8, deadline: Instant },
    UpnpDescribe { conn: TcpId, deadline: Instant },
    UpnpExternal { conn: TcpId, deadline: Instant },
    UpnpMap { conn: TcpId, deadline: Instant, external_ip: IpAddr },
}

/// The v6 pinhole sub-machine (PCP only; NAT-PMP/UPnP have no v6 story).
enum PinPhase {
    Off,
    Idle { at: Instant },
    Wait { attempt: u8, deadline: Instant },
}

pub struct PortMapper {
    config: PortMapConfig,
    /// UDP socket for the gateway conversation, bound on first drive so the
    /// gateway sees a stable source. `None` until then (or if bind failed).
    socket: Option<SocketId>,
    /// PCP mapping nonces (RFC 6887): responses are matched on them, which
    /// also disambiguates the v4 map from the v6 pinhole on one socket.
    nonce: [u8; 12],
    nonce_v6: [u8; 12],
    phase: Phase,
    mapped: Option<Mapped>,
    pin_phase: PinPhase,
    pinhole: Option<Mapped>,
    /// UPnP route learned from SSDP/description, pinned to the gateway IP.
    http_endpoint: Option<SocketAddr>,
    describe_path: String,
    control_url: Option<String>,
    http_buf: Vec<u8>,
    /// Gateway responses that failed to parse, dropped inertly. Oracle.
    pub malformed_responses: u64,
    /// Gateway refusals (error results / SOAP faults). Oracle.
    pub denials: u64,
}

impl PortMapper {
    pub fn new(config: PortMapConfig, now: Instant) -> Self {
        let pin_phase = if config.internal_v6.is_some() {
            PinPhase::Idle { at: now }
        } else {
            PinPhase::Off
        };
        Self {
            config,
            socket: None,
            nonce: [0; 12],
            nonce_v6: [0; 12],
            phase: Phase::Idle { at: now },
            mapped: None,
            pin_phase,
            pinhole: None,
            http_endpoint: None,
            describe_path: String::new(),
            control_url: None,
            http_buf: Vec::new(),
            malformed_responses: 0,
            denials: 0,
        }
    }

    /// The UDP socket this machine owns, for the core's datagram routing.
    pub fn socket(&self) -> Option<SocketId> {
        self.socket
    }

    /// The gateway-granted external mapping, while its lease lives. A §6.2.3
    /// dial-back candidate — never advertised without confirmation.
    pub fn mapped_external(&self, now: Instant) -> Option<SocketAddr> {
        self.mapped
            .filter(|mapped| !mapped.expired(now))
            .map(|mapped| mapped.external)
    }

    /// Protocol that granted the current mapping (diagnostics/oracles).
    #[allow(dead_code)]
    pub fn mapped_protocol(&self, now: Instant) -> Option<MapProtocol> {
        self.mapped
            .filter(|mapped| !mapped.expired(now))
            .map(|mapped| mapped.protocol)
    }

    /// A v6 pinhole lease is live: the firewall admits unsolicited inbound
    /// on our v6 port, so a fresh-source dial-back can succeed (§6.3).
    pub fn pinhole_active(&self, now: Instant) -> bool {
        self.pinhole.is_some_and(|pinhole| !pinhole.expired(now))
    }

    /// Next deadline. Renewals are folded into the `Idle` wake-up (set to
    /// the half-life at grant time), so this never returns a perpetually
    /// past instant — a past deadline here would spin the driver.
    pub fn poll_timeout(&self) -> Option<Instant> {
        let mut deadline = match self.phase {
            Phase::Idle { at } => at,
            Phase::Pcp { deadline, .. }
            | Phase::NatPmpExternal { deadline, .. }
            | Phase::NatPmpMap { deadline, .. }
            | Phase::Ssdp { deadline, .. }
            | Phase::UpnpDescribe { deadline, .. }
            | Phase::UpnpExternal { deadline, .. }
            | Phase::UpnpMap { deadline, .. } => deadline,
        };
        match self.pin_phase {
            PinPhase::Off => {}
            PinPhase::Idle { at } => deadline = deadline.min(at),
            PinPhase::Wait { deadline: pin, .. } => deadline = deadline.min(pin),
        }
        Some(deadline)
    }

    fn ensure_socket(&mut self, env: &mut dyn OverlayEnv) -> Option<SocketId> {
        if self.socket.is_none() {
            match env.bind(None, IpFamily::V4) {
                Ok(socket) => {
                    env.rng().fill_bytes(&mut self.nonce);
                    env.rng().fill_bytes(&mut self.nonce_v6);
                    self.socket = Some(socket);
                }
                Err(e) => {
                    log::debug!("overlay: portmap socket bind failed: {e}");
                }
            }
        }
        self.socket
    }

    // ---- scheduling -----------------------------------------------------

    pub fn on_timer(&mut self, env: &mut dyn OverlayEnv) {
        let now = env.now();
        if self.mapped.is_some_and(|mapped| mapped.expired(now)) {
            log::debug!("overlay: portmap lease expired unrenewed; candidate withdrawn");
            self.mapped = None;
        }
        if self.pinhole.is_some_and(|pinhole| pinhole.expired(now)) {
            self.pinhole = None;
        }
        self.drive_phase(env, now);
        self.drive_pinhole(env, now);
    }

    fn drive_phase(&mut self, env: &mut dyn OverlayEnv, now: Instant) {
        match self.phase {
            Phase::Idle { at } => {
                if now >= at {
                    self.start_ladder_or_renew(env, now);
                }
            }
            Phase::Pcp { attempt, deadline } if now >= deadline => {
                if attempt + 1 < STEP_ATTEMPTS {
                    self.send_pcp_map(env, now, attempt + 1);
                } else {
                    self.send_natpmp_external(env, now, 0);
                }
            }
            Phase::NatPmpExternal { attempt, deadline } if now >= deadline => {
                if attempt + 1 < STEP_ATTEMPTS {
                    self.send_natpmp_external(env, now, attempt + 1);
                } else {
                    self.send_ssdp(env, now, 0);
                }
            }
            Phase::NatPmpMap { attempt, deadline, external_ip } if now >= deadline => {
                if attempt + 1 < STEP_ATTEMPTS {
                    self.send_natpmp_map(env, now, attempt + 1, external_ip);
                } else {
                    self.send_ssdp(env, now, 0);
                }
            }
            Phase::Ssdp { attempt, deadline } if now >= deadline => {
                if attempt + 1 < STEP_ATTEMPTS {
                    self.send_ssdp(env, now, attempt + 1);
                } else {
                    self.ladder_failed(now);
                }
            }
            Phase::UpnpDescribe { conn, deadline }
            | Phase::UpnpExternal { conn, deadline }
            | Phase::UpnpMap { conn, deadline, .. }
                if now >= deadline =>
            {
                env.tcp_close(conn);
                self.http_buf.clear();
                self.ladder_failed(now);
            }
            _ => {}
        }
    }

    fn start_ladder_or_renew(&mut self, env: &mut dyn OverlayEnv, now: Instant) {
        match self.mapped {
            // Renew through the protocol that granted, shortcutting the
            // ladder; a failed renewal falls through the remaining rungs
            // and, if all fail, the lease expires and the candidate drops.
            Some(mapped) => match mapped.protocol {
                MapProtocol::Pcp => self.send_pcp_map(env, now, 0),
                MapProtocol::NatPmp => self.send_natpmp_map(env, now, 0, mapped.external.ip()),
                MapProtocol::Upnp => match (self.http_endpoint, self.control_url.clone()) {
                    (Some(_), Some(control)) => {
                        self.send_upnp_map(env, now, control, mapped.external.ip());
                    }
                    _ => self.send_ssdp(env, now, 0),
                },
            },
            None => self.send_pcp_map(env, now, 0),
        }
    }

    fn ladder_failed(&mut self, now: Instant) {
        self.phase = Phase::Idle {
            at: now + LADDER_RETRY,
        };
    }

    // ---- PCP ------------------------------------------------------------

    fn send_pcp_map(&mut self, env: &mut dyn OverlayEnv, now: Instant, attempt: u8) {
        let Some(socket) = self.ensure_socket(env) else {
            self.ladder_failed(now);
            return;
        };
        let request = encode_pcp_map(
            self.nonce,
            self.config.internal_ip,
            self.config.internal_port,
            self.config.internal_port,
            REQUEST_LIFETIME_SECS,
        );
        env.send(socket, self.config.gateway, &request);
        self.phase = Phase::Pcp {
            attempt,
            deadline: now + STEP_TIMEOUT,
        };
    }

    // ---- NAT-PMP --------------------------------------------------------

    fn send_natpmp_external(&mut self, env: &mut dyn OverlayEnv, now: Instant, attempt: u8) {
        let Some(socket) = self.ensure_socket(env) else {
            self.ladder_failed(now);
            return;
        };
        env.send(socket, self.config.gateway, &[NATPMP_VERSION, NATPMP_OP_EXTERNAL]);
        self.phase = Phase::NatPmpExternal {
            attempt,
            deadline: now + STEP_TIMEOUT,
        };
    }

    fn send_natpmp_map(
        &mut self,
        env: &mut dyn OverlayEnv,
        now: Instant,
        attempt: u8,
        external_ip: IpAddr,
    ) {
        let Some(socket) = self.ensure_socket(env) else {
            self.ladder_failed(now);
            return;
        };
        let mut request = vec![NATPMP_VERSION, NATPMP_OP_MAP_UDP, 0, 0];
        request.extend_from_slice(&self.config.internal_port.to_be_bytes());
        request.extend_from_slice(&self.config.internal_port.to_be_bytes());
        request.extend_from_slice(&REQUEST_LIFETIME_SECS.to_be_bytes());
        env.send(socket, self.config.gateway, &request);
        self.phase = Phase::NatPmpMap {
            attempt,
            deadline: now + STEP_TIMEOUT,
            external_ip,
        };
    }

    // ---- SSDP + UPnP ----------------------------------------------------

    fn send_ssdp(&mut self, env: &mut dyn OverlayEnv, now: Instant, attempt: u8) {
        let Some(socket) = self.ensure_socket(env) else {
            self.ladder_failed(now);
            return;
        };
        let msearch = "M-SEARCH * HTTP/1.1\r\n\
             HOST: 239.255.255.250:1900\r\n\
             MAN: \"ssdp:discover\"\r\n\
             MX: 2\r\n\
             ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
        env.send(socket, SSDP_MULTICAST, msearch.as_bytes());
        self.phase = Phase::Ssdp {
            attempt,
            deadline: now + STEP_TIMEOUT,
        };
    }

    fn open_http(
        &mut self,
        env: &mut dyn OverlayEnv,
        request: String,
    ) -> Option<TcpId> {
        let endpoint = self.http_endpoint?;
        match env.tcp_connect(endpoint) {
            Ok(conn) => {
                env.tcp_send(conn, request.as_bytes());
                self.http_buf.clear();
                Some(conn)
            }
            Err(e) => {
                log::debug!("overlay: portmap tcp connect failed: {e}");
                None
            }
        }
    }

    fn send_upnp_describe(&mut self, env: &mut dyn OverlayEnv, now: Instant) {
        let Some(endpoint) = self.http_endpoint else {
            self.ladder_failed(now);
            return;
        };
        let request = format!(
            "GET {} HTTP/1.1\r\nHOST: {}\r\nCONNECTION: close\r\n\r\n",
            self.describe_path, endpoint,
        );
        match self.open_http(env, request) {
            Some(conn) => {
                self.phase = Phase::UpnpDescribe {
                    conn,
                    deadline: now + TCP_TIMEOUT,
                };
            }
            None => self.ladder_failed(now),
        }
    }

    fn soap_request(&self, control: &str, action: &str, arguments: &str) -> String {
        let endpoint = self.http_endpoint.expect("caller checked http_endpoint");
        let body = format!(
            "<?xml version=\"1.0\"?>\
             <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
             <s:Body><u:{action} xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\
             {arguments}</u:{action}></s:Body></s:Envelope>"
        );
        format!(
            "POST {control} HTTP/1.1\r\nHOST: {endpoint}\r\n\
             CONTENT-TYPE: text/xml; charset=\"utf-8\"\r\n\
             SOAPACTION: \"urn:schemas-upnp-org:service:WANIPConnection:1#{action}\"\r\n\
             CONTENT-LENGTH: {}\r\nCONNECTION: close\r\n\r\n{body}",
            body.len(),
        )
    }

    fn send_upnp_external(&mut self, env: &mut dyn OverlayEnv, now: Instant, control: String) {
        let request = self.soap_request(&control, "GetExternalIPAddress", "");
        match self.open_http(env, request) {
            Some(conn) => {
                self.control_url = Some(control);
                self.phase = Phase::UpnpExternal {
                    conn,
                    deadline: now + TCP_TIMEOUT,
                };
            }
            None => self.ladder_failed(now),
        }
    }

    fn send_upnp_map(
        &mut self,
        env: &mut dyn OverlayEnv,
        now: Instant,
        control: String,
        external_ip: IpAddr,
    ) {
        let port = self.config.internal_port;
        let arguments = format!(
            "<NewRemoteHost></NewRemoteHost>\
             <NewExternalPort>{port}</NewExternalPort>\
             <NewProtocol>UDP</NewProtocol>\
             <NewInternalPort>{port}</NewInternalPort>\
             <NewInternalClient>{}</NewInternalClient>\
             <NewEnabled>1</NewEnabled>\
             <NewPortMappingDescription>lightbringer-overlay</NewPortMappingDescription>\
             <NewLeaseDuration>{REQUEST_LIFETIME_SECS}</NewLeaseDuration>",
            self.config.internal_ip,
        );
        let request = self.soap_request(&control, "AddPortMapping", &arguments);
        match self.open_http(env, request) {
            Some(conn) => {
                self.control_url = Some(control);
                self.phase = Phase::UpnpMap {
                    conn,
                    deadline: now + TCP_TIMEOUT,
                    external_ip,
                };
            }
            None => self.ladder_failed(now),
        }
    }

    // ---- datagram input -------------------------------------------------

    /// A datagram arrived on the port-map socket. Anything unparseable or
    /// from the wrong host is dropped inertly (§9: the gateway is untrusted
    /// input like everything else).
    pub fn on_datagram(&mut self, env: &mut dyn OverlayEnv, from: SocketAddr, payload: &[u8]) {
        if from.ip() != self.config.gateway.ip() {
            return;
        }
        let now = env.now();
        // The PCP pinhole answer is matched by nonce, independent of the
        // ladder phase (both conversations share the socket).
        if payload.first() == Some(&PCP_VERSION)
            && let Some(response) = parse_pcp_map_response(payload)
            && response.nonce == self.nonce_v6
        {
            self.on_pinhole_response(now, response);
            return;
        }
        match self.phase {
            Phase::Pcp { .. } => self.on_pcp_response(env, now, payload),
            Phase::NatPmpExternal { .. } => self.on_natpmp_external(env, now, payload),
            Phase::NatPmpMap { external_ip, .. } => {
                self.on_natpmp_map(env, now, payload, external_ip)
            }
            Phase::Ssdp { .. } => self.on_ssdp_response(env, now, payload),
            _ => {}
        }
    }

    fn grant(&mut self, now: Instant, protocol: MapProtocol, external: SocketAddr, lease: Duration) {
        log::debug!("overlay: portmap granted {external} via {protocol:?}, lease {lease:?}");
        self.mapped = Some(Mapped {
            protocol,
            external,
            lease,
            granted_at: now,
        });
        // Sleep until half-life; renewal shortcuts through the granting rung.
        self.phase = Phase::Idle {
            at: now + lease / 2,
        };
    }

    fn on_pcp_response(&mut self, env: &mut dyn OverlayEnv, now: Instant, payload: &[u8]) {
        let Some(response) = parse_pcp_map_response(payload) else {
            self.malformed_responses += 1;
            return;
        };
        if response.nonce != self.nonce {
            return;
        }
        let lease = Duration::from_secs(u64::from(response.lifetime));
        if response.result != 0 || lease < MIN_LEASE {
            self.denials += 1;
            self.send_natpmp_external(env, now, 0);
            return;
        }
        self.grant(
            now,
            MapProtocol::Pcp,
            SocketAddr::new(response.external_ip, response.external_port),
            lease,
        );
    }

    fn on_pinhole_response(&mut self, now: Instant, response: PcpMapResponse) {
        let lease = Duration::from_secs(u64::from(response.lifetime));
        if response.result != 0 || lease < MIN_LEASE {
            self.denials += 1;
            self.pin_phase = PinPhase::Idle {
                at: now + LADDER_RETRY,
            };
            return;
        }
        log::debug!("overlay: v6 pinhole granted for port {}", response.external_port);
        self.pinhole = Some(Mapped {
            protocol: MapProtocol::Pcp,
            external: SocketAddr::new(response.external_ip, response.external_port),
            lease,
            granted_at: now,
        });
        self.pin_phase = PinPhase::Idle {
            at: now + lease / 2,
        };
    }

    fn on_natpmp_external(&mut self, env: &mut dyn OverlayEnv, now: Instant, payload: &[u8]) {
        if payload.len() != 12
            || payload[0] != NATPMP_VERSION
            || payload[1] != 128 + NATPMP_OP_EXTERNAL
        {
            self.malformed_responses += 1;
            return;
        }
        let result = u16::from_be_bytes([payload[2], payload[3]]);
        if result != 0 {
            self.denials += 1;
            self.send_ssdp(env, now, 0);
            return;
        }
        let external_ip = IpAddr::V4(Ipv4Addr::new(
            payload[8], payload[9], payload[10], payload[11],
        ));
        self.send_natpmp_map(env, now, 0, external_ip);
    }

    fn on_natpmp_map(
        &mut self,
        env: &mut dyn OverlayEnv,
        now: Instant,
        payload: &[u8],
        external_ip: IpAddr,
    ) {
        if payload.len() != 16
            || payload[0] != NATPMP_VERSION
            || payload[1] != 128 + NATPMP_OP_MAP_UDP
        {
            self.malformed_responses += 1;
            return;
        }
        let result = u16::from_be_bytes([payload[2], payload[3]]);
        let mapped_port = u16::from_be_bytes([payload[10], payload[11]]);
        let lease = Duration::from_secs(u64::from(u32::from_be_bytes([
            payload[12], payload[13], payload[14], payload[15],
        ])));
        if result != 0 || lease < MIN_LEASE {
            self.denials += 1;
            self.send_ssdp(env, now, 0);
            return;
        }
        self.grant(
            now,
            MapProtocol::NatPmp,
            SocketAddr::new(external_ip, mapped_port),
            lease,
        );
    }

    fn on_ssdp_response(&mut self, env: &mut dyn OverlayEnv, now: Instant, payload: &[u8]) {
        let Ok(text) = std::str::from_utf8(payload) else {
            self.malformed_responses += 1;
            return;
        };
        let Some((endpoint, path)) = parse_ssdp_location(text) else {
            self.malformed_responses += 1;
            return;
        };
        // §9: never follow a LOCATION off the gateway host — an SSDP frame
        // is unauthenticated and must not steer HTTP anywhere else.
        if endpoint.ip() != self.config.gateway.ip() {
            self.malformed_responses += 1;
            return;
        }
        self.http_endpoint = Some(endpoint);
        self.describe_path = path;
        self.send_upnp_describe(env, now);
    }

    // ---- TCP input (UPnP) -----------------------------------------------

    pub fn on_tcp_event(&mut self, env: &mut dyn OverlayEnv, event: TcpEvent) {
        let now = env.now();
        let active = match self.phase {
            Phase::UpnpDescribe { conn, .. }
            | Phase::UpnpExternal { conn, .. }
            | Phase::UpnpMap { conn, .. } => conn,
            _ => return,
        };
        if event.conn() != active {
            return;
        }
        match event {
            TcpEvent::Connected(_) => {}
            TcpEvent::Data(_, bytes) => {
                self.http_buf.extend_from_slice(&bytes);
                if self.http_buf.len() > MAX_HTTP_RESPONSE {
                    env.tcp_close(active);
                    self.http_buf.clear();
                    self.malformed_responses += 1;
                    self.ladder_failed(now);
                    return;
                }
                if parse_http_response(&self.http_buf).is_some() {
                    env.tcp_close(active);
                    self.finish_http(env, now);
                }
            }
            TcpEvent::Closed(_) => {
                // EOF also delimits responses without a content-length.
                if parse_http_response(&self.http_buf).is_some() {
                    self.finish_http(env, now);
                } else {
                    self.http_buf.clear();
                    self.ladder_failed(now);
                }
            }
        }
    }

    fn finish_http(&mut self, env: &mut dyn OverlayEnv, now: Instant) {
        let buf = std::mem::take(&mut self.http_buf);
        let Some((status, body)) = parse_http_response(&buf) else {
            self.malformed_responses += 1;
            self.ladder_failed(now);
            return;
        };
        match &self.phase {
            Phase::UpnpDescribe { .. } => {
                match (status == 200).then(|| parse_control_url(body)).flatten() {
                    Some(control) => self.send_upnp_external(env, now, control),
                    None => {
                        self.malformed_responses += 1;
                        self.ladder_failed(now);
                    }
                }
            }
            Phase::UpnpExternal { .. } => {
                let external = (status == 200)
                    .then(|| xml_field(body, "NewExternalIPAddress"))
                    .flatten()
                    .and_then(|value| value.parse::<IpAddr>().ok());
                match (external, self.control_url.clone()) {
                    (Some(ip), Some(control)) => self.send_upnp_map(env, now, control, ip),
                    _ => {
                        self.malformed_responses += 1;
                        self.ladder_failed(now);
                    }
                }
            }
            Phase::UpnpMap { external_ip, .. } => {
                if status == 200 && body.contains("AddPortMappingResponse") {
                    // IGDv1 grants exactly the requested port; lease is what
                    // we asked for (many gateways treat it as permanent).
                    let external = SocketAddr::new(*external_ip, self.config.internal_port);
                    self.grant(
                        now,
                        MapProtocol::Upnp,
                        external,
                        Duration::from_secs(u64::from(REQUEST_LIFETIME_SECS)),
                    );
                } else {
                    self.denials += 1;
                    self.ladder_failed(now);
                }
            }
            _ => {}
        }
    }

    // ---- v6 pinhole -----------------------------------------------------

    fn drive_pinhole(&mut self, env: &mut dyn OverlayEnv, now: Instant) {
        let Some(internal_v6) = self.config.internal_v6 else {
            return;
        };
        match self.pin_phase {
            PinPhase::Off => {}
            PinPhase::Idle { at } => {
                if now >= at {
                    self.send_pinhole(env, now, 0, internal_v6);
                }
            }
            PinPhase::Wait { attempt, deadline } if now >= deadline => {
                if attempt + 1 < STEP_ATTEMPTS {
                    self.send_pinhole(env, now, attempt + 1, internal_v6);
                } else {
                    self.pin_phase = PinPhase::Idle {
                        at: now + LADDER_RETRY,
                    };
                }
            }
            PinPhase::Wait { .. } => {}
        }
    }

    fn send_pinhole(
        &mut self,
        env: &mut dyn OverlayEnv,
        now: Instant,
        attempt: u8,
        internal_v6: SocketAddr,
    ) {
        let Some(socket) = self.ensure_socket(env) else {
            self.pin_phase = PinPhase::Idle {
                at: now + LADDER_RETRY,
            };
            return;
        };
        let request = encode_pcp_map(
            self.nonce_v6,
            internal_v6.ip(),
            internal_v6.port(),
            internal_v6.port(),
            REQUEST_LIFETIME_SECS,
        );
        env.send(socket, self.config.gateway, &request);
        self.pin_phase = PinPhase::Wait {
            attempt,
            deadline: now + STEP_TIMEOUT,
        };
    }
}

// ---- wire codecs ---------------------------------------------------------

fn ip_to_16(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

fn ip_from_16(bytes: &[u8]) -> IpAddr {
    let octets: [u8; 16] = bytes.try_into().expect("16-byte IP field");
    let v6 = Ipv6Addr::from(octets);
    match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    }
}

/// RFC 6887 MAP request: 24-byte common header + 36-byte MAP payload.
fn encode_pcp_map(
    nonce: [u8; 12],
    client_ip: IpAddr,
    internal_port: u16,
    suggested_port: u16,
    lifetime: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(60);
    out.push(PCP_VERSION);
    out.push(PCP_OP_MAP);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&lifetime.to_be_bytes());
    out.extend_from_slice(&ip_to_16(client_ip));
    out.extend_from_slice(&nonce);
    out.push(PCP_UDP);
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(&internal_port.to_be_bytes());
    out.extend_from_slice(&suggested_port.to_be_bytes());
    out.extend_from_slice(&ip_to_16(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    out
}

struct PcpMapResponse {
    result: u8,
    lifetime: u32,
    nonce: [u8; 12],
    external_port: u16,
    external_ip: IpAddr,
}

fn parse_pcp_map_response(payload: &[u8]) -> Option<PcpMapResponse> {
    if payload.len() != 60
        || payload[0] != PCP_VERSION
        || payload[1] != (0x80 | PCP_OP_MAP)
    {
        return None;
    }
    Some(PcpMapResponse {
        result: payload[3],
        lifetime: u32::from_be_bytes(payload[4..8].try_into().ok()?),
        nonce: payload[24..36].try_into().ok()?,
        external_port: u16::from_be_bytes(payload[42..44].try_into().ok()?),
        external_ip: ip_from_16(&payload[44..60]),
    })
}

/// Extract host and path from an SSDP `LOCATION: http://ip:port/path` line.
/// IP-literal hosts only — sans-IO code resolves no names.
fn parse_ssdp_location(text: &str) -> Option<(SocketAddr, String)> {
    if !text.starts_with("HTTP/1.1 200") {
        return None;
    }
    let location = text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim().eq_ignore_ascii_case("location").then(|| value.trim())
    })?;
    let rest = location.strip_prefix("http://")?;
    let (host, path) = match rest.find('/') {
        Some(slash) => (&rest[..slash], &rest[slash..]),
        None => (rest, "/"),
    };
    let endpoint: SocketAddr = host.parse().ok()?;
    Some((endpoint, path.to_string()))
}

/// One complete HTTP response: `(status, body)`. `None` while incomplete
/// (a declared content-length not yet fully buffered).
fn parse_http_response(buf: &[u8]) -> Option<(u16, &str)> {
    let text = std::str::from_utf8(buf).ok()?;
    let header_end = text.find("\r\n\r\n")? + 4;
    let headers = &text[..header_end];
    let status: u16 = headers
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    let content_length = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok());
    let body = &text[header_end..];
    match content_length {
        Some(length) if body.len() < length => None,
        Some(length) => Some((status, &body[..length])),
        None => Some((status, body)),
    }
}

/// Find the `WANIPConnection` service's control URL in a device
/// description: the first `<controlURL>` following the serviceType, which
/// holds for both real nested descriptions and the sim's.
fn parse_control_url(body: &str) -> Option<String> {
    let service = body.find("urn:schemas-upnp-org:service:WANIPConnection:")?;
    let rest = &body[service..];
    let control = xml_field(rest, "controlURL")?;
    (!control.is_empty()).then(|| control.to_string())
}

fn xml_field<'a>(body: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&close)? + start;
    Some(body[start..end].trim())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overlay::env::OverlayEnv;
    use anyhow::Result;
    use rand::{RngCore, SeedableRng, rngs::StdRng};
    use std::collections::VecDeque;

    /// Test env: records sends/TCP intents, virtual clock.
    struct TestEnv {
        now: Instant,
        rng: StdRng,
        sent: Vec<(SocketId, SocketAddr, Vec<u8>)>,
        tcp: Vec<(TcpId, SocketAddr)>,
        tcp_sent: Vec<(TcpId, Vec<u8>)>,
        next_socket: u32,
        next_tcp: u64,
        closed: VecDeque<TcpId>,
    }

    impl TestEnv {
        fn new() -> Self {
            Self {
                now: Instant::now(),
                rng: StdRng::seed_from_u64(7),
                sent: Vec::new(),
                tcp: Vec::new(),
                tcp_sent: Vec::new(),
                next_socket: 1,
                next_tcp: 0,
                closed: VecDeque::new(),
            }
        }

        fn advance(&mut self, by: Duration) {
            self.now += by;
        }
    }

    impl OverlayEnv for TestEnv {
        fn now(&self) -> Instant {
            self.now
        }
        fn rng(&mut self) -> &mut dyn RngCore {
            &mut self.rng
        }
        fn send(&mut self, from: SocketId, to: SocketAddr, datagram: &[u8]) {
            self.sent.push((from, to, datagram.to_vec()));
        }
        fn bind(&mut self, _port: Option<u16>, _family: IpFamily) -> Result<SocketId> {
            let id = SocketId(self.next_socket);
            self.next_socket += 1;
            Ok(id)
        }
        fn close(&mut self, _socket: SocketId) {}
        fn tcp_connect(&mut self, to: SocketAddr) -> Result<TcpId> {
            let id = TcpId(self.next_tcp);
            self.next_tcp += 1;
            self.tcp.push((id, to));
            Ok(id)
        }
        fn tcp_send(&mut self, conn: TcpId, bytes: &[u8]) {
            self.tcp_sent.push((conn, bytes.to_vec()));
        }
        fn tcp_close(&mut self, conn: TcpId) {
            self.closed.push_back(conn);
        }
    }

    fn config() -> PortMapConfig {
        PortMapConfig {
            gateway: "10.7.0.1:5351".parse().unwrap(),
            internal_port: 51_000,
            internal_ip: "10.7.0.2".parse().unwrap(),
            internal_v6: None,
        }
    }

    fn pcp_response(request: &[u8], result: u8, lifetime: u32, port: u16, ip: IpAddr) -> Vec<u8> {
        let mut resp = vec![2, 0x81, 0, result];
        resp.extend_from_slice(&lifetime.to_be_bytes());
        resp.extend_from_slice(&0u32.to_be_bytes());
        resp.extend_from_slice(&[0u8; 12]);
        resp.extend_from_slice(&request[24..36]);
        resp.push(17);
        resp.extend_from_slice(&[0u8; 3]);
        resp.extend_from_slice(&request[40..42]);
        resp.extend_from_slice(&port.to_be_bytes());
        resp.extend_from_slice(&ip_to_16(ip));
        resp
    }

    #[test]
    fn pcp_grant_maps_and_schedules_half_life_renewal() {
        let mut env = TestEnv::new();
        let mut mapper = PortMapper::new(config(), env.now);
        mapper.on_timer(&mut env);
        assert_eq!(env.sent.len(), 1, "PCP request sent first");
        let (_, to, request) = env.sent[0].clone();
        assert_eq!(to, "10.7.0.1:5351".parse().unwrap());
        assert_eq!(request.len(), 60);
        assert_eq!(request[0], 2);

        let external: IpAddr = "198.51.0.8".parse().unwrap();
        let resp = pcp_response(&request, 0, 600, 51_000, external);
        mapper.on_datagram(&mut env, "10.7.0.1:5351".parse().unwrap(), &resp);
        assert_eq!(
            mapper.mapped_external(env.now),
            Some("198.51.0.8:51000".parse().unwrap()),
        );
        assert_eq!(mapper.mapped_protocol(env.now), Some(MapProtocol::Pcp));

        // Renewal fires at half-life: another PCP request goes out.
        env.advance(Duration::from_secs(301));
        mapper.on_timer(&mut env);
        assert_eq!(env.sent.len(), 2, "half-life renewal sent");
        // Unrenewed, the lease expires and the candidate is withdrawn.
        env.advance(Duration::from_secs(300));
        mapper.on_timer(&mut env);
        assert_eq!(mapper.mapped_external(env.now), None);
    }

    #[test]
    fn ladder_falls_pcp_natpmp_ssdp_on_silence() {
        let mut env = TestEnv::new();
        let mut mapper = PortMapper::new(config(), env.now);
        let step = STEP_TIMEOUT + Duration::from_millis(10);
        mapper.on_timer(&mut env); // PCP #1
        env.advance(step);
        mapper.on_timer(&mut env); // PCP #2
        env.advance(step);
        mapper.on_timer(&mut env); // NAT-PMP external #1
        env.advance(step);
        mapper.on_timer(&mut env); // NAT-PMP external #2
        env.advance(step);
        mapper.on_timer(&mut env); // SSDP #1
        env.advance(step);
        mapper.on_timer(&mut env); // SSDP #2
        env.advance(step);
        mapper.on_timer(&mut env); // ladder failed → idle retry

        let kinds: Vec<&[u8]> = env.sent.iter().map(|(_, _, b)| b.as_slice()).collect();
        assert_eq!(kinds.len(), 6);
        assert!(kinds[0][0] == 2 && kinds[1][0] == 2, "two PCP tries");
        assert_eq!(&kinds[2][..2], &[0, 0], "NAT-PMP external addr");
        assert_eq!(&kinds[3][..2], &[0, 0]);
        assert!(kinds[4].starts_with(b"M-SEARCH"), "SSDP rung");
        assert!(kinds[5].starts_with(b"M-SEARCH"));
        assert_eq!(env.sent[4].1, SSDP_MULTICAST);
        assert!(mapper.mapped_external(env.now).is_none());

        // Nothing more until the ladder retry backoff elapses.
        env.advance(Duration::from_secs(1));
        mapper.on_timer(&mut env);
        assert_eq!(env.sent.len(), 6);
        env.advance(LADDER_RETRY);
        mapper.on_timer(&mut env);
        assert_eq!(env.sent.len(), 7, "ladder restarts after backoff");
    }

    #[test]
    fn malformed_and_spoofed_gateway_responses_are_inert() {
        let mut env = TestEnv::new();
        let mut mapper = PortMapper::new(config(), env.now);
        mapper.on_timer(&mut env);
        let request = env.sent[0].2.clone();
        let gateway: SocketAddr = "10.7.0.1:5351".parse().unwrap();

        // Junk of every shape.
        for junk in [&[][..], &[2u8][..], &[2u8; 59][..], &[0xffu8; 60][..]] {
            mapper.on_datagram(&mut env, gateway, junk);
        }
        // Right shape, wrong nonce.
        let mut wrong_nonce = pcp_response(&request, 0, 600, 51_000, "198.51.0.8".parse().unwrap());
        wrong_nonce[24] ^= 0xff;
        mapper.on_datagram(&mut env, gateway, &wrong_nonce);
        // Right bytes, wrong source host.
        let resp = pcp_response(&request, 0, 600, 51_000, "198.51.0.8".parse().unwrap());
        mapper.on_datagram(&mut env, "203.0.113.9:5351".parse().unwrap(), &resp);

        assert_eq!(mapper.mapped_external(env.now), None);
        assert!(mapper.malformed_responses > 0);

        // A denial advances the ladder instead of mapping.
        let deny = pcp_response(&request, 2, 0, 0, "198.51.0.8".parse().unwrap());
        mapper.on_datagram(&mut env, gateway, &deny);
        assert_eq!(mapper.mapped_external(env.now), None);
        assert_eq!(mapper.denials, 1);
        assert_eq!(&env.sent.last().unwrap().2[..2], &[0, 0], "fell to NAT-PMP");
    }

    #[test]
    fn ssdp_location_is_pinned_to_the_gateway_host() {
        let mut env = TestEnv::new();
        let mut mapper = PortMapper::new(config(), env.now);
        let step = STEP_TIMEOUT + Duration::from_millis(10);
        // Walk to the SSDP rung.
        for _ in 0..5 {
            mapper.on_timer(&mut env);
            env.advance(step);
        }
        assert!(env.sent.last().unwrap().2.starts_with(b"M-SEARCH"));

        // LOCATION pointing off-gateway must not be followed.
        let evil = "HTTP/1.1 200 OK\r\nLOCATION: http://203.0.113.66:80/desc.xml\r\n\r\n";
        mapper.on_datagram(&mut env, "10.7.0.1:1900".parse().unwrap(), evil.as_bytes());
        assert!(env.tcp.is_empty(), "no TCP connect to a third party");
        assert_eq!(mapper.malformed_responses, 1);

        // The gateway's own LOCATION is followed with a GET.
        let good = "HTTP/1.1 200 OK\r\nLOCATION: http://10.7.0.1:1900/rootDesc.xml\r\n\r\n";
        mapper.on_datagram(&mut env, "10.7.0.1:1900".parse().unwrap(), good.as_bytes());
        assert_eq!(env.tcp.len(), 1);
        assert_eq!(env.tcp[0].1, "10.7.0.1:1900".parse().unwrap());
        let get = String::from_utf8(env.tcp_sent[0].1.clone()).unwrap();
        assert!(get.starts_with("GET /rootDesc.xml"));
    }

    #[test]
    fn pinhole_requests_ride_their_own_nonce() {
        let mut env = TestEnv::new();
        let mut config = config();
        config.internal_v6 = Some("[2001:db8:0:7::2]:51000".parse().unwrap());
        let mut mapper = PortMapper::new(config, env.now);
        mapper.on_timer(&mut env);
        // Two PCP MAPs go out: the v4 map and the v6 pinhole.
        assert_eq!(env.sent.len(), 2);
        let v6_req = env.sent[1].2.clone();
        assert_eq!(v6_req.len(), 60);
        assert_eq!(&v6_req[8..10], &[0x20, 0x01], "pinhole carries the v6 client IP");

        let resp = pcp_response(&v6_req, 0, 600, 51_000, "2001:db8:0:7::2".parse().unwrap());
        mapper.on_datagram(&mut env, "10.7.0.1:5351".parse().unwrap(), &resp);
        assert!(mapper.pinhole_active(env.now));
        assert!(
            mapper.mapped_external(env.now).is_none(),
            "pinhole must not masquerade as the v4 mapping",
        );
    }
}

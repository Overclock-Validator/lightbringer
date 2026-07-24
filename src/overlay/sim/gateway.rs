//! Deterministic home-gateway model (nat-traversal.md §6.3): the LAN-side
//! counterpart of the port-mapping ladder. It answers PCP and NAT-PMP on UDP
//! :5351, SSDP `M-SEARCH` on :1900, and UPnP IGD HTTP/SOAP over the sim's TCP
//! model — with per-tier behavior modes (grant / deny / grant-without-install
//! / malformed / silent) so scenarios can exercise every §4 gateway
//! population. Responses are hand-built from the RFC 6886/6887 and UPnP IGD
//! layouts, deliberately NOT sharing the client codecs in
//! `overlay::portmap` — the ground-truth/inference split that `NatBox` vs the
//! classifier established (a shared codec would let a wrong layout
//! self-agree).

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use super::nat::{FirewallBox, NatBox};

/// PCP and NAT-PMP server port (RFC 6886/6887).
pub const PCP_PORT: u16 = 5351;
/// SSDP + the sim gateway's HTTP endpoint.
pub const UPNP_PORT: u16 = 1900;
/// SSDP discovery multicast group.
pub const SSDP_MULTICAST: SocketAddr = SocketAddr::new(
    IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)),
    UPNP_PORT,
);

/// Cap on a buffered HTTP request (headers + SOAP body).
const MAX_HTTP_REQUEST: usize = 64 * 1024;
/// Concurrent HTTP conns the gateway holds state for.
const MAX_TCP_CONNS: usize = 16;

const PCP_VERSION: u8 = 2;
const PCP_OP_MAP: u8 = 1;
const PCP_RESULT_SUCCESS: u8 = 0;
const PCP_RESULT_NOT_AUTHORIZED: u8 = 2;
const PCP_RESULT_NO_RESOURCES: u8 = 8;

const NATPMP_VERSION: u8 = 0;
const NATPMP_OP_EXTERNAL: u8 = 0;
const NATPMP_OP_MAP_UDP: u8 = 1;
const NATPMP_RESULT_SUCCESS: u16 = 0;
const NATPMP_RESULT_REFUSED: u16 = 2;

/// How one protocol tier of the gateway behaves (§4's empirical gateway
/// population, made configurable).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TierMode {
    /// Protocol absent: requests get no answer at all.
    Off,
    /// Working gateway: grants and installs the mapping/pinhole.
    Grant,
    /// Protocol present but refuses (admin-disabled).
    Deny,
    /// Lying/broken gateway (the CGN-ish case §6.3 guards against): answers
    /// success but installs nothing, so the granted port is unreachable.
    GrantFake,
    /// Firmware garbage: answers deterministic junk bytes.
    Malformed,
}

#[derive(Clone, Debug)]
pub struct GatewayConfig {
    pub pcp: TierMode,
    pub natpmp: TierMode,
    pub upnp: TierMode,
    /// PCP v6 pinhole handling; `None` follows `pcp`.
    pub pcp_v6_pinhole: Option<TierMode>,
    /// Longest lease this gateway grants; shorter requests are honored.
    pub lease: Duration,
}

impl GatewayConfig {
    fn tiers(pcp: TierMode, natpmp: TierMode, upnp: TierMode) -> Self {
        Self {
            pcp,
            natpmp,
            upnp,
            pcp_v6_pinhole: None,
            lease: Duration::from_secs(120),
        }
    }

    /// A current, working gateway: full ladder available.
    pub fn granting() -> Self {
        Self::tiers(TierMode::Grant, TierMode::Grant, TierMode::Grant)
    }

    /// No mapping protocol at all (the ~25-35% "disabled" population).
    pub fn absent() -> Self {
        Self::tiers(TierMode::Off, TierMode::Off, TierMode::Off)
    }

    /// Present but refusing on every tier.
    pub fn denying() -> Self {
        Self::tiers(TierMode::Deny, TierMode::Deny, TierMode::Deny)
    }

    /// Grants but never installs (§6.3: a mapped port a fresh-source probe
    /// cannot reach must not be advertised).
    pub fn grant_fake() -> Self {
        Self::tiers(TierMode::GrantFake, TierMode::GrantFake, TierMode::GrantFake)
    }

    /// No PCP; NAT-PMP works (the pre-PCP Apple-era router).
    pub fn natpmp_only() -> Self {
        Self::tiers(TierMode::Off, TierMode::Grant, TierMode::Off)
    }

    /// Only UPnP IGD works (the most common legacy home router).
    pub fn upnp_only() -> Self {
        Self::tiers(TierMode::Off, TierMode::Off, TierMode::Grant)
    }

    /// Garbage firmware on every tier (the malformed-response oracle).
    pub fn malformed() -> Self {
        Self::tiers(TierMode::Malformed, TierMode::Malformed, TierMode::Malformed)
    }

    pub fn lease(mut self, lease: Duration) -> Self {
        self.lease = lease;
        self
    }

    pub fn v6_pinhole(mut self, mode: TierMode) -> Self {
        self.pcp_v6_pinhole = Some(mode);
        self
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct GatewayStats {
    pub pcp_requests: u64,
    pub natpmp_requests: u64,
    pub ssdp_requests: u64,
    pub http_requests: u64,
    pub grants: u64,
    pub denials: u64,
}

/// One host's LAN gateway. Owned by the sim `Host` next to the NAT chain it
/// programs (always the innermost box — PCP/UPnP never traverses a CGN,
/// which is exactly why §4 calls mapping "useless behind CGN").
pub struct Gateway {
    pub config: GatewayConfig,
    lan_ip: IpAddr,
    /// Per-conn HTTP receive buffers.
    tcp_bufs: BTreeMap<u64, Vec<u8>>,
    pub stats: GatewayStats,
}

impl Gateway {
    pub fn new(config: GatewayConfig, lan_ip: IpAddr) -> Self {
        Self {
            config,
            lan_ip,
            tcp_bufs: BTreeMap::new(),
            stats: GatewayStats::default(),
        }
    }

    pub fn lan_ip(&self) -> IpAddr {
        self.lan_ip
    }

    /// The PCP/NAT-PMP endpoint clients talk to.
    pub fn udp_endpoint(&self) -> SocketAddr {
        SocketAddr::new(self.lan_ip, PCP_PORT)
    }

    /// The HTTP endpoint SSDP advertises.
    fn http_endpoint(&self) -> SocketAddr {
        SocketAddr::new(self.lan_ip, UPNP_PORT)
    }

    /// Whether `dst` addresses this gateway (its LAN IP, or the SSDP
    /// multicast group it listens on).
    pub fn is_gateway_dst(&self, dst: SocketAddr) -> bool {
        dst.ip() == self.lan_ip || dst == SSDP_MULTICAST
    }

    /// Handle a UDP datagram from LAN host `src` addressed to `dst`.
    /// Returns response datagrams as `(gateway source, payload)`.
    pub fn handle_udp(
        &mut self,
        now: u64,
        src: SocketAddr,
        dst: SocketAddr,
        payload: &[u8],
        nat: &mut NatBox,
        firewall: Option<&mut FirewallBox>,
    ) -> Vec<(SocketAddr, Vec<u8>)> {
        match dst.port() {
            PCP_PORT => match payload.first() {
                Some(&PCP_VERSION) => self.handle_pcp(now, src, payload, nat, firewall),
                Some(&NATPMP_VERSION) => self.handle_natpmp(now, src, payload, nat),
                _ => Vec::new(),
            },
            UPNP_PORT => self.handle_ssdp(payload),
            _ => Vec::new(),
        }
    }

    fn granted_lease(&self, requested_secs: u32) -> Duration {
        Duration::from_secs(u64::from(requested_secs)).min(self.config.lease)
    }

    fn epoch(now: u64) -> u32 {
        (now / 1_000_000_000) as u32
    }

    // ---- PCP (RFC 6887) -------------------------------------------------

    fn handle_pcp(
        &mut self,
        now: u64,
        src: SocketAddr,
        payload: &[u8],
        nat: &mut NatBox,
        firewall: Option<&mut FirewallBox>,
    ) -> Vec<(SocketAddr, Vec<u8>)> {
        self.stats.pcp_requests += 1;
        let from = self.udp_endpoint();
        // MAP request: 24-byte header + 36-byte MAP payload.
        if payload.len() != 60 || payload[1] & 0x7f != PCP_OP_MAP {
            return Vec::new();
        }
        let client_ip = ip_from_16(&payload[8..24]);
        let mode = if client_ip.is_ipv6() {
            self.config.pcp_v6_pinhole.unwrap_or(self.config.pcp)
        } else {
            self.config.pcp
        };
        match mode {
            TierMode::Off => Vec::new(),
            TierMode::Malformed => vec![(from, garbage(PCP_VERSION))],
            TierMode::Deny => {
                self.stats.denials += 1;
                vec![(from, pcp_map_response(payload, PCP_RESULT_NOT_AUTHORIZED, 0, Self::epoch(now), 0, client_ip))]
            }
            TierMode::Grant | TierMode::GrantFake => {
                let requested = u32::from_be_bytes(payload[4..8].try_into().expect("len 60"));
                let internal_port = u16::from_be_bytes(payload[40..42].try_into().expect("len 60"));
                let suggested = u16::from_be_bytes(payload[42..44].try_into().expect("len 60"));
                let lease = self.granted_lease(requested);
                let lease_secs = lease.as_secs() as u32;
                if client_ip.is_ipv6() {
                    // v6 pinhole (§6.3): open the firewall for the client's
                    // own port — no rewriting, the "external" is the client.
                    if mode == TierMode::Grant {
                        if let Some(firewall) = firewall {
                            firewall.install_pinhole(now, internal_port, lease);
                        }
                    }
                    self.stats.grants += 1;
                    return vec![(from, pcp_map_response(payload, PCP_RESULT_SUCCESS, lease_secs, Self::epoch(now), internal_port, client_ip))];
                }
                let internal = SocketAddr::new(src.ip(), internal_port);
                let assigned = if mode == TierMode::Grant {
                    nat.install_static(now, internal, suggested, lease)
                } else {
                    Some(if suggested != 0 { suggested } else { internal_port })
                };
                match assigned {
                    Some(port) => {
                        self.stats.grants += 1;
                        vec![(from, pcp_map_response(payload, PCP_RESULT_SUCCESS, lease_secs, Self::epoch(now), port, nat.external_ip))]
                    }
                    None => {
                        self.stats.denials += 1;
                        vec![(from, pcp_map_response(payload, PCP_RESULT_NO_RESOURCES, 0, Self::epoch(now), 0, nat.external_ip))]
                    }
                }
            }
        }
    }

    // ---- NAT-PMP (RFC 6886) ---------------------------------------------

    fn handle_natpmp(
        &mut self,
        now: u64,
        src: SocketAddr,
        payload: &[u8],
        nat: &mut NatBox,
    ) -> Vec<(SocketAddr, Vec<u8>)> {
        self.stats.natpmp_requests += 1;
        let from = self.udp_endpoint();
        let mode = self.config.natpmp;
        if mode == TierMode::Off {
            return Vec::new();
        }
        if mode == TierMode::Malformed {
            return vec![(from, garbage(NATPMP_VERSION))];
        }
        match payload.get(1) {
            Some(&NATPMP_OP_EXTERNAL) if payload.len() == 2 => {
                let external = match nat.external_ip {
                    IpAddr::V4(v4) => v4,
                    IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
                };
                let (result, ip) = if mode == TierMode::Deny {
                    self.stats.denials += 1;
                    (NATPMP_RESULT_REFUSED, Ipv4Addr::UNSPECIFIED)
                } else {
                    (NATPMP_RESULT_SUCCESS, external)
                };
                let mut resp = vec![NATPMP_VERSION, 128];
                resp.extend_from_slice(&result.to_be_bytes());
                resp.extend_from_slice(&Self::epoch(now).to_be_bytes());
                resp.extend_from_slice(&ip.octets());
                vec![(from, resp)]
            }
            Some(&NATPMP_OP_MAP_UDP) if payload.len() == 12 => {
                let internal_port = u16::from_be_bytes(payload[4..6].try_into().expect("len 12"));
                let suggested = u16::from_be_bytes(payload[6..8].try_into().expect("len 12"));
                let requested = u32::from_be_bytes(payload[8..12].try_into().expect("len 12"));
                let lease = self.granted_lease(requested);
                let (result, mapped, lease_secs) = match mode {
                    TierMode::Deny => {
                        self.stats.denials += 1;
                        (NATPMP_RESULT_REFUSED, 0u16, 0u32)
                    }
                    TierMode::Grant => {
                        let internal = SocketAddr::new(src.ip(), internal_port);
                        match nat.install_static(now, internal, suggested, lease) {
                            Some(port) => {
                                self.stats.grants += 1;
                                (NATPMP_RESULT_SUCCESS, port, lease.as_secs() as u32)
                            }
                            None => {
                                self.stats.denials += 1;
                                (NATPMP_RESULT_REFUSED, 0, 0)
                            }
                        }
                    }
                    // GrantFake: success, nothing installed.
                    _ => {
                        self.stats.grants += 1;
                        let port = if suggested != 0 { suggested } else { internal_port };
                        (NATPMP_RESULT_SUCCESS, port, lease.as_secs() as u32)
                    }
                };
                let mut resp = vec![NATPMP_VERSION, 128 + NATPMP_OP_MAP_UDP];
                resp.extend_from_slice(&result.to_be_bytes());
                resp.extend_from_slice(&Self::epoch(now).to_be_bytes());
                resp.extend_from_slice(&internal_port.to_be_bytes());
                resp.extend_from_slice(&mapped.to_be_bytes());
                resp.extend_from_slice(&lease_secs.to_be_bytes());
                vec![(from, resp)]
            }
            _ => Vec::new(),
        }
    }

    // ---- SSDP + UPnP IGD ------------------------------------------------

    fn handle_ssdp(&mut self, payload: &[u8]) -> Vec<(SocketAddr, Vec<u8>)> {
        self.stats.ssdp_requests += 1;
        if self.config.upnp == TierMode::Off {
            return Vec::new();
        }
        let Ok(text) = std::str::from_utf8(payload) else {
            return Vec::new();
        };
        if !text.starts_with("M-SEARCH") {
            return Vec::new();
        }
        let from = self.http_endpoint();
        if self.config.upnp == TierMode::Malformed {
            return vec![(from, b"HTTP/1.1 200 OK\r\nLOCATION:\x00\xff\xfe\r\n".to_vec())];
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             CACHE-CONTROL: max-age=120\r\n\
             ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
             USN: uuid:sim-gateway::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
             LOCATION: http://{}/rootDesc.xml\r\n\r\n",
            self.http_endpoint(),
        );
        vec![(from, response.into_bytes())]
    }

    /// A TCP connect from the LAN host reached us. Accepts only the HTTP
    /// endpoint of an advertised (non-Off) UPnP tier.
    pub fn tcp_open(&mut self, conn: u64, to: SocketAddr) -> bool {
        if self.config.upnp == TierMode::Off || to != self.http_endpoint() {
            return false;
        }
        if self.tcp_bufs.len() >= MAX_TCP_CONNS {
            return false;
        }
        self.tcp_bufs.insert(conn, Vec::new());
        true
    }

    pub fn tcp_closed(&mut self, conn: u64) {
        self.tcp_bufs.remove(&conn);
    }

    /// Bytes arrived on an accepted HTTP conn; returns response chunks once
    /// a complete request is buffered.
    pub fn tcp_bytes(
        &mut self,
        now: u64,
        conn: u64,
        bytes: &[u8],
        nat: &mut NatBox,
    ) -> Vec<Vec<u8>> {
        let Some(buf) = self.tcp_bufs.get_mut(&conn) else {
            return Vec::new();
        };
        buf.extend_from_slice(bytes);
        if buf.len() > MAX_HTTP_REQUEST {
            self.tcp_bufs.remove(&conn);
            return Vec::new();
        }
        let Some((request, consumed)) = parse_http_request(buf) else {
            return Vec::new();
        };
        let buffered = std::mem::take(buf);
        buf.extend_from_slice(&buffered[consumed..]);
        self.stats.http_requests += 1;
        self.dispatch_http(now, request, nat)
    }

    fn dispatch_http(&mut self, now: u64, request: HttpRequest, nat: &mut NatBox) -> Vec<Vec<u8>> {
        if self.config.upnp == TierMode::Malformed {
            return vec![b"HTTP\x00/1.1 garbage\r\n\r\n<not-xml".to_vec()];
        }
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/rootDesc.xml") => vec![http_ok(&device_description())],
            ("POST", "/ctl/IPConn") => {
                let body = request.body;
                if body.contains("GetExternalIPAddress") {
                    let ip = match nat.external_ip {
                        IpAddr::V4(v4) => v4.to_string(),
                        IpAddr::V6(v6) => v6.to_string(),
                    };
                    vec![http_ok(&soap_body(
                        "GetExternalIPAddressResponse",
                        &format!("<NewExternalIPAddress>{ip}</NewExternalIPAddress>"),
                    ))]
                } else if body.contains("AddPortMapping") {
                    self.add_port_mapping(now, &body, nat)
                } else {
                    vec![soap_error(401, "Invalid Action")]
                }
            }
            _ => vec![b"HTTP/1.1 404 Not Found\r\nCONTENT-LENGTH: 0\r\n\r\n".to_vec()],
        }
    }

    fn add_port_mapping(&mut self, now: u64, body: &str, nat: &mut NatBox) -> Vec<Vec<u8>> {
        if self.config.upnp == TierMode::Deny {
            self.stats.denials += 1;
            return vec![soap_error(718, "ConflictInMappingEntry")];
        }
        let external = xml_field(body, "NewExternalPort").and_then(|v| v.parse::<u16>().ok());
        let internal_port = xml_field(body, "NewInternalPort").and_then(|v| v.parse::<u16>().ok());
        let client = xml_field(body, "NewInternalClient").and_then(|v| v.parse::<IpAddr>().ok());
        let lease_secs = xml_field(body, "NewLeaseDuration")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        let (Some(external), Some(internal_port), Some(client)) = (external, internal_port, client)
        else {
            return vec![soap_error(402, "Invalid Args")];
        };
        // UPnP grants exactly the requested external port or errors; a
        // lease of 0 means permanent — model it as the gateway's max.
        let lease = if lease_secs == 0 {
            self.config.lease
        } else {
            self.granted_lease(lease_secs)
        };
        if self.config.upnp == TierMode::Grant {
            let internal = SocketAddr::new(client, internal_port);
            match nat.install_static(now, internal, external, lease) {
                Some(port) if port == external => {}
                Some(port) => {
                    // Assigned elsewhere: undo and refuse, per AddPortMapping
                    // semantics (no port negotiation in IGDv1).
                    nat.remove_static(internal, port);
                    self.stats.denials += 1;
                    return vec![soap_error(718, "ConflictInMappingEntry")];
                }
                None => {
                    self.stats.denials += 1;
                    return vec![soap_error(718, "ConflictInMappingEntry")];
                }
            }
        }
        self.stats.grants += 1;
        vec![http_ok(&soap_body("AddPortMappingResponse", ""))]
    }
}

// ---- wire helpers -------------------------------------------------------

fn ip_from_16(bytes: &[u8]) -> IpAddr {
    let octets: [u8; 16] = bytes.try_into().expect("16-byte IP field");
    let v6 = Ipv6Addr::from(octets);
    match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    }
}

fn ip_to_16(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Deterministic junk that still leads with a plausible version byte, so
/// clients cannot shortcut on byte 0.
fn garbage(version: u8) -> Vec<u8> {
    let mut junk = vec![version];
    junk.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
    junk
}

fn pcp_map_response(
    request: &[u8],
    result: u8,
    lifetime: u32,
    epoch: u32,
    assigned_port: u16,
    assigned_ip: IpAddr,
) -> Vec<u8> {
    let mut resp = Vec::with_capacity(60);
    resp.push(PCP_VERSION);
    resp.push(0x80 | PCP_OP_MAP);
    resp.push(0);
    resp.push(result);
    resp.extend_from_slice(&lifetime.to_be_bytes());
    resp.extend_from_slice(&epoch.to_be_bytes());
    resp.extend_from_slice(&[0u8; 12]);
    // MAP payload: nonce + protocol copied from the request.
    resp.extend_from_slice(&request[24..36]);
    resp.push(request[36]);
    resp.extend_from_slice(&[0u8; 3]);
    resp.extend_from_slice(&request[40..42]);
    resp.extend_from_slice(&assigned_port.to_be_bytes());
    resp.extend_from_slice(&ip_to_16(assigned_ip));
    resp
}

struct HttpRequest {
    method: String,
    path: String,
    body: String,
}

/// Parse one complete HTTP request off the front of `buf`; returns it and
/// the bytes consumed, or `None` while incomplete.
fn parse_http_request(buf: &[u8]) -> Option<(HttpRequest, usize)> {
    let text = std::str::from_utf8(buf).ok()?;
    let header_end = text.find("\r\n\r\n")? + 4;
    let headers = &text[..header_end];
    let mut lines = headers.split("\r\n");
    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_string();
    let path = request_line.next()?.to_string();
    let content_length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    if buf.len() < header_end + content_length {
        return None;
    }
    let body = std::str::from_utf8(&buf[header_end..header_end + content_length])
        .ok()?
        .to_string();
    Some((
        HttpRequest { method, path, body },
        header_end + content_length,
    ))
}

fn http_ok(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nCONTENT-TYPE: text/xml; charset=\"utf-8\"\r\nCONTENT-LENGTH: {}\r\n\r\n{}",
        body.len(),
        body,
    )
    .into_bytes()
}

fn soap_body(action_response: &str, fields: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">\
         <s:Body><u:{action_response} xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\
         {fields}</u:{action_response}></s:Body></s:Envelope>"
    )
}

fn soap_error(code: u32, description: &str) -> Vec<u8> {
    let body = format!(
        "<?xml version=\"1.0\"?>\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">\
         <s:Body><s:Fault><detail><UPnPError>\
         <errorCode>{code}</errorCode><errorDescription>{description}</errorDescription>\
         </UPnPError></detail></s:Fault></s:Body></s:Envelope>"
    );
    format!(
        "HTTP/1.1 500 Internal Server Error\r\nCONTENT-TYPE: text/xml\r\nCONTENT-LENGTH: {}\r\n\r\n{}",
        body.len(),
        body,
    )
    .into_bytes()
}

fn device_description() -> String {
    "<?xml version=\"1.0\"?>\
     <root xmlns=\"urn:schemas-upnp-org:device-1-0\">\
     <device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>\
     <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>\
     <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>\
     <serviceList><service>\
     <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
     <controlURL>/ctl/IPConn</controlURL>\
     </service></serviceList></device></deviceList></device></deviceList></device></root>"
        .to_string()
}

/// First `<tag>value</tag>` occurrence in `body`.
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
    use crate::overlay::sim::nat::{FirewallConfig, NatConfig};

    fn gw(config: GatewayConfig) -> (Gateway, NatBox) {
        let lan_ip: IpAddr = "10.7.0.1".parse().unwrap();
        let nat = NatBox::new(
            NatConfig::port_restricted_cone(),
            "198.51.0.8".parse().unwrap(),
            7,
        );
        (Gateway::new(config, lan_ip), nat)
    }

    fn natpmp_map_request(internal: u16, suggested: u16, lifetime: u32) -> Vec<u8> {
        let mut req = vec![0, 1, 0, 0];
        req.extend_from_slice(&internal.to_be_bytes());
        req.extend_from_slice(&suggested.to_be_bytes());
        req.extend_from_slice(&lifetime.to_be_bytes());
        req
    }

    fn pcp_map_request(client: IpAddr, internal: u16, suggested: u16, lifetime: u32) -> Vec<u8> {
        let mut req = vec![2, 1, 0, 0];
        req.extend_from_slice(&lifetime.to_be_bytes());
        req.extend_from_slice(&ip_to_16(client));
        req.extend_from_slice(&[0x11u8; 12]); // nonce
        req.push(17); // UDP
        req.extend_from_slice(&[0u8; 3]);
        req.extend_from_slice(&internal.to_be_bytes());
        req.extend_from_slice(&suggested.to_be_bytes());
        req.extend_from_slice(&ip_to_16(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        req
    }

    #[test]
    fn natpmp_grant_installs_lease_mapping() {
        let (mut gateway, mut nat) = gw(GatewayConfig::granting());
        let src: SocketAddr = "10.7.0.2:51000".parse().unwrap();
        let responses = gateway.handle_udp(
            0,
            src,
            gateway.udp_endpoint(),
            &natpmp_map_request(51_000, 51_000, 3600),
            &mut nat,
            None,
        );
        assert_eq!(responses.len(), 1);
        let (_, resp) = &responses[0];
        assert_eq!(resp[1], 129);
        assert_eq!(u16::from_be_bytes([resp[2], resp[3]]), 0, "success");
        let mapped = u16::from_be_bytes([resp[10], resp[11]]);
        assert_eq!(mapped, 51_000);
        // Granted lease clamps to the gateway max (120s < 3600s).
        assert_eq!(u32::from_be_bytes([resp[12], resp[13], resp[14], resp[15]]), 120);
        assert!(nat.static_map_live(0, mapped));
        // Inbound from a never-contacted source passes the lease mapping.
        let stranger: SocketAddr = "203.0.113.99:4242".parse().unwrap();
        let external = SocketAddr::new(nat.external_ip, mapped);
        assert_eq!(nat.inbound(1, stranger, external), Ok(src));
    }

    #[test]
    fn pcp_grant_deny_fake_and_off_behave_per_mode() {
        let src: SocketAddr = "10.7.0.2:51000".parse().unwrap();
        let client = IpAddr::V4("10.7.0.2".parse().unwrap());
        let req = pcp_map_request(client, 51_000, 51_000, 600);

        let (mut gateway, mut nat) = gw(GatewayConfig::granting());
        let responses = gateway.handle_udp(0, src, gateway.udp_endpoint(), &req, &mut nat, None);
        let (_, resp) = &responses[0];
        assert_eq!(resp[3], 0, "success result");
        assert_eq!(u16::from_be_bytes([resp[42], resp[43]]), 51_000);
        assert!(nat.static_map_live(0, 51_000));

        let (mut gateway, mut nat) = gw(GatewayConfig::denying());
        let responses = gateway.handle_udp(0, src, gateway.udp_endpoint(), &req, &mut nat, None);
        assert_eq!(responses[0].1[3], PCP_RESULT_NOT_AUTHORIZED);
        assert!(!nat.static_map_live(0, 51_000));

        let (mut gateway, mut nat) = gw(GatewayConfig::grant_fake());
        let responses = gateway.handle_udp(0, src, gateway.udp_endpoint(), &req, &mut nat, None);
        assert_eq!(responses[0].1[3], 0, "fake grant answers success");
        assert!(!nat.static_map_live(0, 51_000), "but installs nothing");

        let (mut gateway, mut nat) = gw(GatewayConfig::absent());
        let responses = gateway.handle_udp(0, src, gateway.udp_endpoint(), &req, &mut nat, None);
        assert!(responses.is_empty(), "absent tier stays silent");
    }

    #[test]
    fn pcp_v6_request_installs_firewall_pinhole() {
        let (mut gateway, mut nat) = gw(GatewayConfig::granting());
        let mut firewall = FirewallBox::new(FirewallConfig::default());
        let client: IpAddr = "2001:db8:0:7::2".parse().unwrap();
        let src: SocketAddr = "10.7.0.2:51000".parse().unwrap();
        let req = pcp_map_request(client, 51_000, 51_000, 600);
        let responses = gateway.handle_udp(
            0,
            src,
            gateway.udp_endpoint(),
            &req,
            &mut nat,
            Some(&mut firewall),
        );
        assert_eq!(responses[0].1[3], 0);
        assert!(firewall.pinhole_live(0, 51_000));
        assert!(!nat.static_map_live(0, 51_000), "pinhole touches only the firewall");
    }

    #[test]
    fn upnp_flow_describes_and_maps() {
        let (mut gateway, mut nat) = gw(GatewayConfig::upnp_only());
        // SSDP discovery.
        let msearch = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
        let responses = gateway.handle_udp(
            0,
            "10.7.0.2:49152".parse().unwrap(),
            SSDP_MULTICAST,
            msearch,
            &mut nat,
            None,
        );
        let text = String::from_utf8(responses[0].1.clone()).unwrap();
        assert!(text.contains("LOCATION: http://10.7.0.1:1900/rootDesc.xml"));

        // HTTP description.
        assert!(gateway.tcp_open(1, "10.7.0.1:1900".parse().unwrap()));
        let get = b"GET /rootDesc.xml HTTP/1.1\r\nHOST: 10.7.0.1:1900\r\n\r\n";
        let desc = gateway.tcp_bytes(0, 1, get, &mut nat);
        let desc = String::from_utf8(desc.concat()).unwrap();
        assert!(desc.contains("WANIPConnection:1"));
        assert!(desc.contains("<controlURL>/ctl/IPConn</controlURL>"));

        // SOAP AddPortMapping.
        let soap = "<?xml version=\"1.0\"?><s:Envelope><s:Body><u:AddPortMapping>\
            <NewRemoteHost></NewRemoteHost><NewExternalPort>51000</NewExternalPort>\
            <NewProtocol>UDP</NewProtocol><NewInternalPort>51000</NewInternalPort>\
            <NewInternalClient>10.7.0.2</NewInternalClient><NewEnabled>1</NewEnabled>\
            <NewPortMappingDescription>t</NewPortMappingDescription>\
            <NewLeaseDuration>600</NewLeaseDuration></u:AddPortMapping></s:Body></s:Envelope>";
        let post = format!(
            "POST /ctl/IPConn HTTP/1.1\r\nHOST: 10.7.0.1:1900\r\nSOAPACTION: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nCONTENT-LENGTH: {}\r\n\r\n{}",
            soap.len(),
            soap,
        );
        let resp = gateway.tcp_bytes(0, 1, post.as_bytes(), &mut nat);
        let resp = String::from_utf8(resp.concat()).unwrap();
        assert!(resp.starts_with("HTTP/1.1 200"));
        assert!(nat.static_map_live(0, 51_000));
    }

    #[test]
    fn upnp_deny_and_split_delivery_and_malformed_are_handled() {
        // Deny: SOAP 718 error, no install.
        let (mut gateway, mut nat) = gw(GatewayConfig::denying());
        assert!(gateway.tcp_open(1, "10.7.0.1:1900".parse().unwrap()));
        let soap = "<u:AddPortMapping><NewExternalPort>51000</NewExternalPort>\
            <NewInternalPort>51000</NewInternalPort><NewInternalClient>10.7.0.2</NewInternalClient>\
            <NewLeaseDuration>600</NewLeaseDuration></u:AddPortMapping>";
        let post = format!(
            "POST /ctl/IPConn HTTP/1.1\r\nCONTENT-LENGTH: {}\r\n\r\n{}",
            soap.len(),
            soap,
        );
        // Deliver the request split across arbitrary chunk boundaries.
        let bytes = post.as_bytes();
        let mut responses = Vec::new();
        for chunk in bytes.chunks(7) {
            responses.extend(gateway.tcp_bytes(0, 1, chunk, &mut nat));
        }
        let resp = String::from_utf8(responses.concat()).unwrap();
        assert!(resp.contains("718"));
        assert!(!nat.static_map_live(0, 51_000));

        // Junk bytes on the wire never panic and never install.
        let (mut gateway, mut nat) = gw(GatewayConfig::granting());
        for junk in [&b"\xff\xfe\xfd"[..], &[2u8; 59], &[0u8; 11], &[]] {
            let _ = gateway.handle_udp(
                0,
                "10.7.0.2:51000".parse().unwrap(),
                gateway.udp_endpoint(),
                junk,
                &mut nat,
                None,
            );
        }
        assert!(!nat.static_map_live(0, 51_000));
    }

    #[test]
    fn lease_expiry_and_renewal() {
        let (mut gateway, mut nat) = gw(GatewayConfig::granting().lease(Duration::from_secs(60)));
        let src: SocketAddr = "10.7.0.2:51000".parse().unwrap();
        let req = natpmp_map_request(51_000, 51_000, 60);
        gateway.handle_udp(0, src, gateway.udp_endpoint(), &req, &mut nat, None);
        let nanos = |secs: u64| secs * 1_000_000_000;
        assert!(nat.static_map_live(nanos(59), 51_000));
        assert!(!nat.static_map_live(nanos(61), 51_000));
        // Renewal at half-life extends the lease.
        gateway.handle_udp(nanos(30), src, gateway.udp_endpoint(), &req, &mut nat, None);
        assert!(nat.static_map_live(nanos(89), 51_000));
        assert_eq!(nat.stats.static_installs, 2);
    }
}

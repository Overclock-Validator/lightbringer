//! P4 port-mapping client safety oracles (nat-traversal.md §6.3 ladder, §6.9
//! sans-IO seam, §9 untrusted-gateway hardening). These drive
//! [`PortMapper`] directly against a recording [`TestEnv`] with a manually
//! advanced virtual clock — no `SimWorld` — and hand-build gateway responses
//! byte-for-byte (the ground-truth/inference split of `sim::gateway`: the
//! client codec is never shared, so a wrong layout cannot self-agree).
//!
//! The behavioral constants the client uses are private, so every assertion
//! is expressed through observable behavior (sends emitted, mapping exposed,
//! deadlines scheduled) rather than the constants themselves.

use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

use anyhow::Result;
use rand::{RngCore, SeedableRng, rngs::StdRng};

use crate::overlay::env::{IpFamily, OverlayEnv, SocketId, TcpEvent, TcpId};
use crate::overlay::portmap::{MapProtocol, PortMapConfig, PortMapper};

// ---- harness ------------------------------------------------------------

/// Recording env: captures every `send`/`tcp_connect`/`tcp_send`/`tcp_close`
/// the client issues, hands out monotonic socket/stream ids, and carries a
/// virtual clock the test advances by hand. `bind_fails` models a platform
/// that cannot hand out the port-map UDP socket (§6.9: the driver owns the
/// socket; the core must tolerate its absence).
struct TestEnv {
    now: Instant,
    rng: StdRng,
    sent: Vec<(SocketId, SocketAddr, Vec<u8>)>,
    tcp: Vec<(TcpId, SocketAddr)>,
    tcp_sent: Vec<(TcpId, Vec<u8>)>,
    closed: VecDeque<TcpId>,
    next_socket: u32,
    next_tcp: u64,
    bind_fails: bool,
}

impl TestEnv {
    fn new() -> Self {
        Self {
            now: Instant::now(),
            rng: StdRng::seed_from_u64(7),
            sent: Vec::new(),
            tcp: Vec::new(),
            tcp_sent: Vec::new(),
            closed: VecDeque::new(),
            next_socket: 1,
            next_tcp: 0,
            bind_fails: false,
        }
    }

    fn new_bind_fails() -> Self {
        Self {
            bind_fails: true,
            ..Self::new()
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
        if self.bind_fails {
            return Err(anyhow::anyhow!("bind unavailable"));
        }
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

// ---- fixtures -----------------------------------------------------------

/// The gateway's PCP/NAT-PMP endpoint used across the file.
fn gw() -> SocketAddr {
    "10.7.0.1:5351".parse().unwrap()
}

/// A NATed subject binding in-pool on 51000 (the §12-Q3 default port), with
/// its LAN IP behind the gateway.
fn config() -> PortMapConfig {
    PortMapConfig {
        gateway: gw(),
        internal_port: 51_000,
        internal_ip: "10.7.0.2".parse().unwrap(),
        internal_v6: None,
    }
}

/// Dual-stack variant: a v6 overlay socket that draws a PCP pinhole (§6.3).
fn config_v6() -> PortMapConfig {
    PortMapConfig {
        internal_v6: Some("[2001:db8:0:7::2]:51000".parse().unwrap()),
        ..config()
    }
}

/// One virtual per-rung timeout plus a hair of slack (the client's step
/// timeout is 2s; asserted only behaviorally).
fn advance_step(env: &mut TestEnv) {
    env.advance(Duration::from_millis(2_100));
}

/// Past the ~60s ladder/pinhole retry backoff.
fn advance_backoff(env: &mut TestEnv) {
    env.advance(Duration::from_secs(61));
}

/// v4-mapped-or-native 16-byte IP field, matching the client codec so a
/// hand-built response round-trips through `parse_pcp_map_response`.
fn ip_to_16(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// A 60-byte PCP MAP response echoing the request nonce/protocol/internal
/// port (RFC 6887 layout: version 2, opcode 0x81, result at byte 3, lifetime
/// 4..8, nonce 24..36, external port 42..44, external IP 44..60).
fn pcp_response(request: &[u8], result: u8, lifetime: u32, port: u16, ip: IpAddr) -> Vec<u8> {
    let mut resp = vec![2u8, 0x81, 0, result];
    resp.extend_from_slice(&lifetime.to_be_bytes());
    resp.extend_from_slice(&0u32.to_be_bytes()); // epoch
    resp.extend_from_slice(&[0u8; 12]); // reserved
    resp.extend_from_slice(&request[24..36]); // nonce echo
    resp.push(17); // protocol (UDP)
    resp.extend_from_slice(&[0u8; 3]);
    resp.extend_from_slice(&request[40..42]); // internal port echo
    resp.extend_from_slice(&port.to_be_bytes());
    resp.extend_from_slice(&ip_to_16(ip));
    resp
}

/// A 12-byte NAT-PMP external-address response (opcode 128, result 2..4,
/// external v4 IP 8..12; RFC 6886).
fn natpmp_external_response(result: u16, ip: Ipv4Addr) -> Vec<u8> {
    let mut resp = vec![0u8, 128];
    resp.extend_from_slice(&result.to_be_bytes());
    resp.extend_from_slice(&0u32.to_be_bytes()); // epoch
    resp.extend_from_slice(&ip.octets());
    resp
}

/// A 16-byte NAT-PMP UDP map response (opcode 129, result 2..4, mapped port
/// 10..12, lifetime 12..16).
fn natpmp_map_response(result: u16, internal: u16, mapped: u16, lifetime: u32) -> Vec<u8> {
    let mut resp = vec![0u8, 129];
    resp.extend_from_slice(&result.to_be_bytes());
    resp.extend_from_slice(&0u32.to_be_bytes()); // epoch
    resp.extend_from_slice(&internal.to_be_bytes());
    resp.extend_from_slice(&mapped.to_be_bytes());
    resp.extend_from_slice(&lifetime.to_be_bytes());
    resp
}

/// An HTTP 200 with a declared content-length.
fn http_ok(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nCONTENT-TYPE: text/xml\r\nCONTENT-LENGTH: {}\r\n\r\n{}",
        body.len(),
        body,
    )
    .into_bytes()
}

/// IGD device description carrying the WANIPConnection service + control URL
/// the client scrapes.
fn device_description() -> String {
    "<?xml version=\"1.0\"?>\
     <root xmlns=\"urn:schemas-upnp-org:device-1-0\">\
     <device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>\
     <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>\
     <serviceList><service>\
     <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
     <controlURL>/ctl/IPConn</controlURL>\
     </service></serviceList></device></deviceList></device></root>"
        .to_string()
}

fn external_ip_body(ip: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?><s:Envelope><s:Body>\
         <u:GetExternalIPAddressResponse><NewExternalIPAddress>{ip}</NewExternalIPAddress>\
         </u:GetExternalIPAddressResponse></s:Body></s:Envelope>"
    )
}

fn add_map_body() -> String {
    "<?xml version=\"1.0\"?><s:Envelope><s:Body>\
     <u:AddPortMappingResponse></u:AddPortMappingResponse></s:Body></s:Envelope>"
        .to_string()
}

/// Silence PCP + NAT-PMP by letting both rungs time out, landing on the SSDP
/// rung (last send is an `M-SEARCH`). Assumes a fresh `Idle` start.
fn walk_to_ssdp(env: &mut TestEnv, mapper: &mut PortMapper) {
    mapper.on_timer(env); // PCP #1
    for _ in 0..4 {
        advance_step(env);
        mapper.on_timer(env); // PCP #2, NAT-PMP ext #1/#2, SSDP #1
    }
    assert!(
        env.sent.last().unwrap().2.starts_with(b"M-SEARCH"),
        "walk should terminate on the SSDP rung",
    );
}

/// Answer the SSDP `M-SEARCH` with a LOCATION on the gateway host; returns
/// the TCP stream the client opened for the device description.
fn answer_location(env: &mut TestEnv, mapper: &mut PortMapper) -> TcpId {
    let good = b"HTTP/1.1 200 OK\r\nLOCATION: http://10.7.0.1:1900/rootDesc.xml\r\n\r\n";
    mapper.on_datagram(env, "10.7.0.1:1900".parse().unwrap(), good);
    env.tcp.last().expect("device-description connect").0
}

/// Deliver an HTTP response split into `chunk`-byte `Data` events.
fn feed_http(env: &mut TestEnv, mapper: &mut PortMapper, conn: TcpId, response: &[u8], chunk: usize) {
    for part in response.chunks(chunk.max(1)) {
        mapper.on_tcp_event(env, TcpEvent::Data(conn, part.to_vec()));
    }
}

fn ext() -> IpAddr {
    "198.51.0.8".parse().unwrap()
}

// ---- oracles ------------------------------------------------------------

/// §6.9 deadline discipline: after every `on_timer` at any point in the
/// ladder → grant → renewal lifecycle, `poll_timeout()` is strictly in the
/// future. A deadline at or before `now` would spin the driver's timer loop,
/// so this is the regression guard the client's own doc-comment promises.
#[test]
fn poll_timeout_is_always_strictly_future() {
    let mut env = TestEnv::new();
    let mut mapper = PortMapper::new(config(), env.now);

    macro_rules! tick {
        () => {{
            mapper.on_timer(&mut env);
            assert!(
                mapper.poll_timeout().unwrap() > env.now,
                "poll_timeout must stay strictly future after on_timer",
            );
        }};
    }

    // Silent ladder, all the way to the failed → backoff transition.
    tick!(); // PCP #1
    for _ in 0..6 {
        advance_step(&mut env);
        tick!(); // PCP #2, NAT-PMP ext x2, SSDP x2, then ladder-failed idle
    }

    // Restart, grant, and a renewal cycle.
    advance_backoff(&mut env);
    tick!(); // PCP #1 of the restart
    let request = env.sent.last().unwrap().2.clone();
    mapper.on_datagram(&mut env, gw(), &pcp_response(&request, 0, 600, 51_000, ext()));
    tick!(); // idle at half-life; nothing due yet
    env.advance(Duration::from_secs(301));
    tick!(); // half-life renewal fires
    env.advance(Duration::from_secs(400));
    tick!(); // original lease lapses, candidate withdrawn
}

/// §6.3 ladder walk + §6.3 backoff restart: a silent gateway draws exactly
/// two PCP MAPs, two NAT-PMP external-address probes, and two SSDP
/// `M-SEARCH`es (each rung retransmits once), then goes quiet for the retry
/// backoff before restarting the whole ladder from PCP.
#[test]
fn silent_gateway_walks_ladder_then_restarts_after_backoff() {
    let mut env = TestEnv::new();
    let mut mapper = PortMapper::new(config(), env.now);

    mapper.on_timer(&mut env); // PCP #1
    for _ in 0..6 {
        advance_step(&mut env);
        mapper.on_timer(&mut env);
    }

    let kinds: Vec<&[u8]> = env.sent.iter().map(|(_, _, b)| b.as_slice()).collect();
    assert_eq!(kinds.len(), 6, "exactly two attempts per rung, three rungs");
    assert!(kinds[0][0] == 2 && kinds[0].len() == 60, "PCP #1 is a 60-byte v2 request");
    assert!(kinds[1][0] == 2 && kinds[1].len() == 60, "PCP #2");
    assert_eq!(&kinds[2][..2], &[0, 0], "NAT-PMP external-addr #1");
    assert_eq!(&kinds[3][..2], &[0, 0], "NAT-PMP external-addr #2");
    assert!(kinds[4].starts_with(b"M-SEARCH"), "SSDP #1");
    assert!(kinds[5].starts_with(b"M-SEARCH"), "SSDP #2");
    assert_eq!(
        env.sent[4].1,
        "239.255.255.250:1900".parse().unwrap(),
        "SSDP goes to the discovery multicast group",
    );
    assert!(mapper.mapped_external(env.now).is_none());

    // Quiet until the backoff elapses, then the ladder restarts from PCP.
    env.advance(Duration::from_secs(1));
    mapper.on_timer(&mut env);
    assert_eq!(env.sent.len(), 6, "no traffic during the backoff");
    advance_backoff(&mut env);
    mapper.on_timer(&mut env);
    assert_eq!(env.sent.len(), 7, "ladder restarts after the backoff");
    assert_eq!(env.sent[6].2[0], 2, "restart begins at the PCP rung");
}

/// §6.3 deny cascade: a PCP denial (result byte 2 in a valid, nonce-echoing
/// 60-byte response) advances immediately to NAT-PMP; a NAT-PMP
/// external-address denial (result u16 = 2 in a 12-byte opcode-128 response)
/// advances to SSDP. Each refusal is counted in `denials`.
#[test]
fn denials_cascade_pcp_to_natpmp_to_ssdp() {
    let mut env = TestEnv::new();
    let mut mapper = PortMapper::new(config(), env.now);

    mapper.on_timer(&mut env); // PCP #1
    let request = env.sent[0].2.clone();

    let deny_pcp = pcp_response(&request, 2, 0, 0, ext());
    mapper.on_datagram(&mut env, gw(), &deny_pcp);
    assert_eq!(mapper.denials, 1, "PCP refusal counted");
    assert_eq!(&env.sent.last().unwrap().2[..2], &[0, 0], "advanced to NAT-PMP");

    let deny_natpmp = natpmp_external_response(2, Ipv4Addr::UNSPECIFIED);
    mapper.on_datagram(&mut env, gw(), &deny_natpmp);
    assert_eq!(mapper.denials, 2, "NAT-PMP refusal counted");
    assert!(env.sent.last().unwrap().2.starts_with(b"M-SEARCH"), "advanced to SSDP");
    assert!(mapper.mapped_external(env.now).is_none());
}

/// §9 malformed inertness: an untrusted gateway can answer anything. A table
/// of garbage — at each protocol rung it can reach — must never mint a
/// mapping, never panic, always bump `malformed_responses` where a parse was
/// attempted, and above all never wedge the machine: a clean grant still
/// completes afterward.
#[test]
fn malformed_gateway_traffic_is_inert_and_never_wedges() {
    let mut env = TestEnv::new();
    let mut mapper = PortMapper::new(config(), env.now);

    // --- PCP rung ---
    mapper.on_timer(&mut env);
    let request = env.sent[0].2.clone();
    let mut wrong_nonce = pcp_response(&request, 0, 600, 51_000, ext());
    wrong_nonce[24] ^= 0xff;
    let pcp_junk: Vec<Vec<u8>> = vec![
        Vec::new(),          // empty
        vec![2u8],           // one byte
        vec![2u8; 59],       // one short of a PCP response
        vec![2u8; 61],       // one long
        vec![0xffu8; 60],    // right length, all-ones
        wrong_nonce,         // valid header, wrong nonce
    ];
    let start = mapper.malformed_responses;
    for junk in &pcp_junk {
        mapper.on_datagram(&mut env, gw(), junk);
        assert!(mapper.mapped_external(env.now).is_none());
    }
    // Right bytes from a spoofed source host: dropped before any parse.
    let spoof = pcp_response(&request, 0, 600, 51_000, ext());
    mapper.on_datagram(&mut env, "203.0.113.9:5351".parse().unwrap(), &spoof);
    assert!(mapper.mapped_external(env.now).is_none());
    assert!(mapper.malformed_responses > start, "malformed PCP shapes were counted");
    assert_eq!(env.sent.len(), 1, "inert junk never advances the PCP rung");

    // --- SSDP rung ---
    for _ in 0..4 {
        advance_step(&mut env);
        mapper.on_timer(&mut env);
    }
    let before_ssdp = mapper.malformed_responses;
    let ssdp_src: SocketAddr = "10.7.0.1:1900".parse().unwrap();
    mapper.on_datagram(&mut env, ssdp_src, &[0xff, 0xfe, 0xfd]); // non-UTF8
    mapper.on_datagram(
        &mut env,
        ssdp_src,
        b"HTTP/1.1 200 OK\r\nLOCATION: http://gateway.local:1900/desc.xml\r\n\r\n", // DNS host
    );
    mapper.on_datagram(
        &mut env,
        ssdp_src,
        b"HTTP/1.1 200 OK\r\nLOCATION: http://203.0.113.9:1900/desc.xml\r\n\r\n", // off-gateway
    );
    assert!(env.tcp.is_empty(), "no HTTP conversation opened toward a third party");
    assert!(mapper.malformed_responses > before_ssdp, "malformed SSDP frames counted");

    // --- UPnP HTTP rung: a non-200 device description ---
    let describe = answer_location(&mut env, &mut mapper);
    let before_http = mapper.malformed_responses;
    mapper.on_tcp_event(
        &mut env,
        TcpEvent::Data(describe, b"HTTP/1.1 500 Error\r\nCONTENT-LENGTH: 0\r\n\r\n".to_vec()),
    );
    assert!(mapper.malformed_responses > before_http, "bad HTTP status counted");
    assert!(mapper.mapped_external(env.now).is_none());

    // --- UPnP HTTP rung: an oversized (>64KB) response body ---
    advance_backoff(&mut env);
    walk_to_ssdp(&mut env, &mut mapper);
    let describe2 = answer_location(&mut env, &mut mapper);
    let before_overflow = mapper.malformed_responses;
    let filler = vec![b'A'; 1024];
    for _ in 0..66 {
        mapper.on_tcp_event(&mut env, TcpEvent::Data(describe2, filler.clone()));
    }
    assert!(mapper.malformed_responses > before_overflow, "oversized body counted");
    assert!(mapper.mapped_external(env.now).is_none());

    // --- Not wedged: a clean PCP grant still lands ---
    advance_backoff(&mut env);
    mapper.on_timer(&mut env);
    let fresh = env.sent.last().unwrap().2.clone();
    assert_eq!(fresh.len(), 60, "restart re-emits a PCP request");
    mapper.on_datagram(&mut env, gw(), &pcp_response(&fresh, 0, 600, 51_000, ext()));
    assert_eq!(
        mapper.mapped_external(env.now),
        Some("198.51.0.8:51000".parse().unwrap()),
        "the machine recovers to a normal grant after all the garbage",
    );
    assert_eq!(mapper.mapped_protocol(env.now), Some(MapProtocol::Pcp));
}

/// §6.3 lease lifecycle: a 600s grant is live immediately; a renewal PCP is
/// emitted at half-life (between 300s and 600s). Answered, the mapping
/// extends past the original expiry; unanswered, the candidate is withdrawn
/// once the original lease lapses.
#[test]
fn lease_renews_at_half_life_or_is_withdrawn() {
    // Answered renewal extends the mapping past the original expiry.
    {
        let mut env = TestEnv::new();
        let t0 = env.now;
        let mut mapper = PortMapper::new(config(), env.now);
        mapper.on_timer(&mut env);
        let request = env.sent[0].2.clone();
        mapper.on_datagram(&mut env, gw(), &pcp_response(&request, 0, 600, 51_000, ext()));
        assert!(mapper.mapped_external(env.now).is_some(), "grant live at once");

        env.advance(Duration::from_secs(301)); // inside (300s, 600s)
        let before = env.sent.len();
        mapper.on_timer(&mut env);
        assert_eq!(env.sent.len(), before + 1, "half-life renewal emitted");
        let renewal = env.sent.last().unwrap().2.clone();
        assert!(renewal.len() == 60 && renewal[0] == 2, "renewal is a PCP MAP");

        mapper.on_datagram(&mut env, gw(), &pcp_response(&renewal, 0, 600, 51_000, ext()));
        env.advance(Duration::from_secs(400)); // t0 + 701s: past the original 600s expiry
        assert!(env.now > t0 + Duration::from_secs(600));
        assert!(
            mapper.mapped_external(env.now).is_some(),
            "answered renewal carries the mapping past the original expiry",
        );
    }

    // An unanswered renewal lets the lease lapse and drops the candidate.
    {
        let mut env = TestEnv::new();
        let t0 = env.now;
        let mut mapper = PortMapper::new(config(), env.now);
        mapper.on_timer(&mut env);
        let request = env.sent[0].2.clone();
        mapper.on_datagram(&mut env, gw(), &pcp_response(&request, 0, 600, 51_000, ext()));

        env.advance(Duration::from_secs(301));
        mapper.on_timer(&mut env); // renewal fires, goes unanswered
        env.advance(Duration::from_secs(300)); // t0 + 601s: past the original expiry
        assert!(env.now > t0 + Duration::from_secs(600));
        mapper.on_timer(&mut env);
        assert!(
            mapper.mapped_external(env.now).is_none(),
            "an unrenewable lease expires and the candidate is withdrawn (§6.3)",
        );
    }
}

/// §6.3 short-lease refusal: a "grant" whose lifetime is below the client's
/// minimum-useful lease is churn, not a mapping — it is treated exactly like
/// a denial (no mapping, `denials` grows, the ladder advances).
#[test]
fn sub_minimum_lease_is_treated_as_a_denial() {
    let mut env = TestEnv::new();
    let mut mapper = PortMapper::new(config(), env.now);
    mapper.on_timer(&mut env);
    let request = env.sent[0].2.clone();

    // Success result, but a 5s lifetime — below the min-useful lease.
    let short = pcp_response(&request, 0, 5, 51_000, ext());
    mapper.on_datagram(&mut env, gw(), &short);
    assert!(mapper.mapped_external(env.now).is_none(), "no mapping from a sub-min lease");
    assert_eq!(mapper.denials, 1, "counted as a refusal");
    assert_eq!(&env.sent.last().unwrap().2[..2], &[0, 0], "ladder advanced to NAT-PMP");
}

/// §6.3 v6-pinhole independence: with a dual-stack config the v4 MAP and the
/// v6 pinhole ride one socket but distinct nonces. The pinhole answer sets
/// `pinhole_active` and never masquerades as the v4 mapping; the v4 answer
/// sets the mapping and never the pinhole; and a pinhole denial reschedules
/// itself without disturbing a live v4 mapping.
#[test]
fn v6_pinhole_is_independent_of_the_v4_mapping() {
    // Two requests, one socket, distinct nonces; the v6 one carries a native
    // v6 client IP.
    {
        let mut env = TestEnv::new();
        let mut mapper = PortMapper::new(config_v6(), env.now);
        mapper.on_timer(&mut env);
        assert_eq!(env.sent.len(), 2, "v4 MAP and v6 pinhole both emitted");
        let v4 = env.sent[0].2.clone();
        let v6 = env.sent[1].2.clone();
        assert!(v4.len() == 60 && v6.len() == 60);
        assert_ne!(&v4[24..36], &v6[24..36], "the two conversations use different nonces");
        assert_eq!(&v6[8..10], &[0x20, 0x01], "the pinhole carries the native v6 client IP");
        // The v4 client IP is v4-mapped into the 16-byte field at 8..24:
        // ::ffff:10.7.0.2, so the mapped marker sits at 18..20 and the v4
        // octets at 20..24.
        assert_eq!(&v4[18..24], &[0xff, 0xff, 10, 7, 0, 2], "the v4 MAP carries a v4-mapped IP");
    }

    // Answering the pinhole nonce sets the pinhole but NOT the v4 mapping.
    {
        let mut env = TestEnv::new();
        let mut mapper = PortMapper::new(config_v6(), env.now);
        mapper.on_timer(&mut env);
        let v6 = env.sent[1].2.clone();
        let grant = pcp_response(&v6, 0, 600, 51_000, "2001:db8:0:7::2".parse().unwrap());
        mapper.on_datagram(&mut env, gw(), &grant);
        assert!(mapper.pinhole_active(env.now));
        assert!(mapper.mapped_external(env.now).is_none(), "pinhole is not the v4 mapping");
    }

    // Answering the v4 nonce sets the mapping but NOT the pinhole.
    {
        let mut env = TestEnv::new();
        let mut mapper = PortMapper::new(config_v6(), env.now);
        mapper.on_timer(&mut env);
        let v4 = env.sent[0].2.clone();
        mapper.on_datagram(&mut env, gw(), &pcp_response(&v4, 0, 600, 51_000, ext()));
        assert!(mapper.mapped_external(env.now).is_some());
        assert!(!mapper.pinhole_active(env.now), "v4 grant does not open the pinhole");
    }

    // A pinhole denial reschedules without touching the live v4 mapping.
    {
        let mut env = TestEnv::new();
        let t0 = env.now;
        let mut mapper = PortMapper::new(config_v6(), env.now);
        mapper.on_timer(&mut env);
        let v4 = env.sent[0].2.clone();
        let v6 = env.sent[1].2.clone();
        mapper.on_datagram(&mut env, gw(), &pcp_response(&v4, 0, 600, 51_000, ext()));
        assert!(mapper.mapped_external(env.now).is_some());

        let denials = mapper.denials;
        let deny = pcp_response(&v6, 2, 0, 0, "2001:db8:0:7::2".parse().unwrap());
        mapper.on_datagram(&mut env, gw(), &deny);
        assert_eq!(mapper.denials, denials + 1, "pinhole refusal counted");
        assert!(!mapper.pinhole_active(env.now));
        assert!(mapper.mapped_external(env.now).is_some(), "v4 mapping undisturbed");

        let before = env.sent.len();
        advance_backoff(&mut env);
        mapper.on_timer(&mut env);
        let last = env.sent.last().unwrap().2.clone();
        assert!(env.sent.len() > before, "pinhole retried after backoff");
        assert!(last.len() == 60 && &last[8..10] == &[0x20, 0x01], "the retry is a v6 pinhole");
        assert!(env.now > t0);
        assert!(mapper.mapped_external(env.now).is_some(), "the v4 mapping stays live across it");
    }
}

/// §6.3 NAT-PMP grant path: an external-address success (opcode 128, result
/// 0, IP at 8..12) followed by a UDP map success (opcode 129, result 0,
/// mapped port at 10..12, lifetime at 12..16) yields the external endpoint
/// stamped `NatPmp`.
#[test]
fn natpmp_external_then_map_grants_the_endpoint() {
    let mut env = TestEnv::new();
    let mut mapper = PortMapper::new(config(), env.now);

    // Silence PCP to reach the NAT-PMP external-address rung.
    mapper.on_timer(&mut env); // PCP #1
    advance_step(&mut env);
    mapper.on_timer(&mut env); // PCP #2
    advance_step(&mut env);
    mapper.on_timer(&mut env); // NAT-PMP external #1
    assert_eq!(&env.sent.last().unwrap().2[..2], &[0, 0]);

    let external: Ipv4Addr = "198.51.0.8".parse().unwrap();
    mapper.on_datagram(&mut env, gw(), &natpmp_external_response(0, external));
    // The external success triggers the UDP map request.
    let map_req = env.sent.last().unwrap().2.clone();
    assert_eq!(&map_req[..2], &[0, 1], "NAT-PMP UDP map request is opcode 1");
    assert_eq!(map_req.len(), 12);

    mapper.on_datagram(&mut env, gw(), &natpmp_map_response(0, 51_000, 42_000, 600));
    assert_eq!(
        mapper.mapped_external(env.now),
        Some("198.51.0.8:42000".parse().unwrap()),
        "the mapped external endpoint is (external IP, gateway-assigned port)",
    );
    assert_eq!(mapper.mapped_protocol(env.now), Some(MapProtocol::NatPmp));
}

/// §6.3 UPnP happy path + split delivery: SSDP → device description →
/// GetExternalIPAddress → AddPortMapping, each HTTP response delivered in
/// small `Data` chunks, yields a `Upnp` mapping. Also: a response carrying no
/// Content-Length is delimited by end-of-stream — the client accepts it and
/// a trailing `Closed` is idempotent.
#[test]
fn upnp_maps_across_split_http_delivery() {
    // Content-length responses, delivered eight bytes at a time.
    {
        let mut env = TestEnv::new();
        let mut mapper = PortMapper::new(config(), env.now);
        walk_to_ssdp(&mut env, &mut mapper);
        let describe = answer_location(&mut env, &mut mapper);
        feed_http(&mut env, &mut mapper, describe, &http_ok(&device_description()), 8);

        let external = env.tcp.last().unwrap().0;
        assert_ne!(external, describe, "GetExternalIPAddress opens a fresh stream");
        feed_http(&mut env, &mut mapper, external, &http_ok(&external_ip_body("198.51.0.8")), 8);

        let map = env.tcp.last().unwrap().0;
        assert_ne!(map, external, "AddPortMapping opens a fresh stream");
        feed_http(&mut env, &mut mapper, map, &http_ok(&add_map_body()), 8);

        assert_eq!(mapper.mapped_protocol(env.now), Some(MapProtocol::Upnp));
        assert_eq!(
            mapper.mapped_external(env.now),
            Some("198.51.0.8:51000".parse().unwrap()),
        );
    }

    // A final AddPortMapping response with no Content-Length is EOF-delimited:
    // nothing may finalize before `Closed`, even when the header terminator
    // has long been buffered — finalizing early would truncate a body split
    // across chunks. Deliver it in small chunks straddling the `\r\n\r\n`
    // boundary, assert no premature grant, then let `Closed` conclude it.
    {
        let mut env = TestEnv::new();
        let mut mapper = PortMapper::new(config(), env.now);
        walk_to_ssdp(&mut env, &mut mapper);
        let describe = answer_location(&mut env, &mut mapper);
        feed_http(&mut env, &mut mapper, describe, &http_ok(&device_description()), 64);
        let external = env.tcp.last().unwrap().0;
        feed_http(&mut env, &mut mapper, external, &http_ok(&external_ip_body("198.51.0.8")), 64);
        let map = env.tcp.last().unwrap().0;

        let no_length =
            format!("HTTP/1.1 200 OK\r\nCONTENT-TYPE: text/xml\r\n\r\n{}", add_map_body())
                .into_bytes();
        for chunk in no_length.chunks(8) {
            mapper.on_tcp_event(&mut env, TcpEvent::Data(map, chunk.to_vec()));
            assert_eq!(
                mapper.mapped_protocol(env.now),
                None,
                "an EOF-delimited response must not finalize before Closed",
            );
        }
        mapper.on_tcp_event(&mut env, TcpEvent::Closed(map));
        assert_eq!(mapper.mapped_protocol(env.now), Some(MapProtocol::Upnp));
        assert_eq!(
            mapper.mapped_external(env.now),
            Some("198.51.0.8:51000".parse().unwrap()),
        );
    }
}

/// §6.9 bind-failure tolerance: a driver that cannot hand out the port-map
/// UDP socket must not take the core down. `on_timer` never panics, emits no
/// datagrams, exposes no socket, and keeps rescheduling its retry in the
/// future.
#[test]
fn bind_failure_is_tolerated_without_panicking() {
    let mut env = TestEnv::new_bind_fails();
    let mut mapper = PortMapper::new(config(), env.now);

    for _ in 0..5 {
        mapper.on_timer(&mut env);
        assert!(env.sent.is_empty(), "no datagrams without a bound socket");
        assert!(mapper.socket().is_none(), "no socket materialized");
        assert!(
            mapper.poll_timeout().unwrap() > env.now,
            "a retry stays scheduled in the future",
        );
        advance_backoff(&mut env);
    }
    assert!(mapper.mapped_external(env.now).is_none());
}

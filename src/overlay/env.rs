use std::{fmt, net::SocketAddr, time::Instant};

use rand::RngCore;

/// Identifies a UDP socket bound through [`OverlayEnv::bind`]. The primary
/// overlay socket (`overlay.bind_addr`) is always [`SocketId::PRIMARY`];
/// further ids are handed out for helper binds (nat-traversal.md §6.5.1)
/// and, when dual-stack is enabled, the secondary IPv6 socket (§6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SocketId(pub u32);

impl SocketId {
    pub const PRIMARY: Self = Self(0);
}

impl fmt::Display for SocketId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "socket#{}", self.0)
    }
}

/// Address family for [`OverlayEnv::bind`]: a §6.2.3 fresh-source probe must
/// egress a socket of the candidate's family, and the §6.3 dual-stack path
/// binds a dedicated v6 socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    pub fn of(addr: &SocketAddr) -> Self {
        if addr.is_ipv6() { Self::V6 } else { Self::V4 }
    }
}

/// Identifies a TCP byte stream opened through [`OverlayEnv::tcp_connect`]
/// (the §6.3 UPnP gateway conversation). Ids are unique for the life of the
/// environment and never recycled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TcpId(pub u64);

impl fmt::Display for TcpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tcp#{}", self.0)
    }
}

/// TCP stream lifecycle, delivered by the driver as events (never awaited
/// inside the core, §6.9). `Connected` fires once the connect completes;
/// bytes queued before it are flushed by the driver on connect.
#[allow(dead_code)] // consumed by the P4 port-map client (§6.3 UPnP)
#[derive(Clone, Debug)]
pub enum TcpEvent {
    Connected(TcpId),
    Data(TcpId, Vec<u8>),
    /// The stream closed or failed (connect refused, reset, EOF). Terminal.
    Closed(TcpId),
}

impl TcpEvent {
    #[allow(dead_code)] // consumed by the P4 port-map client (§6.3 UPnP)
    pub fn conn(&self) -> TcpId {
        match self {
            Self::Connected(conn) | Self::Data(conn, _) | Self::Closed(conn) => *conn,
        }
    }
}

/// Low seam per nat-traversal.md §6.9: everything the overlay core is allowed
/// to ask of the platform. Inbound datagrams, TCP bytes, and timer expiries
/// arrive as events (`on_datagram`/`on_tcp_event`/`on_timer` calls from a
/// driver), never as awaits inside the core; `send`/`tcp_send` queue without
/// blocking and drivers flush after the current event is handled. Production
/// wires this to glommio + the OS (`driver_glommio`), tests wire it to the
/// deterministic simulator.
pub trait OverlayEnv {
    fn now(&self) -> Instant;
    /// Seam surface for randomness the core needs (P4 PCP mapping nonces,
    /// P5 punch probing); seeded in the simulator.
    #[allow(dead_code)]
    fn rng(&mut self) -> &mut dyn RngCore;
    /// Queue `datagram` for transmission from local socket `from` to `to`.
    fn send(&mut self, from: SocketId, to: SocketAddr, datagram: &[u8]);
    /// Bind an additional UDP socket (`None` = ephemeral port) in `family`:
    /// §6.2.3 fresh-source dial-back probes and the §6.3 port-map client.
    fn bind(&mut self, port: Option<u16>, family: IpFamily) -> anyhow::Result<SocketId>;
    /// Release a helper socket bound via [`Self::bind`]. Dial-back binds are
    /// short-lived (§9); closing [`SocketId::PRIMARY`] is a no-op.
    fn close(&mut self, socket: SocketId);
    /// Open a TCP byte stream toward `to` (§6.3 UPnP: the gateway's HTTP
    /// endpoints). Non-blocking: the id is live immediately, the driver
    /// reports the outcome via [`TcpEvent`]s fed to the core.
    #[allow(dead_code)] // consumed by the P4 port-map client (§6.3 UPnP)
    fn tcp_connect(&mut self, to: SocketAddr) -> anyhow::Result<TcpId>;
    /// Queue bytes on the stream; flushed by the driver once connected.
    #[allow(dead_code)]
    fn tcp_send(&mut self, conn: TcpId, bytes: &[u8]);
    /// Close the stream. No further events are delivered for it.
    #[allow(dead_code)]
    fn tcp_close(&mut self, conn: TcpId);
}

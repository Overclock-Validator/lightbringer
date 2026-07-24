use std::{fmt, net::SocketAddr, time::Instant};

use rand::RngCore;

/// Identifies a UDP socket bound through [`OverlayEnv::bind`]. The primary
/// overlay socket (`overlay.bind_addr`) is always [`SocketId::PRIMARY`];
/// further ids are handed out for helper binds (nat-traversal.md §6.5.1).
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

/// Low seam per nat-traversal.md §6.9: everything the overlay core is allowed
/// to ask of the platform. Inbound datagrams and timer expiries arrive as
/// events (`on_datagram`/`on_timer` calls from a driver), never as awaits
/// inside the core; `send` queues without blocking and drivers flush after
/// the current event is handled. Production wires this to glommio + the OS
/// (`driver_glommio`), tests wire it to the deterministic simulator.
pub trait OverlayEnv {
    fn now(&self) -> Instant;
    fn rng(&mut self) -> &mut dyn RngCore;
    /// Queue `datagram` for transmission from local socket `from` to `to`.
    fn send(&mut self, from: SocketId, to: SocketAddr, datagram: &[u8]);
    /// Bind an additional UDP socket (`None` = ephemeral port).
    fn bind(&mut self, port: Option<u16>) -> anyhow::Result<SocketId>;
}

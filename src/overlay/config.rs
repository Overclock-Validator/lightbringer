use std::{net::SocketAddr, time::Duration};

use serde::{Deserialize, Serialize};

fn default_bind_addr() -> SocketAddr {
    "0.0.0.0:65410".parse().unwrap()
}

fn default_fanout() -> usize {
    8
}

fn default_peer_ttl_ms() -> u64 {
    30_000
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverlayMode {
    #[default]
    Sink,
    Source,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OverlayConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: OverlayMode,
    #[serde(default = "default_bind_addr")]
    pub bind_addr: SocketAddr,
    /// Secondary IPv6 overlay socket (nat-traversal.md §6.3 dual-stack).
    /// Unset disables the v6 path entirely.
    #[serde(default)]
    pub bind_addr_v6: Option<SocketAddr>,
    pub advertised_addr: Option<SocketAddr>,
    /// Operator-claimed public IPv6 address, advertised alongside v4 without
    /// dial-back confirmation (the operator vouches for it, §6.3).
    #[serde(default)]
    pub advertised_addr_v6: Option<SocketAddr>,
    /// LAN gateway for the §6.3 port-mapping ladder (PCP/NAT-PMP on :5351,
    /// UPnP SSDP/HTTP). Unset lets the driver auto-discover the default
    /// gateway; explicitly set wins.
    #[serde(default)]
    pub gateway_addr: Option<SocketAddr>,
    #[serde(default)]
    pub static_peers: Vec<SocketAddr>,
    #[serde(default = "default_fanout")]
    pub fanout: usize,
    pub repair_addr: Option<SocketAddr>,
    pub shred_version: Option<u16>,
    #[serde(default = "default_peer_ttl_ms")]
    pub peer_ttl_ms: u64,
}

impl Default for OverlayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: OverlayMode::Sink,
            bind_addr: default_bind_addr(),
            bind_addr_v6: None,
            advertised_addr: None,
            advertised_addr_v6: None,
            gateway_addr: None,
            static_peers: Vec::new(),
            fanout: default_fanout(),
            repair_addr: None,
            shred_version: None,
            peer_ttl_ms: default_peer_ttl_ms(),
        }
    }
}

impl OverlayConfig {
    pub fn peer_ttl(&self) -> Duration {
        Duration::from_millis(self.peer_ttl_ms)
    }
}

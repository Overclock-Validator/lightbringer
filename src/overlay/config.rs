use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

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

/// NAT-traversal knobs. Kept under `[overlay.nat]` so the expensive P5
/// birthday behaviour is visibly separate from normal overlay operation.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OverlayNatConfig {
    /// Enable the expensive §6.5.1 rung-3 birthday volley. Disabled by
    /// default: one attempt briefly binds 256 sockets and can consume a
    /// meaningful fraction of a CGN subscriber's port budget.
    #[serde(default)]
    pub birthday_punch: bool,
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
    /// LAN IP presented to the gateway in PCP/UPnP requests (§6.3). Falls
    /// back to `bind_addr`'s IP; the driver auto-resolves it when that is
    /// unspecified (0.0.0.0).
    #[serde(default)]
    pub portmap_local_ip: Option<IpAddr>,
    #[serde(default)]
    pub nat: OverlayNatConfig,
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
            portmap_local_ip: None,
            nat: OverlayNatConfig::default(),
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

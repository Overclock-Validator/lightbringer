//! Composable NAT boxes: the nat-traversal.md §6.2 taxonomy made executable.
//!
//! A [`NatBox`] is a datagram-rewriting state machine parameterized by mapping
//! key × allocator × filtering × idle timeout × port pool, and boxes compose
//! into chains for double-NAT/CGN. All internal maps are ordered and the only
//! randomness is the seeded RNG handed in at construction, so behavior is a
//! pure function of the run seed.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use rand::{Rng, SeedableRng, rngs::StdRng};

/// Which parts of the destination select the mapping (RFC 4787 terms plus the
/// §6.2 field-note flavor that keys on destination port only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingKey {
    /// EIM: one mapping per internal socket regardless of destination.
    EndpointIndependent,
    /// Field-note NAT: mapping varies with destination *port*, ignores the
    /// destination IP.
    DstPort,
    /// Mapping varies with destination IP, ignores the destination port.
    DstAddr,
    /// Fully symmetric: fresh mapping per destination IP+port.
    DstAddrPort,
}

/// External-port allocation discipline (§6.2 allocator calibration).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Allocator {
    /// Present the internal source port externally when free.
    Preserving,
    /// Walk the pool with a fixed stride.
    Sequential { stride: u16 },
    /// Uniform over the pool.
    Random,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Filtering {
    EndpointIndependent,
    AddressRestricted,
    PortRestricted,
}

#[derive(Clone, Debug)]
pub struct NatConfig {
    pub mapping: MappingKey,
    pub allocator: Allocator,
    pub filtering: Filtering,
    /// Mappings refresh on outbound traffic only; idle mappings expire.
    pub idle_timeout: Duration,
    pub port_range: (u16, u16),
    pub hairpin: bool,
}

impl NatConfig {
    fn base(mapping: MappingKey, allocator: Allocator, filtering: Filtering) -> Self {
        Self {
            mapping,
            allocator,
            filtering,
            idle_timeout: Duration::from_secs(30),
            port_range: (40_000, 59_999),
            hairpin: false,
        }
    }

    pub fn full_cone() -> Self {
        Self::base(
            MappingKey::EndpointIndependent,
            Allocator::Preserving,
            Filtering::EndpointIndependent,
        )
    }

    pub fn restricted_cone() -> Self {
        Self::base(
            MappingKey::EndpointIndependent,
            Allocator::Preserving,
            Filtering::AddressRestricted,
        )
    }

    pub fn port_restricted_cone() -> Self {
        Self::base(
            MappingKey::EndpointIndependent,
            Allocator::Preserving,
            Filtering::PortRestricted,
        )
    }

    /// The §6.2 field-note NAT measured on a real fiber ISP router:
    /// mapping keyed on destination port only (destination-IP-independent),
    /// so fixed-port STUN checkers classify it as EIM while punches toward
    /// peers on other ports see a different mapping.
    pub fn field_note_fiber() -> Self {
        Self::base(
            MappingKey::DstPort,
            Allocator::Sequential { stride: 1 },
            Filtering::PortRestricted,
        )
    }

    pub fn symmetric_sequential(stride: u16) -> Self {
        Self::base(
            MappingKey::DstAddrPort,
            Allocator::Sequential { stride },
            Filtering::PortRestricted,
        )
    }

    pub fn symmetric_random() -> Self {
        Self::base(
            MappingKey::DstAddrPort,
            Allocator::Random,
            Filtering::PortRestricted,
        )
    }

    /// Port-preserving symmetric NAT: behaves as EIM until a port collision.
    pub fn symmetric_preserving() -> Self {
        Self::base(
            MappingKey::DstAddrPort,
            Allocator::Preserving,
            Filtering::PortRestricted,
        )
    }

    /// CGN flavor: random symmetric with a small per-subscriber port budget.
    pub fn cgn_random(pool_size: u16) -> Self {
        let mut config = Self::symmetric_random();
        config.port_range = (40_000, 40_000 + pool_size.saturating_sub(1).max(1));
        config
    }

    pub fn idle_timeout(mut self, idle_timeout: Duration) -> Self {
        self.idle_timeout = idle_timeout;
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum MapKey {
    Any,
    Port(u16),
    Addr(IpAddr),
    AddrPort(IpAddr, u16),
}

fn map_key(mapping: MappingKey, dst: SocketAddr) -> MapKey {
    match mapping {
        MappingKey::EndpointIndependent => MapKey::Any,
        MappingKey::DstPort => MapKey::Port(dst.port()),
        MappingKey::DstAddr => MapKey::Addr(dst.ip()),
        MappingKey::DstAddrPort => MapKey::AddrPort(dst.ip(), dst.port()),
    }
}

#[derive(Clone, Debug)]
struct Mapping {
    internal: SocketAddr,
    external_port: u16,
    last_refresh: u64,
    /// Remote endpoints this mapping has emitted a packet toward; the
    /// filtering policy checks inbound sources against it.
    allowed: BTreeSet<(IpAddr, u16)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatDropReason {
    NoMapping,
    MappingExpired,
    Filtered,
    PortPoolExhausted,
}

impl NatDropReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoMapping => "no-mapping",
            Self::MappingExpired => "mapping-expired",
            Self::Filtered => "filtered",
            Self::PortPoolExhausted => "port-pool-exhausted",
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NatStats {
    pub mappings_created: u64,
    pub expired_drops: u64,
    pub filtered_drops: u64,
    pub no_mapping_drops: u64,
    pub pool_exhausted_drops: u64,
}

pub struct OutboundPass {
    pub external: SocketAddr,
    /// A fresh mapping was allocated for this datagram.
    pub created: bool,
}

pub struct NatBox {
    pub config: NatConfig,
    pub external_ip: IpAddr,
    mappings: BTreeMap<(SocketAddr, MapKey), Mapping>,
    /// One external port can carry several mappings of the *same* internal
    /// socket (port-preserving symmetric NATs reuse the port per
    /// destination; inbound disambiguates by remote endpoint).
    by_port: BTreeMap<u16, Vec<(SocketAddr, MapKey)>>,
    next_port: u16,
    rng: StdRng,
    pub stats: NatStats,
}

impl NatBox {
    pub fn new(config: NatConfig, external_ip: IpAddr, rng_seed: u64) -> Self {
        let next_port = config.port_range.0;
        Self {
            config,
            external_ip,
            mappings: BTreeMap::new(),
            by_port: BTreeMap::new(),
            next_port,
            rng: StdRng::seed_from_u64(rng_seed),
            stats: NatStats::default(),
        }
    }

    fn expired(&self, mapping: &Mapping, now: u64) -> bool {
        now.saturating_sub(mapping.last_refresh) > self.config.idle_timeout.as_nanos() as u64
    }

    fn evict(&mut self, slot: (SocketAddr, MapKey)) {
        if let Some(mapping) = self.mappings.remove(&slot) {
            if let Some(slots) = self.by_port.get_mut(&mapping.external_port) {
                slots.retain(|occupant| *occupant != slot);
                if slots.is_empty() {
                    self.by_port.remove(&mapping.external_port);
                }
            }
        }
    }

    /// Process a LAN→WAN datagram: allocate/refresh the mapping for
    /// `(src, dst-derived key)` and rewrite the source address.
    pub fn outbound(
        &mut self,
        now: u64,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Result<OutboundPass, NatDropReason> {
        let key = map_key(self.config.mapping, dst);
        let slot = (src, key);
        if let Some(mapping) = self.mappings.get(&slot)
            && self.expired(mapping, now)
        {
            self.evict(slot);
        }

        if let Some(mapping) = self.mappings.get_mut(&slot) {
            mapping.last_refresh = now;
            mapping.allowed.insert((dst.ip(), dst.port()));
            return Ok(OutboundPass {
                external: SocketAddr::new(self.external_ip, mapping.external_port),
                created: false,
            });
        }

        let external_port = self
            .allocate_port(now, src)
            .ok_or(NatDropReason::PortPoolExhausted)
            .inspect_err(|_| self.stats.pool_exhausted_drops += 1)?;
        let mut allowed = BTreeSet::new();
        allowed.insert((dst.ip(), dst.port()));
        self.mappings.insert(
            slot,
            Mapping {
                internal: src,
                external_port,
                last_refresh: now,
                allowed,
            },
        );
        self.by_port.entry(external_port).or_default().push(slot);
        self.stats.mappings_created += 1;
        Ok(OutboundPass {
            external: SocketAddr::new(self.external_ip, external_port),
            created: true,
        })
    }

    /// Process a WAN→LAN datagram addressed to `dst` (on our external IP):
    /// find the live mapping for `dst.port`, apply the filtering policy to
    /// `src`, and rewrite the destination to the internal socket. Inbound
    /// traffic does not refresh mappings, so only outbound keepalives hold
    /// them open (nat-traversal.md §4).
    pub fn inbound(
        &mut self,
        now: u64,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Result<SocketAddr, NatDropReason> {
        let Some(slots) = self.by_port.get(&dst.port()) else {
            self.stats.no_mapping_drops += 1;
            return Err(NatDropReason::NoMapping);
        };
        let slots = slots.clone();

        let mut expired = Vec::new();
        let mut saw_live = false;
        let mut admitted = None;
        for slot in slots {
            let mapping = self
                .mappings
                .get(&slot)
                .expect("by_port and mappings are kept in sync");
            if self.expired(mapping, now) {
                expired.push(slot);
                continue;
            }
            saw_live = true;
            let passes = match self.config.filtering {
                Filtering::EndpointIndependent => true,
                Filtering::AddressRestricted => mapping
                    .allowed
                    .iter()
                    .any(|(allowed_ip, _)| *allowed_ip == src.ip()),
                Filtering::PortRestricted => mapping.allowed.contains(&(src.ip(), src.port())),
            };
            if passes && admitted.is_none() {
                admitted = Some(mapping.internal);
            }
        }
        for slot in expired {
            self.evict(slot);
        }

        match admitted {
            Some(internal) => Ok(internal),
            None if saw_live => {
                self.stats.filtered_drops += 1;
                Err(NatDropReason::Filtered)
            }
            None => {
                self.stats.expired_drops += 1;
                Err(NatDropReason::MappingExpired)
            }
        }
    }

    fn allocate_port(&mut self, now: u64, internal: SocketAddr) -> Option<u16> {
        let (lo, hi) = self.config.port_range;
        let pool_size = usize::from(hi - lo) + 1;

        if matches!(self.config.allocator, Allocator::Preserving)
            && (lo..=hi).contains(&internal.port())
            && self.port_available(now, internal.port(), Some(internal))
        {
            return Some(internal.port());
        }

        match self.config.allocator {
            Allocator::Preserving | Allocator::Sequential { .. } => {
                let stride = match self.config.allocator {
                    Allocator::Sequential { stride } => stride.max(1),
                    _ => 1,
                };
                for _ in 0..pool_size {
                    let candidate = self.next_port;
                    let span = u32::from(hi - lo) + 1;
                    let offset = (u32::from(candidate - lo) + u32::from(stride)) % span;
                    self.next_port = lo + offset as u16;
                    if self.port_available(now, candidate, None) {
                        return Some(candidate);
                    }
                }
                None
            }
            Allocator::Random => {
                for _ in 0..(pool_size * 2).max(64) {
                    let candidate = self.rng.random_range(lo..=hi);
                    if self.port_available(now, candidate, None) {
                        return Some(candidate);
                    }
                }
                None
            }
        }
    }

    /// Whether `port` can take a new mapping. With `share_with` set (the
    /// port-preserving path), the port may already carry live mappings of
    /// that same internal socket — inbound resolves by remote endpoint.
    fn port_available(&mut self, now: u64, port: u16, share_with: Option<SocketAddr>) -> bool {
        let Some(slots) = self.by_port.get(&port) else {
            return true;
        };
        let slots = slots.clone();
        let mut expired = Vec::new();
        let mut blocked = false;
        for slot in slots {
            let live = self
                .mappings
                .get(&slot)
                .is_some_and(|mapping| !self.expired(mapping, now));
            if !live {
                expired.push(slot);
            } else if share_with != Some(slot.0) {
                blocked = true;
            }
        }
        for slot in expired {
            self.evict(slot);
        }
        !blocked
    }
}

impl std::fmt::Debug for NatBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NatBox")
            .field("external_ip", &self.external_ip)
            .field("mappings", &self.mappings.len())
            .field("stats", &self.stats)
            .finish()
    }
}

/// RFC 6092 residential IPv6 firewall (nat-traversal.md §4): no address
/// rewriting, but unsolicited inbound is dropped by default. Outbound
/// traffic opens a flow (matched on the exact remote endpoint, refreshed by
/// outbound only, expiring idle — the same discipline as NAT filtering);
/// a PCP pinhole (§6.3) opens a local port to any remote for a lease.
#[derive(Clone, Debug)]
pub struct FirewallConfig {
    pub idle_timeout: Duration,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FirewallStats {
    pub filtered_drops: u64,
    pub pinholes_installed: u64,
}

pub struct FirewallBox {
    pub config: FirewallConfig,
    /// (local socket, remote endpoint) → last outbound refresh (nanos).
    flows: BTreeMap<(SocketAddr, (IpAddr, u16)), u64>,
    /// Local port → pinhole lease expiry (nanos). Lease-based, not
    /// idle-refreshed: renewal is the client's job (§6.3 half-life).
    pinholes: BTreeMap<u16, u64>,
    pub stats: FirewallStats,
}

impl FirewallBox {
    pub fn new(config: FirewallConfig) -> Self {
        Self {
            config,
            flows: BTreeMap::new(),
            pinholes: BTreeMap::new(),
            stats: FirewallStats::default(),
        }
    }

    /// Record an outbound datagram: opens/refreshes the flow toward `dst`.
    pub fn outbound(&mut self, now: u64, src: SocketAddr, dst: SocketAddr) {
        self.flows.insert((src, (dst.ip(), dst.port())), now);
    }

    /// Admit or drop an inbound datagram from `src` addressed to local
    /// socket `dst`. Inbound never refreshes flows (§4: only outbound
    /// keepalives hold state open).
    pub fn inbound(&mut self, now: u64, src: SocketAddr, dst: SocketAddr) -> Result<(), NatDropReason> {
        if let Some(&expires) = self.pinholes.get(&dst.port()) {
            if now <= expires {
                return Ok(());
            }
            self.pinholes.remove(&dst.port());
        }
        let idle = self.config.idle_timeout.as_nanos() as u64;
        let key = (dst, (src.ip(), src.port()));
        match self.flows.get(&key) {
            Some(&refreshed) if now.saturating_sub(refreshed) <= idle => Ok(()),
            _ => {
                self.flows.remove(&key);
                self.stats.filtered_drops += 1;
                Err(NatDropReason::Filtered)
            }
        }
    }

    /// Install (or renew) a PCP pinhole for `port` (§6.3): any remote may
    /// reach the local socket at `port` until the lease expires.
    pub fn install_pinhole(&mut self, now: u64, port: u16, lifetime: Duration) {
        self.stats.pinholes_installed += 1;
        self.pinholes.insert(port, now + lifetime.as_nanos() as u64);
    }

    /// A pinhole for `port` is currently live.
    pub fn pinhole_live(&self, now: u64, port: u16) -> bool {
        self.pinholes.get(&port).is_some_and(|&expires| now <= expires)
    }
}

/// The §6.2 classifier and its observation/class types live in shared
/// `overlay::nat` so the core and the simulator use one implementation
/// (nat-traversal.md §6.2/§10 P3). Re-exported here for the sim call sites
/// that predate the move.
pub use crate::overlay::nat::{
    AllocatorProfile, NatClass, TaggedObservation, classify_observations,
};

//! Rolling event-trace hash: a failure is a `(seed, config)` pair and the
//! hash is the equality witness — same seed twice must produce the same
//! hash (nat-traversal.md §6.9).
//!
//! The hash covers virtual time, endpoints, event kinds, datagram lengths,
//! and application-level payload digests — everything protocol behavior
//! determines. Raw ciphertext bytes are deliberately excluded: rustls's
//! `SecureRandom` seam covers TLS randoms/session ids but ring generates
//! ECDHE ephemeral keys from its own entropy (documented at
//! `rustls::crypto::SecureRandom`), so encrypted bytes differ per run while
//! packet counts, sizes, and timing do not.

use std::net::SocketAddr;

use solana_sdk::pubkey::Pubkey;

#[derive(Clone, Debug)]
pub enum TraceEvent {
    HostSend {
        host: u32,
        from: SocketAddr,
        to: SocketAddr,
        len: usize,
    },
    Delivered {
        host: u32,
        src: SocketAddr,
        dst: SocketAddr,
        len: usize,
    },
    LinkDropped {
        from: u32,
        to: u32,
        len: usize,
    },
    LinkDuplicated {
        from: u32,
        to: u32,
    },
    LinkDown {
        from: u32,
        to: u32,
    },
    MtuDropped {
        from: u32,
        to: u32,
        len: usize,
        mtu: usize,
    },
    NoRoute {
        from: u32,
        to: SocketAddr,
    },
    NatMapped {
        host: u32,
        level: u8,
        internal: SocketAddr,
        external: SocketAddr,
    },
    NatDropped {
        host: u32,
        level: u8,
        reason: &'static str,
    },
    NoSocket {
        host: u32,
        dst: SocketAddr,
    },
    PeerConnected {
        host: u32,
        peer: SocketAddr,
        pubkey: Option<Pubkey>,
    },
    PeerDisconnected {
        host: u32,
        peer: SocketAddr,
    },
    ShredDelivered {
        host: u32,
        payload_hash: u64,
    },
    /// Application datagram surfaced by a bare-transport host.
    AppDatagram {
        host: u32,
        from: SocketAddr,
        payload_hash: u64,
    },
    HostDown {
        host: u32,
    },
    HostUp {
        host: u32,
    },
    /// Server side: a §6.4 repair request was admitted and answered from
    /// the host's store (`found` = a shred went back).
    RepairServed {
        host: u32,
        slot: u64,
        index: u32,
        highest: bool,
        found: bool,
    },
    /// Client side: a repair stream concluded with the peer's answer.
    RepairConcluded {
        host: u32,
        found: bool,
    },
    /// Client side: a repair stream died without an answer.
    RepairFailed {
        host: u32,
    },
}

pub struct Trace {
    state: [u8; 32],
    events: u64,
    buf: Vec<u8>,
    pub verbose: bool,
}

impl Trace {
    pub fn new(verbose: bool) -> Self {
        Self {
            state: [0u8; 32],
            events: 0,
            buf: Vec::with_capacity(128),
            verbose,
        }
    }

    pub fn record(&mut self, nanos: u64, event: &TraceEvent) {
        self.buf.clear();
        self.buf.extend_from_slice(&nanos.to_le_bytes());
        encode_event(&mut self.buf, event);
        self.state = solana_sha256_hasher::hashv(&[&self.state, &self.buf]).to_bytes();
        self.events += 1;
        if self.verbose {
            eprintln!("[{:>12}ns] {event:?}", nanos);
        }
    }

    pub fn events(&self) -> u64 {
        self.events
    }

    pub fn hash_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.state {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

fn encode_addr(buf: &mut Vec<u8>, addr: &SocketAddr) {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            buf.push(4);
            buf.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            buf.push(6);
            buf.extend_from_slice(&ip.octets());
        }
    }
    buf.extend_from_slice(&addr.port().to_le_bytes());
}

fn encode_event(buf: &mut Vec<u8>, event: &TraceEvent) {
    match event {
        TraceEvent::HostSend { host, from, to, len } => {
            buf.push(1);
            buf.extend_from_slice(&host.to_le_bytes());
            encode_addr(buf, from);
            encode_addr(buf, to);
            buf.extend_from_slice(&(*len as u64).to_le_bytes());
        }
        TraceEvent::Delivered { host, src, dst, len } => {
            buf.push(2);
            buf.extend_from_slice(&host.to_le_bytes());
            encode_addr(buf, src);
            encode_addr(buf, dst);
            buf.extend_from_slice(&(*len as u64).to_le_bytes());
        }
        TraceEvent::LinkDropped { from, to, len } => {
            buf.push(3);
            buf.extend_from_slice(&from.to_le_bytes());
            buf.extend_from_slice(&to.to_le_bytes());
            buf.extend_from_slice(&(*len as u64).to_le_bytes());
        }
        TraceEvent::LinkDuplicated { from, to } => {
            buf.push(4);
            buf.extend_from_slice(&from.to_le_bytes());
            buf.extend_from_slice(&to.to_le_bytes());
        }
        TraceEvent::LinkDown { from, to } => {
            buf.push(5);
            buf.extend_from_slice(&from.to_le_bytes());
            buf.extend_from_slice(&to.to_le_bytes());
        }
        TraceEvent::MtuDropped { from, to, len, mtu } => {
            buf.push(6);
            buf.extend_from_slice(&from.to_le_bytes());
            buf.extend_from_slice(&to.to_le_bytes());
            buf.extend_from_slice(&(*len as u64).to_le_bytes());
            buf.extend_from_slice(&(*mtu as u64).to_le_bytes());
        }
        TraceEvent::NoRoute { from, to } => {
            buf.push(7);
            buf.extend_from_slice(&from.to_le_bytes());
            encode_addr(buf, to);
        }
        TraceEvent::NatMapped {
            host,
            level,
            internal,
            external,
        } => {
            buf.push(8);
            buf.extend_from_slice(&host.to_le_bytes());
            buf.push(*level);
            encode_addr(buf, internal);
            encode_addr(buf, external);
        }
        TraceEvent::NatDropped { host, level, reason } => {
            buf.push(9);
            buf.extend_from_slice(&host.to_le_bytes());
            buf.push(*level);
            buf.extend_from_slice(reason.as_bytes());
        }
        TraceEvent::NoSocket { host, dst } => {
            buf.push(10);
            buf.extend_from_slice(&host.to_le_bytes());
            encode_addr(buf, dst);
        }
        TraceEvent::PeerConnected { host, peer, pubkey } => {
            buf.push(11);
            buf.extend_from_slice(&host.to_le_bytes());
            encode_addr(buf, peer);
            match pubkey {
                Some(pubkey) => {
                    buf.push(1);
                    buf.extend_from_slice(pubkey.as_ref());
                }
                None => buf.push(0),
            }
        }
        TraceEvent::PeerDisconnected { host, peer } => {
            buf.push(12);
            buf.extend_from_slice(&host.to_le_bytes());
            encode_addr(buf, peer);
        }
        TraceEvent::ShredDelivered { host, payload_hash } => {
            buf.push(13);
            buf.extend_from_slice(&host.to_le_bytes());
            buf.extend_from_slice(&payload_hash.to_le_bytes());
        }
        TraceEvent::HostDown { host } => {
            buf.push(14);
            buf.extend_from_slice(&host.to_le_bytes());
        }
        TraceEvent::HostUp { host } => {
            buf.push(15);
            buf.extend_from_slice(&host.to_le_bytes());
        }
        TraceEvent::AppDatagram {
            host,
            from,
            payload_hash,
        } => {
            buf.push(16);
            buf.extend_from_slice(&host.to_le_bytes());
            encode_addr(buf, from);
            buf.extend_from_slice(&payload_hash.to_le_bytes());
        }
        TraceEvent::RepairServed {
            host,
            slot,
            index,
            highest,
            found,
        } => {
            buf.push(17);
            buf.extend_from_slice(&host.to_le_bytes());
            buf.extend_from_slice(&slot.to_le_bytes());
            buf.extend_from_slice(&index.to_le_bytes());
            buf.push(u8::from(*highest));
            buf.push(u8::from(*found));
        }
        TraceEvent::RepairConcluded { host, found } => {
            buf.push(18);
            buf.extend_from_slice(&host.to_le_bytes());
            buf.push(u8::from(*found));
        }
        TraceEvent::RepairFailed { host } => {
            buf.push(19);
            buf.extend_from_slice(&host.to_le_bytes());
        }
    }
}

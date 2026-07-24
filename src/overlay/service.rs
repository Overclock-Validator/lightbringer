use std::{
    collections::VecDeque,
    net::SocketAddr,
    time::{Duration, Instant},
};

use arrayvec::ArrayVec;
use solana_sdk::pubkey::Pubkey;

use crate::types::{PacketInfo, PacketView};

use super::{
    OverlayConfig, OverlayMode, OverlayPeer, TurbineTree,
    env::{OverlayEnv, SocketId},
    gossip::LightbringerGossip,
    packet::OverlayFrame,
    transport::{OverlayTransport, TransportEvent},
};

const ADVERT_INTERVAL: Duration = Duration::from_secs(10);
const MAX_CORE_EVENTS: usize = 8192;

fn packet_view(payload: Vec<u8>) -> Option<PacketView> {
    if payload.len() > solana_packet::PACKET_DATA_SIZE {
        return None;
    }
    ArrayVec::try_from(payload.as_slice()).ok()
}

/// Application-level outputs of the core, drained by the driver after every
/// event (the glommio driver forwards shreds into the packet filter channel;
/// the simulator records them).
#[derive(Clone, Debug)]
pub enum CoreEvent {
    ShredForFilter(PacketInfo),
    PeerConnected {
        peer: SocketAddr,
        pubkey: Option<Pubkey>,
    },
    PeerDisconnected {
        peer: SocketAddr,
        reason: String,
    },
}

/// Sans-IO overlay state machine (nat-traversal.md §6.9): inbound datagrams
/// and timer expiries arrive as `on_*` events from a driver, outbound
/// datagrams leave through `OverlayEnv::send`, and everything else is polled.
/// No socket, clock, or RNG access happens outside the seams.
pub struct OverlayCore<T> {
    mode: OverlayMode,
    advertised_addr: SocketAddr,
    transport: T,
    gossip: LightbringerGossip,
    tree: TurbineTree,
    local_peer: OverlayPeer,
    next_advert: Instant,
    events: VecDeque<CoreEvent>,
}

impl<T: OverlayTransport> OverlayCore<T> {
    pub fn new(transport: T, config: &OverlayConfig, now: Instant) -> Self {
        let advertised_addr = config.advertised_addr.unwrap_or(config.bind_addr);
        let mut gossip = LightbringerGossip::new(config.peer_ttl());
        for peer in config.static_peers.iter().copied() {
            gossip.observe(
                OverlayPeer {
                    overlay_addr: peer,
                    repair_addr: None,
                },
                now,
            );
        }
        if let Some(repair_addr) = config.repair_addr {
            gossip.observe_repair(advertised_addr, repair_addr, now);
        }

        Self {
            mode: config.mode,
            advertised_addr,
            transport,
            gossip,
            tree: TurbineTree::new(advertised_addr, config.fanout),
            local_peer: OverlayPeer {
                overlay_addr: advertised_addr,
                repair_addr: config.repair_addr,
            },
            next_advert: now + ADVERT_INTERVAL,
            events: VecDeque::new(),
        }
    }

    pub fn on_datagram(
        &mut self,
        env: &mut dyn OverlayEnv,
        socket: SocketId,
        from: SocketAddr,
        datagram: &[u8],
    ) {
        self.transport.on_datagram(env, socket, from, datagram);
        self.pump(env);
    }

    /// Fire due deadlines. Safe to call early; deadlines are re-checked.
    pub fn on_timer(&mut self, env: &mut dyn OverlayEnv) {
        self.transport.on_timer(env);
        let now = env.now();
        if now >= self.next_advert {
            self.next_advert = now + ADVERT_INTERVAL;
            self.gossip.prune_expired(now);
            self.advertise_except(env, None);
        }
        self.pump(env);
    }

    pub fn on_source_packet(&mut self, env: &mut dyn OverlayEnv, packet: PacketInfo) {
        if self.mode != OverlayMode::Source {
            return;
        }
        let now = env.now();
        let peers = self.gossip.peers(now);
        let peer_addrs = peers
            .iter()
            .map(|peer| peer.overlay_addr)
            .collect::<Vec<_>>();
        let frame = OverlayFrame::shred(self.advertised_addr, packet.to_vec());
        for peer in self.tree.origin_peers(packet.as_slice(), &peer_addrs) {
            self.send_frame(env, peer, &frame);
        }
        self.pump(env);
    }

    pub fn poll_timeout(&mut self) -> Option<Instant> {
        let deadline = match self.transport.poll_timeout() {
            Some(transport_deadline) => transport_deadline.min(self.next_advert),
            None => self.next_advert,
        };
        Some(deadline)
    }

    pub fn poll_event(&mut self) -> Option<CoreEvent> {
        self.events.pop_front()
    }

    #[allow(dead_code)]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    fn pump(&mut self, env: &mut dyn OverlayEnv) {
        while let Some(event) = self.transport.poll_event() {
            let event = match event {
                TransportEvent::Connected { peer, pubkey } => {
                    CoreEvent::PeerConnected { peer, pubkey }
                }
                TransportEvent::Disconnected { peer, reason } => {
                    CoreEvent::PeerDisconnected { peer, reason }
                }
            };
            self.push_event(event);
        }
        while let Some((from, raw)) = self.transport.poll_inbound() {
            self.handle_frame(env, from, raw);
        }
    }

    fn handle_frame(&mut self, env: &mut dyn OverlayEnv, from: SocketAddr, raw: Vec<u8>) {
        let frame = match OverlayFrame::decode(&raw) {
            Ok(frame) => frame,
            Err(e) => {
                log::warn!("overlay: dropped invalid frame from {from}: {e}");
                return;
            }
        };

        let now = env.now();
        self.gossip.observe(
            OverlayPeer {
                overlay_addr: from,
                repair_addr: None,
            },
            now,
        );

        match frame {
            OverlayFrame::Shred {
                origin, payload, ..
            } => {
                if let Some(packet) = packet_view(payload.clone()) {
                    self.push_event(CoreEvent::ShredForFilter(PacketInfo::new(packet)));
                }

                let peers = self.gossip.peers(now);
                let peer_addrs = peers
                    .iter()
                    .map(|peer| peer.overlay_addr)
                    .filter(|peer| *peer != from && *peer != origin)
                    .collect::<Vec<_>>();
                let frame = OverlayFrame::shred(origin, payload);
                let payload = match &frame {
                    OverlayFrame::Shred { payload, .. } => payload.as_slice(),
                    _ => unreachable!(),
                };
                for peer in self.tree.retransmit_peers(payload, &peer_addrs) {
                    self.send_frame(env, peer, &frame);
                }
            }
            OverlayFrame::PeerAdvertisement { peer, .. } => {
                self.gossip.observe(peer, now);
                self.advertise_except(env, Some(from));
            }
        }
    }

    fn advertise_except(&mut self, env: &mut dyn OverlayEnv, excluded_peer: Option<SocketAddr>) {
        let peers = self.gossip.peers(env.now());
        let advert = OverlayFrame::peer_advertisement(self.local_peer.clone());
        for peer in peers.into_iter().map(|peer| peer.overlay_addr) {
            if Some(peer) != excluded_peer {
                self.send_frame(env, peer, &advert);
            }
        }
    }

    fn send_frame(&mut self, env: &mut dyn OverlayEnv, peer: SocketAddr, frame: &OverlayFrame) {
        let raw = match frame.encode() {
            Ok(raw) => raw,
            Err(e) => {
                log::warn!("overlay: failed to encode frame for {peer}: {e}");
                return;
            }
        };
        if let Err(e) = self.transport.queue_datagram(env, peer, raw) {
            log::warn!("overlay: failed to send frame to {peer}: {e}");
        }
    }

    fn push_event(&mut self, event: CoreEvent) {
        if self.events.len() >= MAX_CORE_EVENTS {
            self.events.pop_front();
            log::debug!("overlay: core event queue full ({MAX_CORE_EVENTS}); dropping oldest");
        }
        self.events.push_back(event);
    }
}

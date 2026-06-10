use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use arrayvec::ArrayVec;
use glommio::spawn_local;

use crate::{
    thread_manager::CancelRx,
    types::{PacketInfo, PacketView},
};
use solana_sdk::signature::Keypair;

use super::{
    OverlayConfig, OverlayIdentity, OverlayMode, OverlayPeer, TurbineTree,
    gossip::LightbringerGossip, packet::OverlayFrame, transport::OverlayQuicTransport,
};

const SOURCE_POLL_INTERVAL: Duration = Duration::from_millis(1);
const RECEIVE_POLL_INTERVAL: Duration = Duration::from_millis(10);
const ADVERT_INTERVAL: Duration = Duration::from_secs(10);

fn packet_view(payload: Vec<u8>) -> Option<PacketView> {
    if payload.len() > solana_packet::PACKET_DATA_SIZE {
        return None;
    }
    ArrayVec::try_from(payload.as_slice()).ok()
}

async fn send_frame(transport: &mut OverlayQuicTransport, peer: SocketAddr, frame: &OverlayFrame) {
    let raw = match frame.encode() {
        Ok(raw) => raw,
        Err(e) => {
            log::warn!("overlay: failed to encode frame for {peer}: {e}");
            return;
        }
    };
    if let Err(e) = transport.send_to(raw, peer).await {
        log::warn!("overlay: failed to send frame to {peer}: {e}");
    }
}

struct OverlayRunner {
    mode: OverlayMode,
    advertised_addr: SocketAddr,
    source_rx: Option<kanal::AsyncReceiver<PacketInfo>>,
    filter_tx: kanal::AsyncSender<PacketInfo>,
    transport: OverlayQuicTransport,
    gossip: LightbringerGossip,
    tree: TurbineTree,
    local_peer: OverlayPeer,
    next_advert: Instant,
}

impl OverlayRunner {
    fn new(
        identity: &OverlayIdentity,
        config: OverlayConfig,
        source_rx: Option<kanal::AsyncReceiver<PacketInfo>>,
        filter_tx: kanal::AsyncSender<PacketInfo>,
    ) -> Result<Self> {
        let advertised_addr = config.advertised_addr.unwrap_or(config.bind_addr);
        let mut gossip = LightbringerGossip::new(config.peer_ttl());
        for peer in config.static_peers.iter().copied() {
            gossip.observe(OverlayPeer {
                overlay_addr: peer,
                repair_addr: None,
            });
        }
        if let Some(repair_addr) = config.repair_addr {
            gossip.observe_repair(advertised_addr, repair_addr);
        }

        Ok(Self {
            mode: config.mode,
            advertised_addr,
            source_rx,
            filter_tx,
            transport: OverlayQuicTransport::bind(config.bind_addr, identity)?,
            gossip,
            tree: TurbineTree::new(advertised_addr, config.fanout),
            local_peer: OverlayPeer {
                overlay_addr: advertised_addr,
                repair_addr: config.repair_addr,
            },
            next_advert: Instant::now() + ADVERT_INTERVAL,
        })
    }

    async fn run(&mut self) {
        loop {
            self.poll_source().await;
            self.poll_inbound().await;
            self.poll_advert().await;
            if let Err(e) = self.transport.poll().await {
                log::warn!("overlay: transport poll failed: {e}");
            }
        }
    }

    async fn poll_source(&mut self) {
        let Some(source_rx) = &self.source_rx else {
            return;
        };
        if self.mode != OverlayMode::Source {
            return;
        }

        match source_rx.try_recv() {
            Ok(Some(packet)) => self.handle_source_packet(packet).await,
            Ok(None) => glommio::timer::sleep(SOURCE_POLL_INTERVAL).await,
            Err(e) => log::warn!("overlay: source shred channel closed: {e}"),
        }
    }

    async fn handle_source_packet(&mut self, packet: PacketInfo) {
        let peers = self.gossip.peers();
        let peer_addrs = peers
            .iter()
            .map(|peer| peer.overlay_addr)
            .collect::<Vec<_>>();
        let frame = OverlayFrame::shred(self.advertised_addr, packet.to_vec());
        for peer in self.tree.retransmit_peers(packet.as_slice(), &peer_addrs) {
            send_frame(&mut self.transport, peer, &frame).await;
        }
    }

    async fn poll_inbound(&mut self) {
        match self.transport.recv_for(RECEIVE_POLL_INTERVAL).await {
            Ok(Some((from, raw))) => self.handle_frame(from, raw).await,
            Ok(None) => {}
            Err(e) => log::warn!("overlay: receive failed: {e}"),
        }
    }

    async fn handle_frame(&mut self, from: SocketAddr, raw: Vec<u8>) {
        let frame = match OverlayFrame::decode(&raw) {
            Ok(frame) => frame,
            Err(e) => {
                log::warn!("overlay: dropped invalid frame from {from}: {e}");
                return;
            }
        };

        self.gossip.observe(OverlayPeer {
            overlay_addr: from,
            repair_addr: None,
        });

        match frame {
            OverlayFrame::Shred {
                origin, payload, ..
            } => {
                if let Some(packet) = packet_view(payload.clone())
                    && let Err(e) = self.filter_tx.send(PacketInfo::new(packet)).await
                {
                    log::warn!("overlay: failed to forward shred to filter: {e}");
                }

                let peers = self.gossip.peers();
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
                    send_frame(&mut self.transport, peer, &frame).await;
                }
            }
            OverlayFrame::PeerAdvertisement { peer, .. } => {
                self.gossip.observe(peer);
                self.advertise_except(Some(from)).await;
            }
        }
    }

    async fn poll_advert(&mut self) {
        if Instant::now() < self.next_advert {
            return;
        }
        self.next_advert = Instant::now() + ADVERT_INTERVAL;
        self.advertise_except(None).await;
    }

    async fn advertise_except(&mut self, excluded_peer: Option<SocketAddr>) {
        let peers = self.gossip.peers();
        let advert = OverlayFrame::peer_advertisement(self.local_peer.clone());
        for peer in peers.into_iter().map(|peer| peer.overlay_addr) {
            if Some(peer) != excluded_peer {
                send_frame(&mut self.transport, peer, &advert).await;
            }
        }
    }
}

pub async fn start_overlay_runner(
    exit: CancelRx,
    keypair: Arc<Keypair>,
    config: OverlayConfig,
    source_rx: Option<kanal::AsyncReceiver<PacketInfo>>,
    filter_tx: kanal::AsyncSender<PacketInfo>,
) -> anyhow::Result<()> {
    let identity = OverlayIdentity::from_keypair(&keypair)?;
    log::info!("overlay identity: {}", identity.pubkey);

    let runner_task = spawn_local(async move {
        let mut runner = match OverlayRunner::new(&identity, config, source_rx, filter_tx) {
            Ok(runner) => runner,
            Err(e) => {
                log::error!("overlay: failed to start runner: {e}");
                return;
            }
        };
        runner.run().await;
    });

    exit.await;
    runner_task.cancel().await;
    Ok(())
}

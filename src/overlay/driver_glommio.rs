use std::{
    collections::VecDeque,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};
use glommio::{net::UdpSocket, spawn_local, timer::timeout};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use solana_sdk::signature::Keypair;

use crate::{thread_manager::CancelRx, types::PacketInfo};

use super::{
    OverlayConfig, OverlayIdentity, OverlayMode,
    env::{OverlayEnv, SocketId},
    service::{CoreEvent, OverlayCore},
    transport::{OverlayQuicTransport, TransportOptions},
};

const RECEIVE_POLL_INTERVAL: Duration = Duration::from_millis(10);
const SOURCE_POLL_INTERVAL: Duration = Duration::from_millis(1);
const MIN_RECEIVE_WAIT: Duration = Duration::from_micros(100);
const UDP_BUFFER_SIZE: usize = 65_535;

/// Production side of the `OverlayEnv` seam: real sockets, the OS clock, and
/// OS-seeded randomness. `send` only queues; the driver loop flushes between
/// core events so the core itself never blocks.
struct GlommioEnv {
    sockets: Vec<UdpSocket>,
    out: VecDeque<(SocketId, SocketAddr, Vec<u8>)>,
    rng: StdRng,
}

impl GlommioEnv {
    fn bind_primary(addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(addr)
            .map_err(|e| anyhow!("failed to bind overlay QUIC socket {addr}: {e}"))?;
        Ok(Self {
            sockets: vec![socket],
            out: VecDeque::new(),
            rng: StdRng::from_os_rng(),
        })
    }

    async fn flush(&mut self) {
        while let Some((from, to, bytes)) = self.out.pop_front() {
            let Some(socket) = self.sockets.get(from.0 as usize) else {
                log::warn!("overlay: dropping datagram to {to} from unknown {from}");
                continue;
            };
            if let Err(e) = socket.send_to(&bytes, to).await {
                log::warn!("overlay: failed to send datagram to {to}: {e}");
            }
        }
    }
}

impl OverlayEnv for GlommioEnv {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn rng(&mut self) -> &mut dyn RngCore {
        &mut self.rng
    }

    fn send(&mut self, from: SocketId, to: SocketAddr, datagram: &[u8]) {
        self.out.push_back((from, to, datagram.to_vec()));
    }

    fn bind(&mut self, port: Option<u16>) -> Result<SocketId> {
        let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port.unwrap_or(0)));
        let socket = UdpSocket::bind(addr)
            .map_err(|e| anyhow!("failed to bind overlay helper socket {addr}: {e}"))?;
        let id = SocketId(u32::try_from(self.sockets.len())?);
        self.sockets.push(socket);
        Ok(id)
    }
}

async fn run_driver(
    identity: &OverlayIdentity,
    config: OverlayConfig,
    source_rx: Option<kanal::AsyncReceiver<PacketInfo>>,
    filter_tx: kanal::AsyncSender<PacketInfo>,
) -> Result<()> {
    let mut env = GlommioEnv::bind_primary(config.bind_addr)?;
    let transport =
        OverlayQuicTransport::new(SocketId::PRIMARY, identity, &TransportOptions::default())?;
    let source_mode = config.mode == OverlayMode::Source && source_rx.is_some();
    let mut core = OverlayCore::new(transport, &config, Instant::now());
    let mut buffer = vec![0u8; UDP_BUFFER_SIZE];

    loop {
        core.on_timer(&mut env);

        if let Some(source_rx) = &source_rx {
            loop {
                match source_rx.try_recv() {
                    Ok(Some(packet)) => core.on_source_packet(&mut env, packet),
                    Ok(None) => break,
                    Err(e) => {
                        log::warn!("overlay: source shred channel closed: {e}");
                        break;
                    }
                }
            }
        }

        env.flush().await;
        while let Some(event) = core.poll_event() {
            match event {
                CoreEvent::ShredForFilter(packet) => {
                    if let Err(e) = filter_tx.send(packet).await {
                        log::warn!("overlay: failed to forward shred to filter: {e}");
                    }
                }
                CoreEvent::PeerConnected { peer, pubkey } => {
                    log::debug!("overlay: peer {peer} connected, identity {pubkey:?}");
                }
                CoreEvent::PeerDisconnected { peer, reason } => {
                    log::debug!("overlay: peer {peer} disconnected: {reason}");
                }
            }
        }

        let now = Instant::now();
        let mut wait = core
            .poll_timeout()
            .map(|due| due.saturating_duration_since(now))
            .unwrap_or(RECEIVE_POLL_INTERVAL)
            .min(RECEIVE_POLL_INTERVAL);
        if source_mode {
            wait = wait.min(SOURCE_POLL_INTERVAL);
        }
        let received = timeout(
            wait.max(MIN_RECEIVE_WAIT),
            env.sockets[0].recv_from(&mut buffer),
        )
        .await;
        match received {
            Ok((len, from)) => {
                core.on_datagram(&mut env, SocketId::PRIMARY, from, &buffer[..len]);
                env.flush().await;
            }
            Err(_) => {
                // Receive window elapsed; due deadlines fire at the top of
                // the next iteration.
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
) -> Result<()> {
    let identity = OverlayIdentity::from_keypair(&keypair)?;
    log::info!("overlay identity: {}", identity.pubkey);

    let runner_task = spawn_local(async move {
        if let Err(e) = run_driver(&identity, config, source_rx, filter_tx).await {
            log::error!("overlay: driver stopped: {e}");
        }
    });

    exit.await;
    runner_task.cancel().await;
    Ok(())
}

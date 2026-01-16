use anyhow::anyhow;
use std::net::SocketAddr;

use arrayvec::ArrayVec;
use glommio::{net::UdpSocket, spawn_local};

use crate::{
    thread_manager::CancelRx,
    types::{PacketInfo, PacketView},
};

const BUFFER_SIZE: usize = solana_packet::PACKET_DATA_SIZE;

pub async fn recv_shred(socket: &UdpSocket) -> Option<(PacketView, SocketAddr)> {
    let mut buffer = [0; BUFFER_SIZE];
    let (packet_sz, send_addr) = match socket.recv_from(&mut buffer).await {
        Ok((sz, send_addr)) => (sz, send_addr),
        Err(e) => {
            log::error!("failed to receive turbine datagram: {e}");
            return None;
        }
    };
    let mut packet = ArrayVec::from(buffer);
    packet.truncate(packet_sz);

    Some((packet, send_addr))
}

pub async fn start_turbine_manager(
    exit: CancelRx,
    addr: SocketAddr,
    filter_tx: kanal::AsyncSender<PacketInfo>,
) -> anyhow::Result<()> {
    let socket =
        UdpSocket::bind(addr).map_err(|e| anyhow!("failed to create turbine socket {e}"))?;

    let packet_task = spawn_local(async move {
        loop {
            let Some((packet, _)) = recv_shred(&socket).await else {
                continue;
            };
            let packet = PacketInfo::new(packet);
            if let Err(e) = filter_tx.send(packet.clone()).await {
                log::warn!("failed to send packet to filter: {e}");
            }
        }
    });

    exit.await;
    packet_task.cancel().await;

    Ok(())
}

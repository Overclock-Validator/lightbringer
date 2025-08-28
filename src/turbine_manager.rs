use anyhow::anyhow;
use std::net::SocketAddr;

use arrayvec::ArrayVec;
use glommio::{net::UdpSocket, spawn_local};
use solana_sdk::packet;

use crate::{thread_manager::CancelRx, types::ShredInfo};

const BUFFER_SIZE: usize = packet::PACKET_DATA_SIZE;

pub async fn start_turbine_manager(
    exit: CancelRx,
    addr: SocketAddr,
    slot_store_tx: kanal::AsyncSender<ShredInfo>,
    slot_meta_tx: kanal::AsyncSender<ShredInfo>,
) -> anyhow::Result<()> {
    let socket =
        UdpSocket::bind(addr).map_err(|e| anyhow!("failed to create turbine socket {e}"))?;

    let packet_task = spawn_local(async move {
        loop {
            let mut buffer = [0; BUFFER_SIZE];
            let packet_sz = match socket.recv_from(&mut buffer).await {
                Ok((sz, _)) => sz,
                Err(e) => {
                    log::error!("failed to receive turbine datagram: {e}");
                    return;
                }
            };
            let mut packet = ArrayVec::from(buffer);
            packet.truncate(packet_sz);
            let packet = ShredInfo::new(packet);
            if let Err(e) = slot_store_tx.send(packet.clone()).await {
                log::warn!("failed to send packet to slot store: {e}");
            }
            if let Err(e) = slot_meta_tx.send(packet).await {
                log::warn!("failed to send packet to slot meta: {e}");
            }
        }
    });

    exit.await;
    packet_task.cancel().await;

    Ok(())
}

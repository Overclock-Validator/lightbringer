use std::{net::SocketAddr, rc::Rc, sync::Arc};

use futures::{StreamExt, stream::FuturesUnordered};
use glommio::{net::UdpSocket, spawn_local};
use solana_core::repair::serve_repair::{
    REPAIR_RESPONSE_SERIALIZED_PING_BYTES, RepairProtocol, RepairResponse,
};
use solana_gossip::ping_pong::Pong;
use solana_sdk::signature::{Keypair, Signable};

use crate::{
    thread_manager::CancelRx,
    turbine_manager::recv_shred,
    types::{PacketInfo, PacketView},
};

pub type RepairSocketRequestBatch = Vec<(SocketAddr, Vec<u8>)>;

// attempt to handle ping packet,
// returning true if handled, false if not a ping
async fn handle_ping(
    kp: &Keypair,
    socket: &UdpSocket,
    packet: &PacketView,
    send_addr: SocketAddr,
) -> bool {
    if packet.len() != REPAIR_RESPONSE_SERIALIZED_PING_BYTES {
        return false;
    }
    let Ok(RepairResponse::Ping(ping)) = bincode::deserialize(packet) else {
        return false;
    };
    if !ping.verify() {
        return false;
    }

    let pong = RepairProtocol::Pong(Pong::new(&ping, kp));
    let raw_pong = bincode::serialize(&pong).unwrap();

    if let Err(e) = socket.send_to(&raw_pong, send_addr).await {
        log::error!("failed to send pong to {send_addr}: {e}, ignored");
    }

    true
}

pub async fn start_repair_socket_runner(
    exit: CancelRx,
    kp: Arc<Keypair>,
    socket: UdpSocket,
    req_rx: kanal::AsyncReceiver<RepairSocketRequestBatch>,
    repair_manager_tx: kanal::AsyncSender<(SocketAddr, PacketInfo)>,
) {
    let socket = Rc::new(socket);

    let req_socket = socket.clone();
    let rx_task = spawn_local(async move {
        while let Ok(requests) = req_rx.recv().await {
            let mut res = requests
                .into_iter()
                .map(async |(add, packet)| {
                    if let Err(e) = req_socket.send_to(&packet, add).await {
                        log::error!("failed to send repair packet to {add}: {e}");
                    }
                })
                .collect::<FuturesUnordered<_>>();

            while res.next().await.is_some() {}
        }
    });

    let tx_task = spawn_local(async move {
        // TODO: add stronger filters for repair shreds
        loop {
            let Some((packet, send_addr)) = recv_shred(&socket).await else {
                continue;
            };
            if handle_ping(&kp, &socket, &packet, send_addr).await {
                continue;
            }

            let packet = PacketInfo::new(packet);
            if let Err(e) = repair_manager_tx.send((send_addr, packet)).await {
                log::warn!("failed to send packet to repair manager: {e}");
            }
        }
    });

    exit.await;
    rx_task.cancel().await;
    tx_task.cancel().await;
}

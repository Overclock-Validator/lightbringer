use std::net::SocketAddr;

use futures::{StreamExt, stream::FuturesUnordered};
use glommio::{net::UdpSocket, spawn_local};

use crate::thread_manager::CancelRx;

pub type RepairSocketRequestBatch = Vec<(SocketAddr, Vec<u8>)>;

pub async fn start_repair_socket_runner(
    exit: CancelRx,
    socket: UdpSocket,
    req_rx: kanal::AsyncReceiver<RepairSocketRequestBatch>,
) {
    let rx_task = spawn_local(async move {
        while let Ok(requests) = req_rx.recv().await {
            let mut res = requests
                .into_iter()
                .map(async |(add, packet)| {
                    if let Err(e) = socket.send_to(&packet, add).await {
                        log::error!("failed to send repair packet to {add}: {e}");
                    }
                })
                .collect::<FuturesUnordered<_>>();

            while res.next().await.is_some() {}
        }
    });

    exit.await;
    rx_task.cancel().await;
}

use std::{net::SocketAddr, rc::Rc};

use futures::{StreamExt, stream::FuturesUnordered};
use glommio::{net::UdpSocket, spawn_local};

use crate::{thread_manager::CancelRx, turbine_manager::shred_processor_loop, types::ShredInfo};

pub type RepairSocketRequestBatch = Vec<(SocketAddr, Vec<u8>)>;

pub async fn start_repair_socket_runner(
    exit: CancelRx,
    socket: UdpSocket,
    req_rx: kanal::AsyncReceiver<RepairSocketRequestBatch>,
    req_filter_tx: kanal::AsyncSender<ShredInfo>,
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
        shred_processor_loop(&socket, req_filter_tx, true).await
    });

    exit.await;
    rx_task.cancel().await;
    tx_task.cancel().await;
}

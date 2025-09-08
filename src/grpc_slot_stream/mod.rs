mod pb {
    tonic::include_proto!("slot_stream");
}

use futures::Stream;
use pb::{SlotResponse, SlotStreamRequest, slot_stream_server::SlotStream as SlotStreamTrait};
use tokio::{
    runtime,
    sync::broadcast,
    task::{spawn, spawn_blocking},
};
use tokio_stream::{StreamExt, wrappers::BroadcastStream};
use tonic::{Request, Response, Status, transport::Server};

use crate::{store::shred::ShredStore, util::shred::get_slot_entries_from_store};
use std::{net::SocketAddr, pin::Pin};

#[derive(Debug, Clone)]
pub struct SlotStreamService {
    tx: broadcast::Sender<(String, u64)>,
}

impl SlotStreamService {
    pub fn new(slot_notif: kanal::AsyncReceiver<u64>, store: ShredStore) -> Self {
        let (broadcast_tx, _) = broadcast::channel(10000);

        let broadcast_tx_master = broadcast_tx.clone();
        spawn(async move {
            while let Ok(slot) = slot_notif.recv().await {
                let shred_store = store.clone();
                let msg =
                    match spawn_blocking(move || get_slot_entries_from_store(&shred_store, slot))
                        .await
                        .unwrap()
                    {
                        Ok(e) => serde_json::to_string(&e).unwrap(),
                        Err(e) => e.to_string(),
                    };
                if broadcast_tx_master.send((msg, slot)).is_err() {
                    return;
                }
            }
        });

        Self { tx: broadcast_tx }
    }
}

#[tonic::async_trait]
impl SlotStreamTrait for SlotStreamService {
    type StreamSlotsStream = Pin<Box<dyn Stream<Item = Result<SlotResponse, Status>> + Send>>;

    async fn stream_slots(
        &self,
        _request: Request<SlotStreamRequest>,
    ) -> Result<Response<Self::StreamSlotsStream>, Status> {
        let rx = self.tx.subscribe();

        let stream = BroadcastStream::new(rx).filter_map(|result| match result {
            Ok((data, slot)) => Some(Ok(SlotResponse { data, slot })),
            Err(_) => None,
        });

        Ok(Response::new(Box::pin(stream)))
    }
}

pub fn start_grpc_server(
    addr: SocketAddr,
    slot_notif: kanal::AsyncReceiver<u64>,
    store: ShredStore,
    cancel: oneshot::Receiver<()>,
) {
    let rt = runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        let service = SlotStreamService::new(slot_notif, store);

        log::info!("SlotStremaService grpc listening on {addr}");

        Server::builder()
            .add_service(pb::slot_stream_server::SlotStreamServer::new(service))
            .serve_with_shutdown(addr, async move { _ = cancel.await })
            .await
            .unwrap();
    });
}

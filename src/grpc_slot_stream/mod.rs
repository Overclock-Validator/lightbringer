pub mod slot_entry;
pub mod slot_stream_pb {
    tonic::include_proto!("slot_stream");
}

use futures::Stream;
use slot_stream_pb::{
    SlotResponse, SlotStreamRequest, slot_stream_server::SlotStream as SlotStreamTrait,
};
use tokio::{
    runtime,
    sync::broadcast,
    task::{spawn, spawn_blocking},
};
use tokio_stream::{StreamExt, wrappers::BroadcastStream};
use tonic::{Request, Response, Status, transport::Server};

use crate::{store::shred::SlotRaw, util::shred::get_slot_entries_from_raw_shreds};
use slot_entry::Entry;
use std::{net::SocketAddr, pin::Pin};

#[derive(Debug, Clone)]
pub struct SlotStreamService {
    tx: broadcast::Sender<(Vec<Entry>, u64)>,
}

impl SlotStreamService {
    pub fn new(slot_notif: kanal::AsyncReceiver<SlotRaw>) -> Self {
        let (broadcast_tx, _) = broadcast::channel(10000);

        let broadcast_tx_master = broadcast_tx.clone();
        spawn(async move {
            while let Ok(slot_raw) = slot_notif.recv().await {
                let res = spawn_blocking(move || {
                    get_slot_entries_from_raw_shreds(slot_raw.shreds.iter().map(|s| s.as_slice()))
                });
                let msg = match res.await.unwrap() {
                    Ok(entries) => entries.into_iter().map(|e| e.into()).collect(),
                    Err(e) => {
                        log::warn!("failed to get slot entries for slot {}: {e}", slot_raw.slot);
                        continue;
                    }
                };
                _ = broadcast_tx_master.send((msg, slot_raw.slot));
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
            Ok((entries, slot)) => Some(Ok(SlotResponse { entries, slot })),
            Err(_) => None,
        });

        Ok(Response::new(Box::pin(stream)))
    }
}

pub fn start_grpc_server(
    addr: SocketAddr,
    slot_notif: kanal::AsyncReceiver<SlotRaw>,
    cancel: oneshot::Receiver<()>,
) {
    let rt = runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        let service = SlotStreamService::new(slot_notif);

        log::info!("SlotStremaService grpc listening on {addr}");

        Server::builder()
            .add_service(slot_stream_pb::slot_stream_server::SlotStreamServer::new(
                service,
            ))
            .serve_with_shutdown(addr, async move { _ = cancel.await })
            .await
            .unwrap();
    });
}

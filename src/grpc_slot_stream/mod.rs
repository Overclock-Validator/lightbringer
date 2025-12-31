pub mod slot_entry;
pub mod slot_stream_pb {
    tonic::include_proto!("slot_stream");
}
pub mod shred_source;

use futures::{Stream, StreamExt, future, stream};
use slot_stream_pb::{
    SlotResponse, SlotStreamRequest, slot_stream_server::SlotStream as SlotStreamTrait,
};
use tokio::{
    runtime,
    sync::broadcast,
    task::{spawn, spawn_blocking},
};
use tokio_stream::wrappers::BroadcastStream;
use tonic::{Request, Response, Status, transport::Server};

use crate::{
    grpc_slot_stream::shred_source::ShredSource, rpc::RpcError, store::shred::ShredStore,
    util::shred::get_slot_entries_from_raw_shreds,
};
use slot_entry::Entry;
use std::{net::SocketAddr, pin::Pin};

#[derive(Clone)]
pub struct SlotStreamService {
    tx: broadcast::Sender<(Vec<Entry>, u64)>,
    store: ShredStore,
}

impl SlotStreamService {
    pub fn new<S: ShredSource + 'static>(mut slot_stream: S, store: ShredStore) -> Self {
        let (broadcast_tx, _) = broadcast::channel(10000);

        let broadcast_tx_master = broadcast_tx.clone();
        spawn(async move {
            while let Some((slot, shreds)) = slot_stream.next().await {
                let res = spawn_blocking(move || {
                    get_slot_entries_from_raw_shreds(shreds.iter().map(|s| S::shred_bytes(s)))
                });
                let msg = match res.await.unwrap() {
                    Ok(entries) => entries.into_iter().map(|e| e.into()).collect(),
                    Err(e) => {
                        log::warn!("failed to get slot entries for slot {slot}: {e}");
                        continue;
                    }
                };
                _ = broadcast_tx_master.send((msg, slot));
            }
        });

        Self {
            tx: broadcast_tx,
            store,
        }
    }
}

#[tonic::async_trait]
impl SlotStreamTrait for SlotStreamService {
    type StreamSlotsStream = Pin<Box<dyn Stream<Item = Result<SlotResponse, Status>> + Send>>;
    type CatchupSlotsStream = Pin<Box<dyn Stream<Item = Result<SlotResponse, Status>> + Send>>;

    async fn stream_slots(
        &self,
        _request: Request<SlotStreamRequest>,
    ) -> Result<Response<Self::StreamSlotsStream>, Status> {
        let rx = self.tx.subscribe();

        let stream = BroadcastStream::new(rx).filter_map(|result| {
            let res = match result {
                Ok((entries, slot)) => Some(Ok(SlotResponse { entries, slot })),
                Err(_) => None,
            };
            future::ready(res)
        });

        Ok(Response::new(Box::pin(stream)))
    }

    async fn catchup_slots(
        &self,
        request: Request<slot_stream_pb::CatchupRequest>,
    ) -> Result<Response<Self::CatchupSlotsStream>, Status> {
        let req = request.into_inner();
        let store = self.store.clone();
        let slot_stream = stream::iter((req.from_slot_inclusive..req.to_slot_exclusive).map(
            move |slot| {
                let store = store.clone();
                async move {
                    spawn_blocking(move || {
                        let shreds = store.get_slot_shreds(slot)?;
                        let entries = get_slot_entries_from_raw_shreds(shreds).map(|ents| {
                            ents.into_iter().map(|e| e.into()).collect::<Vec<Entry>>()
                        })?;
                        Ok::<_, RpcError>(SlotResponse { entries, slot })
                    })
                    .await
                    .unwrap()
                }
            },
        ))
        .buffer_unordered(10)
        .filter_map(|res| future::ready(res.ok().map(Ok)));

        Ok(Response::new(Box::pin(slot_stream)))
    }
}

pub fn start_grpc_server(
    addr: SocketAddr,
    slot_notif: impl ShredSource + 'static,
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
            .add_service(slot_stream_pb::slot_stream_server::SlotStreamServer::new(
                service,
            ))
            .serve_with_shutdown(addr, async move { _ = cancel.await })
            .await
            .unwrap();
    });
}

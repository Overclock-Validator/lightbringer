mod slot_entry;
mod slot_stream_pb {
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
use tokio_util::time::DelayQueue;
use tonic::{Request, Response, Status, transport::Server};

use crate::{store::shred::ShredStore, util::shred::get_slot_entries_from_store};
use slot_entry::Entry;
use std::{net::SocketAddr, pin::Pin, time::Duration};

#[derive(Debug, Clone)]
pub struct SlotStreamService {
    tx: broadcast::Sender<(Vec<Entry>, u64)>,
}

impl SlotStreamService {
    pub fn new(slot_notif: kanal::AsyncReceiver<u64>, store: ShredStore) -> Self {
        let (broadcast_tx, _) = broadcast::channel(10000);

        let broadcast_tx_master = broadcast_tx.clone();
        spawn(async move {
            let mut dq = DelayQueue::new();
            let mut fut = Box::pin(slot_notif.recv());

            loop {
                tokio::select! {
                    res = &mut fut => {
                        let Ok(slot) = res else {
                            break;
                        };
                        dq.insert(slot, Duration::from_millis(100));
                        fut = Box::pin(slot_notif.recv());
                    },
                    slot = dq.next() => {
                        let Some(slot) = slot else {
                            let Ok(slot) = fut.await else {
                                break;
                            };
                            dq.insert(slot, Duration::from_millis(100));
                            fut = Box::pin(slot_notif.recv());
                            continue;
                        };

                        let shred_store = store.clone();
                        let slot = slot.into_inner();
                        let msg =
                            match spawn_blocking(move || get_slot_entries_from_store(&shred_store, slot))
                                .await
                                .unwrap()
                            {
                                Ok(e) => e.into_iter().map(|e| e.into()).collect(),
                                Err(e) => {
                                    log::warn!("failed to get slot entries for slot {slot}: {e}");
                                    continue
                                },
                            };

                        _ = broadcast_tx_master.send((msg, slot));
                    }
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
            Ok((entries, slot)) => Some(Ok(SlotResponse { entries, slot })),
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
            .add_service(slot_stream_pb::slot_stream_server::SlotStreamServer::new(
                service,
            ))
            .serve_with_shutdown(addr, async move { _ = cancel.await })
            .await
            .unwrap();
    });
}

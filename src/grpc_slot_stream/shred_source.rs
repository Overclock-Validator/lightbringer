use std::{cell::RefCell, collections::BTreeSet, ops::Deref, rc::Rc};

use fjall::Slice;
use glommio::{
    Task,
    channels::local_channel::{self, LocalSender},
    enclose, spawn_local,
};
use kanal::{AsyncReceiver, AsyncSender};
use uluru::LRUCache;

use crate::{
    block_conf::{BlockConfStream, BlockConfUpdate},
    store::shred::{ShredStore, SlotRaw},
    thread_manager::CancelRx,
    types::{PacketInfo, ShredInfoView},
};

pub struct SlotForGrpc<Shred> {
    pub slot: u64,
    pub shreds: Vec<Shred>,
    pub expected_blockhash: Option<[u8; 32]>,
}

pub(crate) trait ShredSource: Send {
    type Shred: Send + 'static;

    fn next(&mut self) -> impl Future<Output = Option<SlotForGrpc<Self::Shred>>> + Send;

    fn shred_bytes(shred: &Self::Shred) -> &[u8];
}

pub struct SlotMetaShreds {
    rx: kanal::AsyncReceiver<SlotRaw>,
}

impl SlotMetaShreds {
    pub fn new(rx: kanal::AsyncReceiver<SlotRaw>) -> Self {
        Self { rx }
    }
}

impl ShredSource for SlotMetaShreds {
    type Shred = PacketInfo;

    async fn next(&mut self) -> Option<SlotForGrpc<PacketInfo>> {
        self.rx.recv().await.ok().map(|sr| SlotForGrpc {
            slot: sr.slot,
            shreds: sr.shreds,
            expected_blockhash: None,
        })
    }

    fn shred_bytes(shred: &Self::Shred) -> &[u8] {
        shred
    }
}

#[derive(Clone, Default)]
struct SlotShredsWaiter {
    finished_slots: Rc<RefCell<BTreeSet<u64>>>,
    slot_cache: Rc<RefCell<LRUCache<(u64, Vec<ShredInfoView>), 300>>>,
    block_notif: Rc<RefCell<Option<(u64, LocalSender<Vec<ShredInfoView>>)>>>,
}

impl SlotShredsWaiter {
    /// Insert a slot, notifying the receiver if they are waiting for it
    fn insert(&self, slot: SlotRaw) {
        let mut block_notif = self.block_notif.borrow_mut();
        let mut finished_slots = self.finished_slots.borrow_mut();
        let shreds = slot
            .shreds
            .into_iter()
            .map(|s| Slice::from(s.as_slice()))
            .collect();

        let Some((slot_num, tx)) = block_notif.as_ref() else {
            self.slot_cache.borrow_mut().insert((slot.slot, shreds));
            finished_slots.insert(slot.slot);
            return;
        };
        if slot.slot != *slot_num {
            self.slot_cache.borrow_mut().insert((slot.slot, shreds));
            finished_slots.insert(slot.slot);
            return;
        }

        _ = tx.try_send(shreds);
        *block_notif = None;
    }

    async fn send_slot_shreds(
        &self,
        store: &ShredStore,
        tx: &AsyncSender<SlotForGrpc<ShredInfoView>>,
        update: BlockConfUpdate,
    ) -> Option<()> {
        let slot = update.slot;
        let shreds = if self.finished_slots.borrow_mut().remove(&slot) {
            if let Some((_, shreds)) = self.slot_cache.borrow_mut().find(|(s, _)| *s == slot) {
                shreds.clone()
            } else {
                let Ok(shreds) = store.get_slot_shreds(slot) else {
                    log::warn!("could not get shreds for slot {}", slot);
                    return Some(());
                };
                shreds
            }
        } else {
            let (tx, rx) = local_channel::new_bounded(1);
            *self.block_notif.borrow_mut() = Some((slot, tx));
            rx.recv().await?
        };

        tx.send(SlotForGrpc {
            slot,
            shreds,
            expected_blockhash: Some(update.block_hash),
        })
        .await
        .ok()?;

        Some(())
    }
}

async fn confirmed_slot_shreds_glommio_runner_with_backqueue(
    mut conf_stream: BlockConfStream,
    slot_meta_stream: AsyncReceiver<SlotRaw>,
    store: ShredStore,
    tx: AsyncSender<SlotForGrpc<ShredInfoView>>,
) -> Option<()> {
    let (first_slot_tx, first_slot_rx) = local_channel::new_bounded(1);
    let (first_grpc_slot_tx, first_grpc_slot_rx) = local_channel::new_bounded(1);
    let shreds_waiter = SlotShredsWaiter::default();

    let slot_meta_handle = spawn_local(enclose!((shreds_waiter) async move {
        let Ok(first_slot_shreds) = slot_meta_stream.recv().await else {
            log::error!("slot meta stream ended before first slot received");
            return None;
        };
        let first_slot = first_slot_shreds.slot;
        shreds_waiter.insert(first_slot_shreds);
        first_slot_tx.try_send(first_slot).ok()?;
        let first_grpc_slot = first_grpc_slot_rx.recv().await?;

        while let Ok(slot) = slot_meta_stream.recv().await {
            if slot.slot < first_grpc_slot {
                continue;
            }
            shreds_waiter.insert(slot);
        }
        Some(())
    }));

    // This wrapper is required because the confirmation stream must be driven constantly
    // else the websocket connection will be dropped
    let (conf_stream_tx, conf_stream_rx) = local_channel::new_bounded(1000);
    let conf_stream_handle = spawn_local(async move {
        while let Ok(notif) = conf_stream.next().await {
            if conf_stream_tx.send(notif).await.is_err() {
                break;
            }
        }
    });

    let slot_shreds_handle: Task<Option<()>> =
        spawn_local(enclose!((shreds_waiter, tx) async move {
            let first_slot = first_slot_rx.recv().await?;
            log::info!("grpc slot stream is waiting for first confirmed slot... > {first_slot}");
            loop {
                let notif = conf_stream_rx.recv().await?;
                if first_slot > notif.slot {
                    continue;
                }
                log::info!("started grpc slot streaming from {}", notif.slot);
                first_grpc_slot_tx.try_send(notif.slot).ok()?;
                shreds_waiter.send_slot_shreds(&store, &tx, notif).await?;
                break;
            }

            loop {
                let notif = conf_stream_rx.recv().await?;
                log::info!("recv conf slot notif: slot {}", notif.slot);
                shreds_waiter.send_slot_shreds(&store, &tx, notif).await?;
            }
        }));

    conf_stream_handle.await;
    _ = slot_shreds_handle.cancel().await;
    _ = slot_meta_handle.cancel().await;
    Some(())
}

pub async fn confirmed_slot_shreds_glommio_runner(
    conf_stream: BlockConfStream,
    slot_meta_stream: AsyncReceiver<SlotRaw>,
    store: ShredStore,
    tx: AsyncSender<SlotForGrpc<ShredInfoView>>,
    exit: CancelRx,
) {
    let handle = spawn_local(confirmed_slot_shreds_glommio_runner_with_backqueue(
        conf_stream,
        slot_meta_stream,
        store,
        tx,
    ));
    exit.await;
    handle.cancel().await;
}

pub struct ConfirmedSlotShreds {
    glommio_rx: AsyncReceiver<SlotForGrpc<ShredInfoView>>,
}

impl ConfirmedSlotShreds {
    pub fn new(glommio_rx: AsyncReceiver<SlotForGrpc<ShredInfoView>>) -> Self {
        Self { glommio_rx }
    }
}

impl ShredSource for ConfirmedSlotShreds {
    type Shred = ShredInfoView;

    async fn next(&mut self) -> Option<SlotForGrpc<ShredInfoView>> {
        self.glommio_rx.recv().await.ok()
    }

    fn shred_bytes(shred: &Self::Shred) -> &[u8] {
        shred.deref()
    }
}

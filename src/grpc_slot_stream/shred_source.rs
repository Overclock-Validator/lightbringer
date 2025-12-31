use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    ops::Deref,
    rc::Rc,
};

use fjall::Slice;
use glommio::{enclose, spawn_local};
use kanal::{AsyncReceiver, AsyncSender, SendError};

use crate::{
    block_conf::BlockConfStream,
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

async fn confirmed_slot_shreds_glommio_runner_inner(
    mut conf_stream: BlockConfStream,
    store: ShredStore,
    finished_blocks: &RefCell<HashSet<u64>>,
    back_queue: &RefCell<HashMap<u64, [u8; 32]>>,
    tx: AsyncSender<SlotForGrpc<ShredInfoView>>,
) -> Option<()> {
    loop {
        let notif = conf_stream.next().await.ok()?;
        let shreds = if finished_blocks.borrow_mut().remove(&notif.slot) {
            let Ok(shreds) = store.get_slot_shreds(notif.slot) else {
                log::warn!("failed to get shreds for confirmed slot {}", notif.slot);
                continue;
            };
            shreds
        } else {
            back_queue.borrow_mut().insert(notif.slot, notif.block_hash);
            continue;
        };

        tx.send(SlotForGrpc {
            slot: notif.slot,
            shreds,
            expected_blockhash: Some(notif.block_hash),
        })
        .await
        .ok()?;
    }
}

async fn confirmed_slot_shreds_glommio_runner_with_backqueue(
    conf_stream: BlockConfStream,
    slot_meta_stream: AsyncReceiver<SlotRaw>,
    store: ShredStore,
    tx: AsyncSender<SlotForGrpc<ShredInfoView>>,
) -> Option<()> {
    let finished_blocks = Rc::new(RefCell::new(HashSet::new()));
    let back_queue = Rc::new(RefCell::new(HashMap::new()));
    let slot_meta_handle = spawn_local(enclose!((finished_blocks, back_queue, tx) async move {
        while let Ok(slot) = slot_meta_stream.recv().await {
            let Some(expected_blockhash) = back_queue.borrow_mut().remove(&slot.slot) else {
                finished_blocks.borrow_mut().insert(slot.slot);
                continue;
            };
            tx.send(SlotForGrpc {
                slot: slot.slot,
                shreds: slot
                    .shreds
                    .iter()
                    .map(|s| Slice::from(s.as_slice())) // suboptimal clone :P
                    .collect(),
                expected_blockhash: Some(expected_blockhash),
            }).await?;
        }
        Ok::<_, SendError>(())
    }));
    let conf_block_handle = spawn_local(enclose!((finished_blocks, back_queue, tx) async move {
        confirmed_slot_shreds_glommio_runner_inner(
            conf_stream,
            store,
            &finished_blocks,
            &back_queue,
            tx,
        )
        .await
    }));

    conf_block_handle.await?;
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

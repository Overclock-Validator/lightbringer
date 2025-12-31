use std::ops::Deref;

use glommio::spawn_local;
use kanal::{AsyncReceiver, AsyncSender};

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
    tx: AsyncSender<SlotForGrpc<ShredInfoView>>,
) -> Option<()> {
    loop {
        let notif = conf_stream.next().await.ok()?;
        let Ok(shreds) = store.get_slot_shreds(notif.slot) else {
            log::warn!("failed to get shreds for confirmed slot {}", notif.slot);
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

pub async fn confirmed_slot_shreds_glommio_runner(
    conf_stream: BlockConfStream,
    store: ShredStore,
    tx: AsyncSender<SlotForGrpc<ShredInfoView>>,
    exit: CancelRx,
) {
    let handle = spawn_local(confirmed_slot_shreds_glommio_runner_inner(
        conf_stream,
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

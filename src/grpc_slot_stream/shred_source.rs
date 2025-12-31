use std::ops::Deref;

use glommio::spawn_local;
use kanal::{AsyncReceiver, AsyncSender};

use crate::{
    block_conf::BlockConfStream,
    store::shred::{ShredStore, SlotRaw},
    thread_manager::CancelRx,
    types::{PacketInfo, ShredInfoView},
};

pub(crate) trait ShredSource: Send {
    type Shred: Send + 'static;

    fn next(&mut self) -> impl Future<Output = Option<(u64, Vec<Self::Shred>)>> + Send;

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

    async fn next(&mut self) -> Option<(u64, Vec<PacketInfo>)> {
        self.rx.recv().await.ok().map(|sr| (sr.slot, sr.shreds))
    }

    fn shred_bytes(shred: &Self::Shred) -> &[u8] {
        shred
    }
}

async fn confirmed_slot_shreds_glommio_runner_inner(
    mut conf_stream: BlockConfStream,
    store: ShredStore,
    tx: AsyncSender<(u64, Vec<ShredInfoView>)>,
) -> Option<()> {
    loop {
        let notif = conf_stream.next().await.ok()?;
        let Ok(shreds) = store.get_slot_shreds(notif.slot) else {
            log::warn!("failed to get shreds for confirmed slot {}", notif.slot);
            continue;
        };
        tx.send((notif.slot, shreds)).await.ok()?;
    }
}

pub async fn confirmed_slot_shreds_glommio_runner(
    conf_stream: BlockConfStream,
    store: ShredStore,
    tx: AsyncSender<(u64, Vec<ShredInfoView>)>,
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
    glommio_rx: AsyncReceiver<(u64, Vec<ShredInfoView>)>,
}

impl ConfirmedSlotShreds {
    pub fn new(glommio_rx: AsyncReceiver<(u64, Vec<ShredInfoView>)>) -> Self {
        Self { glommio_rx }
    }
}

impl ShredSource for ConfirmedSlotShreds {
    type Shred = ShredInfoView;

    async fn next(&mut self) -> Option<(u64, Vec<ShredInfoView>)> {
        self.glommio_rx.recv().await.ok()
    }

    fn shred_bytes(shred: &Self::Shred) -> &[u8] {
        shred.deref()
    }
}

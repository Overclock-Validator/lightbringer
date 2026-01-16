use std::time::Duration;

use glommio::{enclose, executor, spawn_local, timer::sleep};
use kanal::AsyncReceiver;
use solana_ledger::shred::{self, ShredType};

use crate::{
    thread_manager::CancelRx,
    types::{PacketInfo, ShredInfoView},
};

pub struct ShredRes {
    data: Option<ShredInfoView>,
    code: Option<ShredInfoView>,
}

#[derive(Clone)]
pub struct SlotRaw {
    pub slot: u64,
    pub shreds: Vec<PacketInfo>,
}

#[derive(Clone)]
pub struct ShredStore {
    db: fjall::Database,
    shred_keyspace: fjall::Keyspace,
}

impl ShredStore {
    pub fn new(db: fjall::Database) -> anyhow::Result<Self> {
        let shred_keyspace = db.keyspace("shred_store", Default::default)?;

        Ok(Self { db, shred_keyspace })
    }

    pub async fn slot_listener_loop(self, exit: CancelRx, rx: AsyncReceiver<SlotRaw>) {
        let this = self.clone();
        let task = spawn_local(enclose!((this) async move {
            let executor = executor();
            while let Ok(slot) = rx.recv().await {
                let this = this.clone();
                spawn_local(executor.spawn_blocking(move || {
                    if let Err(e) = this.store_slot(slot.slot, slot.shreds) {
                        log::warn!("failed to store slot {e}");
                    }
                }))
                .detach();
            }
            log::warn!("shred store thread died?!")
        }));
        let cleanup_task = spawn_local(this.slot_cleanup_loop());
        exit.await;
        task.cancel().await;
        cleanup_task.cancel().await;
    }

    async fn slot_cleanup_loop(self) {
        let executor = executor();
        loop {
            sleep(Duration::from_hours(1)).await;
            let this = self.clone();
            let res = executor
                .spawn_blocking(move || -> anyhow::Result<()> {
                    let Some(latest_slot) = this.shred_keyspace.last_key_value().and_then(|g| {
                        Some(u64::from_le_bytes(g.key().ok()?[0..8].try_into().unwrap()))
                    }) else {
                        return Ok(());
                    };

                    let cutoff_slot = latest_slot.saturating_sub(72000); // ~ 8 hrs
                    let keys: Vec<_> = this
                        .shred_keyspace
                        .range(..cutoff_slot.to_le_bytes())
                        .map(|k| k.key())
                        .collect::<Result<_, _>>()?;
                    let rm_count = keys.len();

                    let mut batch = this.db.batch();
                    for k in keys {
                        batch.remove(&this.shred_keyspace, k);
                    }
                    batch.commit()?;
                    log::info!("cleaned up {rm_count} shreds older than slot {cutoff_slot}");

                    Ok(())
                })
                .await;
            if let Err(e) = res {
                log::warn!("failed to cleanup shreds: {e}");
            }
        }
    }

    fn store_slot(&self, slot: u64, shreds: Vec<PacketInfo>) -> anyhow::Result<()> {
        let mut batch = self.db.batch();
        for shred in shreds {
            let shred_info = shred::layout::get_shred_id(&shred)
                .expect("received invalid shred from slot meta?!");
            let mut key = [0; 13];
            key[0..8].copy_from_slice(&slot.to_le_bytes());

            key[8..12].copy_from_slice(&shred_info.index().to_le_bytes());
            key[12] = match shred_info.shred_type() {
                shred::ShredType::Data => ShredType::Data,
                shred::ShredType::Code => ShredType::Code,
            } as u8;
            batch.insert(&self.shred_keyspace, key, shred.as_slice());
        }
        batch.commit()?;
        self.db.persist(fjall::PersistMode::SyncAll)?;

        Ok(())
    }

    pub fn get_slot_shreds(&self, slot: u64) -> fjall::Result<Vec<ShredInfoView>> {
        let mut shred_prefix = [0; 8];
        shred_prefix[0..8].copy_from_slice(&slot.to_le_bytes());

        let res = self
            .shred_keyspace
            .prefix(shred_prefix)
            .map(|shred_res| shred_res.value())
            .collect::<fjall::Result<_>>()?;

        Ok(res)
    }
}

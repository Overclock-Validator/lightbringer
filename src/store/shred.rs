use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use fjall::compaction::filter::{
    CompactionFilter, CompactionFilterResult, Context, Factory, ItemAccessor, Verdict,
};
use glommio::{enclose, executor, spawn_local, timer::sleep};
use kanal::AsyncReceiver;
use solana_ledger::shred::{self, ShredType};

use solana_gossip::cluster_info::ClusterInfo;

use crate::{
    thread_manager::CancelRx,
    types::{PacketInfo, ShredInfoView},
};

pub const SHRED_KEYSPACE: &str = "shred_store";
const RETENTION_SLOTS: u64 = 72_000; // ~ 8 hrs

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
pub struct BatchRaw {
    pub slot: u64,
    pub shreds: Vec<PacketInfo>,
}

#[derive(Clone)]
pub struct ShredStore {
    db: fjall::Database,
    shred_keyspace: fjall::Keyspace,
    cutoff_slot: Arc<AtomicU64>,
    cluster_info: Arc<ClusterInfo>,
}

struct ShredCutoffFilter(u64);

impl CompactionFilter for ShredCutoffFilter {
    fn filter_item(&mut self, item: ItemAccessor<'_>, _ctx: &Context) -> CompactionFilterResult {
        let key = item.key();
        if key.len() < 8 {
            return Ok(Verdict::Keep);
        }
        let slot = u64::from_le_bytes(key[0..8].try_into().unwrap());
        if slot < self.0 {
            Ok(Verdict::Destroy)
        } else {
            Ok(Verdict::Keep)
        }
    }
}

struct ShredCutoffFactory(Arc<AtomicU64>);

impl Factory for ShredCutoffFactory {
    fn make_filter(&self, _ctx: &Context) -> Box<dyn CompactionFilter> {
        Box::new(ShredCutoffFilter(self.0.load(Ordering::Relaxed)))
    }

    fn name(&self) -> &str {
        "shred-cutoff"
    }
}

pub fn compaction_filter_factories(
    cutoff_slot: Arc<AtomicU64>,
) -> Arc<dyn Fn(&str) -> Option<Arc<dyn Factory>> + Send + Sync> {
    Arc::new(move |keyspace| match keyspace {
        SHRED_KEYSPACE => Some(Arc::new(ShredCutoffFactory(cutoff_slot.clone()))),
        _ => None,
    })
}

impl ShredStore {
    pub fn new(
        db: fjall::Database,
        cutoff_slot: Arc<AtomicU64>,
        cluster_info: Arc<ClusterInfo>,
    ) -> anyhow::Result<Self> {
        let shred_keyspace = db.keyspace(SHRED_KEYSPACE, Default::default)?;

        Ok(Self {
            db,
            shred_keyspace,
            cutoff_slot,
            cluster_info,
        })
    }

    pub async fn batch_listener_loop(self, exit: CancelRx, rx: AsyncReceiver<BatchRaw>) {
        let this = self.clone();
        let task = spawn_local(enclose!((this) async move {
            let executor = executor();
            while let Ok(batch) = rx.recv().await {
                let this = this.clone();
                spawn_local(executor.spawn_blocking(move || {
                    if let Err(e) = this.store_batch(batch.slot, batch.shreds) {
                        log::warn!("failed to store batch {e}");
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

                    let cutoff_slot = latest_slot.saturating_sub(RETENTION_SLOTS);
                    this.cutoff_slot.store(cutoff_slot, Ordering::Relaxed);
                    this.shred_keyspace.major_compact()?;
                    log::info!("compacted shreds older than slot {cutoff_slot}");

                    Ok(())
                })
                .await;
            if let Err(e) = res {
                log::warn!("failed to cleanup shreds: {e}");
            }
        }
    }

    fn store_batch(&self, slot: u64, shreds: Vec<PacketInfo>) -> anyhow::Result<()> {
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
        self.cluster_info.push_lowest_slot(slot);

        Ok(())
    }

    pub fn get_shred(
        &self,
        slot: u64,
        shred_index: u64,
        shred_type: ShredType,
    ) -> fjall::Result<Option<ShredInfoView>> {
        let mut key = [0; 13];
        key[0..8].copy_from_slice(&slot.to_le_bytes());
        key[8..12].copy_from_slice(&(shred_index as u32).to_le_bytes());
        key[12] = shred_type as u8;
        self.shred_keyspace.get(key)
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

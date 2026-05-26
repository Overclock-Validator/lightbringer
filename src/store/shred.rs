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

/// Key layout (13 bytes, all big-endian for lexicographic ordering):
///   [0..8]  slot      (u64 BE)
///   [8..12] shred_idx (u32 BE)
///   [12]    shred_type (0x5A = Code, 0xA5 = Data)
fn make_key(slot: u64, shred_index: u32, shred_type: ShredType) -> [u8; 13] {
    let mut key = [0u8; 13];
    key[0..8].copy_from_slice(&slot.to_be_bytes());
    key[8..12].copy_from_slice(&shred_index.to_be_bytes());
    key[12] = shred_type as u8;
    key
}

fn slot_from_key(key: &[u8]) -> Option<u64> {
    let bytes: [u8; 8] = key.get(0..8)?.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
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
        let Some(slot) = slot_from_key(key) else {
            return Ok(Verdict::Keep);
        };
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
                    let Some(latest_slot) = this
                        .shred_keyspace
                        .last_key_value()
                        .and_then(|g| slot_from_key(&g.key().ok()?))
                    else {
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
            let key = make_key(
                slot,
                shred_info.index(),
                match shred_info.shred_type() {
                    shred::ShredType::Data => ShredType::Data,
                    shred::ShredType::Code => ShredType::Code,
                },
            );
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
        let key = make_key(slot, shred_index as u32, shred_type);
        self.shred_keyspace.get(key)
    }

    /// Get the first data shred with index >= `min_index` for a slot.
    pub fn get_first_data_shred_from(
        &self,
        slot: u64,
        min_index: u64,
    ) -> fjall::Result<Option<ShredInfoView>> {
        let start = make_key(slot, min_index as u32, ShredType::Data);
        let end = make_key(slot, u32::MAX, ShredType::Data);

        match self.shred_keyspace.range(start..=end).next_back() {
            Some(entry) => Ok(Some(entry.value()?)),
            None => Ok(None),
        }
    }

    pub fn get_slot_shreds(&self, slot: u64) -> fjall::Result<Vec<ShredInfoView>> {
        let prefix = slot.to_be_bytes();

        let res = self
            .shred_keyspace
            .prefix(prefix)
            .map(|shred_res| shred_res.value())
            .collect::<fjall::Result<_>>()?;

        Ok(res)
    }
}

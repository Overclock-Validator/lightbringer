// use pure in-memory data structures
// we'll use scc::HashMap
// FOR later: investigate queues

use std::{
    collections::{HashMap, HashSet},
    rc::Rc,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use glommio::{channels::local_channel, spawn_local, timer::TimerActionOnce};
use kanal::AsyncReceiver;
use lru::LruCache;
use solana_ledger::shred::Shred;

use crate::{thread_manager::CancelRx, types::ShredInfo};

pub const DEFER_REPAIR_THRESHOLD: Duration = Duration::from_millis(120);
const DATA_SHREDS_PER_FEC_SET: usize = 32;

pub struct FecMetadata {
    pub num_data_shreds: u16,
    pub num_coding_shreds: u16,
}

type FecMap = HashMap<u32, Vec<u32>>;
type FecInfoMap = HashMap<u32, FecMetadata>;
type SlotMetaStore = LruCache<u64, SlotMetadata>;

pub struct SlotMetadata {
    pub slot_num: u64,
    pub fec_data_map: FecMap,
    pub fec_coding_map: FecMap,
    pub fec_meta: FecInfoMap,
    pub timestamp_ms: u64,
    pub completed_batches: HashSet<u32>,
    pub required_batches: Option<usize>,
}

impl SlotMetadata {
    pub fn is_complete(&self) -> bool {
        Some(self.completed_batches.len()) == self.required_batches
    }
}

fn store_slot_metadata(cache: &mut SlotMetaStore, shred: Shred) {}

enum SlotMetaStoreRes {
    Complete,
    Incomplete,
    Ignored,
}

#[derive(Clone)]
pub struct SlotMetadataStore {
    inner: Arc<scc::HashCache<u64, SlotMetadata>>,
    version: u16,
}

enum SlotTimerMsg {
    ShredInsertion { slot: u64 },
    ShredCompletion { slot: u64 },
    ShredTimeout { slot: u64 },
}

impl SlotMetadataStore {
    pub fn new(version: u16) -> Self {
        // stores the last 4096 slots only
        let hash_cache = scc::HashCache::with_capacity(0, 4096);
        Self {
            inner: Arc::new(hash_cache),
            version,
        }
    }
    pub async fn packet_listener_loop(self, exit: CancelRx, rx: AsyncReceiver<ShredInfo>) {
        let (timer_tx, timer_rx) = local_channel::new_unbounded();
        let timer_tx = Rc::new(timer_tx);

        let shred_version = self.version;
        let meta_timer_tx = timer_tx.clone();
        let metadata_handler_task = spawn_local(async move {
            let timer_tx = meta_timer_tx.clone();
            while let Ok(shred) = rx.recv().await {
                let Ok(deser_shred) = Shred::new_from_serialized_shred(shred.to_vec()) else {
                    continue;
                };
                if deser_shred.version() != shred_version {
                    continue;
                }

                let slot = deser_shred.slot();
                let store_res = self.store_shred(deser_shred).await;
                let timer_msg = match store_res {
                    SlotMetaStoreRes::Ignored => continue,
                    SlotMetaStoreRes::Complete => SlotTimerMsg::ShredCompletion { slot },
                    SlotMetaStoreRes::Incomplete => SlotTimerMsg::ShredInsertion { slot },
                };
                _ = timer_tx.try_send(timer_msg);
            }
        });

        let staleness_monitor_task = spawn_local(async move {
            log::info!("started staleness monitor");
            let mut timers: HashMap<u64, TimerActionOnce<()>> = HashMap::new();
            while let Some(msg) = timer_rx.recv().await {
                match msg {
                    SlotTimerMsg::ShredInsertion { slot } => {
                        timers
                            .entry(slot)
                            .and_modify(|timer| {
                                timer.rearm_in(DEFER_REPAIR_THRESHOLD);
                            })
                            .or_insert_with(|| {
                                let timer_tx = timer_tx.clone();
                                TimerActionOnce::do_in(DEFER_REPAIR_THRESHOLD, async move {
                                    _ = timer_tx.send(SlotTimerMsg::ShredTimeout { slot }).await;
                                })
                            });
                    }
                    SlotTimerMsg::ShredCompletion { slot } => {
                        if let Some(timer) = timers.remove(&slot) {
                            timer.destroy();
                        }
                        log::info!("slot {slot} has all shreds!");
                    }
                    SlotTimerMsg::ShredTimeout { slot } => {
                        timers.remove(&slot);
                        log::info!(
                            "[UNIMPLIMENTED] slot {slot} has timed out, need to send to repair!"
                        );
                        // TODO: send to repair manager
                    }
                }
            }
        });
        exit.await;
        futures::join!(
            metadata_handler_task.cancel(),
            staleness_monitor_task.cancel()
        );
    }

    // stores the shred, returning whether slots are complete or not
    async fn store_shred(&self, shred: Shred) -> SlotMetaStoreRes {
        let slot = shred.slot();
        let fec_index = shred.fec_set_index();
        let shred_index = shred.index();

        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let (_, mut shred_entry) =
            self.inner
                .entry_async(slot)
                .await
                .or_put_with(|| SlotMetadata {
                    slot_num: slot,
                    fec_data_map: HashMap::new(),
                    fec_coding_map: HashMap::new(),
                    fec_meta: HashMap::new(),
                    timestamp_ms,
                    completed_batches: HashSet::new(),
                    required_batches: None,
                });
        let shred_meta = shred_entry.get_mut();
        if shred_meta.is_complete() {
            return SlotMetaStoreRes::Ignored;
        }

        let fec_map = match &shred {
            Shred::ShredData(_) => {
                if shred.last_in_slot() {
                    shred_meta.required_batches = Some(
                        (fec_index as usize + DATA_SHREDS_PER_FEC_SET) / DATA_SHREDS_PER_FEC_SET,
                    );
                }
                &mut shred_meta.fec_data_map
            }
            Shred::ShredCode(code_shred) => {
                if !shred_meta.fec_meta.contains_key(&shred.fec_set_index()) {
                    let header = code_shred.coding_header();
                    shred_meta.fec_meta.insert(
                        fec_index,
                        FecMetadata {
                            num_coding_shreds: header.num_coding_shreds,
                            num_data_shreds: header.num_data_shreds,
                        },
                    );
                }
                &mut shred_meta.fec_coding_map
            }
        };
        fec_map
            .entry(shred.fec_set_index())
            .or_insert_with(Vec::new)
            .push(shred_index);
        shred_meta.timestamp_ms = timestamp_ms;

        let completed_batch = shred_meta
            .fec_coding_map
            .get(&fec_index)
            .map(|m| m.len())
            .unwrap_or_default()
            + shred_meta
                .fec_data_map
                .get(&fec_index)
                .map(|m| m.len())
                .unwrap_or_default()
            >= DATA_SHREDS_PER_FEC_SET;
        if completed_batch {
            shred_meta.completed_batches.insert(fec_index);
        }

        if shred_meta.is_complete() {
            SlotMetaStoreRes::Complete
        } else {
            SlotMetaStoreRes::Incomplete
        }
    }
}

// use pure in-memory data structures
// we'll use scc::HashMap
// FOR later: investigate queues

use std::{
    collections::{BTreeSet, HashMap},
    rc::Rc,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use arrayvec::ArrayVec;
use glommio::{channels::local_channel, spawn_local, timer::TimerActionOnce};
use kanal::{AsyncReceiver, AsyncSender};
use lru::LruCache;
use solana_ledger::shred::{self, Shred, ShredCommonHeader, ShredFlags, ShredType};

use crate::{
    metrics::{MetricsSender, points::SlotMeasurement},
    repair::request::RepairReq,
    store::shred::SlotRaw,
    thread_manager::CancelRx,
    types::PacketInfo,
};

pub const DEFER_REPAIR_THRESHOLD: Duration = Duration::from_millis(200);
const DATA_SHREDS_PER_FEC_SET: usize = 32;

type FecMap = HashMap<u32, BTreeSet<u32>>;
type SlotMetaStore = LruCache<u64, SlotMetadata>;

pub struct SlotMetadata {
    pub slot_num: u64,
    pub fec_data_map: FecMap,
    pub fec_coding_map: FecMap,
    pub timestamp_ms: u64,
    pub completed_batches: BTreeSet<u32>,
    pub required_batches: Option<usize>,
    // highest shred index seen
    pub max_inclusive_shred: u32,
    pub shreds: Option<Vec<PacketInfo>>,
    pub timed_out: bool,
}

impl SlotMetadata {
    pub fn is_complete(&self) -> bool {
        Some(self.completed_batches.len()) == self.required_batches
    }

    fn calculate_missing_shreds_bounded(&self) -> Option<Vec<u32>> {
        let max_batch_index = self.required_batches? * DATA_SHREDS_PER_FEC_SET;
        for (batch_idx, batch_idxs) in self.fec_data_map.iter() {
            log::info!("bounded missing shreds: batch {batch_idx} has shreds {batch_idxs:?}");
        }
        log::info!(
            "bounded missing shreds: required batches = {:?}",
            self.required_batches
        );

        let required_shreds = (0..max_batch_index as u32)
            .step_by(DATA_SHREDS_PER_FEC_SET)
            .flat_map(|batch| {
                if self.completed_batches.contains(&batch) {
                    return ArrayVec::<_, DATA_SHREDS_PER_FEC_SET>::new();
                }

                let mut mask = [true; DATA_SHREDS_PER_FEC_SET];
                let Some(shreds) = self.fec_data_map.get(&batch) else {
                    return (0..DATA_SHREDS_PER_FEC_SET)
                        .map(|i| batch + i as u32)
                        .collect();
                };
                shreds
                    .iter()
                    .copied()
                    .for_each(|i| mask[i as usize - batch as usize] = false);
                mask.iter()
                    .enumerate()
                    .filter_map(|(i, missing)| missing.then_some(batch + i as u32))
                    .collect()
            });
        Some(required_shreds.collect())
    }

    fn calculate_missing_shreds_unbounded(&self) -> Vec<u32> {
        let mut max_batch = 0;
        let mut missing_shreds = self
            .fec_data_map
            .iter()
            .flat_map(|(batch_index, batch_shreds)| {
                max_batch = max_batch.max(*batch_index);
                if self.completed_batches.contains(batch_index) {
                    return ArrayVec::<_, DATA_SHREDS_PER_FEC_SET>::new();
                }
                let mut mask = [true; DATA_SHREDS_PER_FEC_SET];
                batch_shreds
                    .iter()
                    .copied()
                    .for_each(|i| mask[i as usize - *batch_index as usize] = false);
                mask.iter()
                    .enumerate()
                    .filter_map(|(i, missing)| missing.then_some(*batch_index + i as u32))
                    .collect()
            })
            .collect::<Vec<_>>();
        missing_shreds.extend((0..max_batch).step_by(DATA_SHREDS_PER_FEC_SET).flat_map(
            |batch_index| {
                if self.fec_data_map.contains_key(&batch_index) {
                    return ArrayVec::<_, DATA_SHREDS_PER_FEC_SET>::new();
                }
                (0..DATA_SHREDS_PER_FEC_SET)
                    .map(|i| batch_index + i as u32)
                    .collect()
            },
        ));

        missing_shreds
    }

    /// find required shreds to complete the slot
    /// returning None if the last shred hasn't been seen yet
    pub fn calculate_missing_shreds(&self) -> RepairReq {
        if let Some(shreds) = self.calculate_missing_shreds_bounded() {
            return RepairReq::MissingBoundedShreds {
                slot: self.slot_num,
                shreds,
            };
        }

        let holes = self.calculate_missing_shreds_unbounded();

        RepairReq::MissingUnboundedShreds {
            slot: self.slot_num,
            shreds: holes,
            max_inclusive_shred: self.max_inclusive_shred,
        }
    }
}

fn store_slot_metadata(cache: &mut SlotMetaStore, shred: Shred) {}

enum SlotMetaStoreRes {
    Complete(SlotRaw),
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

    pub async fn packet_listener_loop(
        self,
        exit: CancelRx,
        rx: AsyncReceiver<PacketInfo>,
        repair_tx: AsyncSender<RepairReq>,
        grpc_tx: AsyncSender<SlotRaw>,
        store_tx: AsyncSender<SlotRaw>,
        metrics: MetricsSender,
    ) {
        let (timer_tx, timer_rx) = local_channel::new_unbounded();
        let timer_tx = Rc::new(timer_tx);

        let shred_version = self.version;
        let this = self.clone();
        let meta_timer_tx = timer_tx.clone();
        let metadata_handler_task = spawn_local(async move {
            let timer_tx = meta_timer_tx.clone();
            while let Ok(shred) = rx.recv().await {
                let Some(common_header) = shred::layout::get_common_header_bytes(&shred)
                    .and_then(|raw_header| {
                        bincode::deserialize::<ShredCommonHeader>(raw_header).ok()
                    })
                    .filter(|hdr| hdr.version == shred_version)
                else {
                    continue;
                };

                let Some(slot) = shred::layout::get_slot(&shred) else {
                    continue;
                };
                let store_res = this.store_shred(common_header, shred);
                let timer_msg = match store_res {
                    SlotMetaStoreRes::Ignored => continue,
                    SlotMetaStoreRes::Complete(raw_slot) => {
                        _ = timer_tx.try_send(SlotTimerMsg::ShredCompletion { slot });
                        _ = store_tx.send(raw_slot.clone()).await;
                        _ = grpc_tx.send(raw_slot).await;
                        continue;
                    }
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
                        let Some(slot_meta) = self.inner.get_sync(&slot) else {
                            continue;
                        };

                        metrics.measure(SlotMeasurement::completion(slot));

                        if slot_meta.timed_out {
                            _ = repair_tx.send(RepairReq::CancelRepair { slot }).await;
                        }
                    }
                    SlotTimerMsg::ShredTimeout { slot } => {
                        timers.remove(&slot);
                        let Some(mut slot_meta) = self.inner.get_sync(&slot) else {
                            continue;
                        };
                        if slot_meta.is_complete() {
                            continue;
                        }
                        slot_meta.timed_out = true;
                        log::info!("slot {slot} has timed out, sending to repair!");

                        _ = repair_tx.send(slot_meta.calculate_missing_shreds()).await;
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
    fn store_shred(&self, hdr: ShredCommonHeader, shred: PacketInfo) -> SlotMetaStoreRes {
        let slot = hdr.slot;
        let fec_index = hdr.fec_set_index;
        let shred_index = hdr.index;

        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let (_, mut shred_entry) = self.inner.entry_sync(slot).or_put_with(|| SlotMetadata {
            slot_num: slot,
            fec_data_map: HashMap::new(),
            fec_coding_map: HashMap::new(),
            timestamp_ms,
            completed_batches: BTreeSet::new(),
            required_batches: None,
            max_inclusive_shred: 0,
            shreds: Some(Default::default()),
            timed_out: false,
        });
        let shred_meta = shred_entry.get_mut();
        if shred_meta.is_complete() {
            return SlotMetaStoreRes::Ignored;
        }

        let fec_map = match ShredType::from(hdr.shred_variant) {
            ShredType::Data => {
                let Ok(flags) = shred::layout::get_flags(&shred) else {
                    return SlotMetaStoreRes::Ignored;
                };
                if flags.contains(ShredFlags::LAST_SHRED_IN_SLOT) {
                    shred_meta.required_batches = Some(
                        (fec_index as usize + DATA_SHREDS_PER_FEC_SET) / DATA_SHREDS_PER_FEC_SET,
                    );
                }
                &mut shred_meta.fec_data_map
            }
            ShredType::Code => &mut shred_meta.fec_coding_map,
        };
        let inserted = fec_map.entry(fec_index).or_default().insert(shred_index);
        if !inserted {
            return SlotMetaStoreRes::Ignored;
        }
        shred_meta.timestamp_ms = timestamp_ms;
        shred_meta.max_inclusive_shred = shred_meta.max_inclusive_shred.max(shred_index);

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
        if let Some(s) = shred_meta.shreds.as_mut() {
            s.push(shred)
        }

        if shred_meta.is_complete() {
            let shreds = shred_entry
                .shreds
                .take()
                .expect("shred entry is none for complete slot?!");
            SlotMetaStoreRes::Complete(SlotRaw { shreds, slot })
        } else {
            SlotMetaStoreRes::Incomplete
        }
    }
}

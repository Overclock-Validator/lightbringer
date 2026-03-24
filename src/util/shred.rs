use std::collections::BTreeMap;

use solana_entry::entry::Entry;
use solana_ledger::shred::{self, ReedSolomonCache, Shred, ShredType, Shredder};

use crate::{rpc::RpcError, store::shred::ShredStore};

pub struct SlotEntries {
    pub entries: Vec<Entry>,
    pub parent_slot: u64,
}

fn recover_shreds_and_group_by_completion(
    shreds_by_fec_set_index: BTreeMap<u32, BatchMeta>,
) -> Result<impl Iterator<Item = BTreeMap<u32, Shred>>, RpcError> {
    let rs_cache = ReedSolomonCache::default();
    let mut data_shreds_partitioned_by_completion = vec![BTreeMap::<u32, Shred>::new()];
    for shred_batch in shreds_by_fec_set_index.into_values() {
        let last = data_shreds_partitioned_by_completion.last_mut().unwrap();
        if shred_batch.data_cnt < 32 {
            let recovered = shred::recover(shred_batch.shreds.clone(), &rs_cache)
                .map_err(RpcError::ShredRecovery)?;
            for shred in recovered {
                let shred = shred.map_err(RpcError::ShredRecovery)?;
                if shred.shred_type() != ShredType::Data {
                    continue;
                }
                last.insert(shred.index(), shred);
            }
        }
        last.extend(
            shred_batch
                .shreds
                .into_iter()
                .filter_map(|s| (s.shred_type() == ShredType::Data).then(|| (s.index(), s))),
        );
        if last.last_key_value().unwrap().1.data_complete() {
            data_shreds_partitioned_by_completion.push(BTreeMap::new());
        }
    }
    data_shreds_partitioned_by_completion.pop();

    Ok(data_shreds_partitioned_by_completion.into_iter())
}

pub fn deshred_to_entries<'a>(
    data_shreds: impl Iterator<Item = &'a Shred>,
) -> Result<Vec<Entry>, RpcError> {
    let deshred_payload =
        Shredder::deshred(data_shreds.map(|s| s.payload())).map_err(RpcError::Deshred)?;
    let deshred_entries: Vec<Entry> = bincode::deserialize(&deshred_payload)?;
    Ok(deshred_entries)
}

#[derive(Default)]
struct BatchMeta {
    shreds: Vec<Shred>,
    data_cnt: usize,
}

pub fn get_slot_entries_from_raw_shreds<S: AsRef<[u8]>>(
    shreds: impl IntoIterator<Item = S>,
) -> Result<SlotEntries, RpcError> {
    let mut shreds_for_slot = BTreeMap::<u32, BatchMeta>::new();
    let mut raw_shred_count = 0usize;
    let mut raw_data_shred_count = 0usize;
    let mut slot = None;

    for shred in shreds {
        let deser = Shred::new_from_serialized_shred(shred.as_ref().to_vec())
            .map_err(RpcError::ShredDeser)?;
        raw_shred_count += 1;
        if slot.is_none() {
            slot = Some(deser.slot());
        }
        let meta = shreds_for_slot.entry(deser.fec_set_index()).or_default();
        if deser.is_data() {
            meta.data_cnt += 1;
            raw_data_shred_count += 1;
        }
        meta.shreds.push(deser);
    }

    let mut entries = Vec::new();
    let mut parent_slot = None;
    let fec_set_count = shreds_for_slot.len();
    let mut completion_batch_count = 0usize;
    for data_shreds in recover_shreds_and_group_by_completion(shreds_for_slot)? {
        completion_batch_count += 1;
        if parent_slot.is_none() {
            parent_slot = data_shreds
                .values()
                .next()
                .map(|shred| shred.parent().map_err(RpcError::ShredDeser))
                .transpose()?;
        }
        let mut deshred_entries = deshred_to_entries(data_shreds.values())?;
        entries.append(&mut deshred_entries);
    }

    let resolved_parent_slot = parent_slot.unwrap_or_default();
    if resolved_parent_slot == 0 {
        log::warn!(
            "deshred reconstructed slot {} with parent_slot=0 | raw_shreds={} | raw_data_shreds={} | fec_sets={} | completion_batches={} | entries={}",
            slot.unwrap_or_default(),
            raw_shred_count,
            raw_data_shred_count,
            fec_set_count,
            completion_batch_count,
            entries.len(),
        );
    }

    Ok(SlotEntries {
        entries,
        parent_slot: resolved_parent_slot,
    })
}

pub fn get_slot_entries_from_store(
    shred_store: &ShredStore,
    slot: u64,
) -> Result<SlotEntries, RpcError> {
    let unsorted_shreds = shred_store.get_slot_shreds(slot)?;

    get_slot_entries_from_raw_shreds(unsorted_shreds)
}

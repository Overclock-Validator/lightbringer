use std::collections::BTreeMap;

use solana_entry::entry::Entry;
use solana_ledger::shred::{self, ReedSolomonCache, Shred, ShredType, Shredder};

use crate::{rpc::RpcError, store::shred::ShredStore};

pub fn recover_shreds_and_group_by_completion(
    shreds_by_fec_set_index: BTreeMap<u32, Vec<Shred>>,
) -> Result<impl Iterator<Item = BTreeMap<u32, Shred>>, RpcError> {
    let rs_cache = ReedSolomonCache::default();
    let mut data_shreds_partitioned_by_completion = vec![BTreeMap::<u32, Shred>::new()];
    for shred_batch in shreds_by_fec_set_index.into_values() {
        let recovered =
            shred::recover(shred_batch.clone(), &rs_cache).map_err(RpcError::ShredRecovery)?;
        let last = data_shreds_partitioned_by_completion.last_mut().unwrap();
        for shred in recovered {
            let shred = shred.map_err(RpcError::ShredRecovery)?;
            if shred.shred_type() != ShredType::Data {
                continue;
            }
            last.insert(shred.index(), shred);
        }
        last.extend(
            shred_batch
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

pub fn get_slot_entries_from_store(
    shred_store: &ShredStore,
    slot: u64,
) -> Result<Vec<Entry>, RpcError> {
    let unsorted_shreds = shred_store.get_slot_shreds(slot)?;

    let mut shreds_for_slot = BTreeMap::<u32, Vec<Shred>>::new();

    for shred in unsorted_shreds {
        let deser =
            Shred::new_from_serialized_shred(shred.to_vec()).map_err(RpcError::ShredDeser)?;
        shreds_for_slot
            .entry(deser.fec_set_index())
            .or_default()
            .push(deser);
    }

    let mut entries = Vec::new();
    for data_shreds in recover_shreds_and_group_by_completion(shreds_for_slot)? {
        let mut deshred_entries = deshred_to_entries(data_shreds.values())?;
        entries.append(&mut deshred_entries);
    }

    Ok(entries)
}

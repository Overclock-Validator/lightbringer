use std::{collections::BTreeMap, sync::Arc};

use anyhow::{Result, anyhow};
use solana_ledger::shred::{DATA_SHREDS_PER_FEC_BLOCK, ReedSolomonCache, Shred};

use crate::{
    types::{PacketInfo, PacketView},
    util::shred::recover_shreds,
};

#[derive(Default)]
struct FecBatch {
    shreds: Vec<Shred>,
    data_shreds: BTreeMap<u32, Shred>,
}

pub fn recover_data_shreds(shreds: &[PacketInfo]) -> Result<Vec<PacketInfo>> {
    let mut batches = BTreeMap::<u32, FecBatch>::new();

    for raw in shreds {
        let shred = Shred::new_from_serialized_shred(raw.as_slice().to_vec())
            .map_err(|e| anyhow!("invalid shred: {e:?}"))?;
        let batch = batches.entry(shred.fec_set_index()).or_default();
        if shred.is_data() {
            batch
                .data_shreds
                .entry(shred.index())
                .or_insert(shred.clone());
        }
        batch.shreds.push(shred);
    }

    let rs_cache = ReedSolomonCache::default();
    let mut recovered_data = Vec::new();
    for mut batch in batches.into_values() {
        if batch.data_shreds.len() < DATA_SHREDS_PER_FEC_BLOCK {
            let recovered = recover_shreds(batch.shreds.clone(), &rs_cache)
                .map_err(|e| anyhow!("failed to recover alpenglow data shreds: {e:?}"))?;
            for shred in recovered {
                let shred =
                    shred.map_err(|e| anyhow!("failed to recover alpenglow data shred: {e:?}"))?;
                if shred.is_data() {
                    batch.data_shreds.entry(shred.index()).or_insert(shred);
                }
            }
        }

        for shred in batch.data_shreds.into_values() {
            recovered_data.push(packet_info_from_shred(&shred)?);
        }
    }

    Ok(recovered_data)
}

fn packet_info_from_shred(shred: &Shred) -> Result<PacketInfo> {
    let mut packet = PacketView::new();
    packet
        .try_extend_from_slice(shred.payload().as_ref())
        .map_err(|_| anyhow!("recovered shred payload exceeds packet size"))?;
    Ok(Arc::new(packet))
}

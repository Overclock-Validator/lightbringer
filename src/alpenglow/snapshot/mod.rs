mod fetch;

use std::{collections::BTreeMap, io::BufReader, sync::Arc};

use anyhow::{Result, anyhow};
use solana_clock::Epoch;
use solana_runtime::{
    epoch_stakes::{BLSPubkeyToRankMap, VersionedEpochStakes},
    serde_snapshot::fields_from_stream,
};

use crate::alpenglow::snapshot::fetch::fetch_incremental_snapshot_manifest;

/// A frozen `epoch_stakes[epoch]` rank map, read out of a snapshot bank manifest.
pub struct EpochRankMap {
    pub rank_map: Arc<BLSPubkeyToRankMap>,
    pub total_stake: u64,
}

/// Source of Alpenglow rank maps: an Agave RPC node's snapshot HTTP endpoint.
///
/// A single incremental snapshot manifest carries `versioned_epoch_stakes` for several
/// epochs at once (current, next, and a few prior), so one fetch covers cold start with
/// no warmup and no reconstruction from live account state.
#[derive(Clone)]
pub struct SnapshotSource {
    rpc_http: String,
}

impl SnapshotSource {
    pub fn new(rpc_http: String) -> Self {
        Self { rpc_http }
    }

    /// Blocking: fetches a fresh incremental snapshot and reads every epoch's rank map
    /// out of its bank manifest. Downloads only the manifest (~ a few MB), never the
    /// accounts. Intended to run on a dedicated thread, not the async executor.
    pub fn fetch_epoch_rank_maps(&self) -> Result<BTreeMap<Epoch, EpochRankMap>> {
        let manifest = fetch_incremental_snapshot_manifest(&self.rpc_http)?;
        let mut reader = BufReader::new(&manifest[..]);
        let fields =
            fields_from_stream(&mut reader).map_err(|e| anyhow!("failed to deserialize snapshot manifest: {e}"))?;
        let bank_fields = fields.0;

        let mut rank_maps = BTreeMap::new();
        for (epoch, deserializable) in bank_fields.versioned_epoch_stakes {
            let epoch_stakes: VersionedEpochStakes = deserializable.into();
            rank_maps.insert(
                epoch,
                EpochRankMap {
                    rank_map: epoch_stakes.bls_pubkey_to_rank_map().clone(),
                    total_stake: epoch_stakes.total_stake(),
                },
            );
        }

        if rank_maps.is_empty() {
            return Err(anyhow!(
                "snapshot manifest from {} carried no versioned epoch stakes",
                self.rpc_http
            ));
        }

        Ok(rank_maps)
    }
}

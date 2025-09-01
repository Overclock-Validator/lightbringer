use std::{collections::BTreeMap, net::SocketAddr};

use base64::{Engine, prelude::BASE64_STANDARD};
use ohkami::{IntoResponse, Json, Ohkami, Path, Response, Route, fang::Context};
use solana_entry::entry::Entry;
use solana_ledger::shred::{self, ReedSolomonCache, Shred, ShredType, Shredder};
use thiserror::Error;

use crate::store::shred::ShredStore;

#[derive(Error, Debug)]
pub enum RpcError {
    #[error("database error: {0}")]
    Fjall(#[from] fjall::Error),
    #[error("failed to deserialize shreds for slot: {0}")]
    ShredDeser(solana_ledger::shred::Error),
    #[error("failed to recover data shreds for slot: {0}")]
    ShredRecovery(solana_ledger::shred::Error),
    #[error("failed to deshred data shreds for slot: {0}")]
    Deshred(solana_ledger::shred::Error),
    #[error("failed to deserialize entries: {0}")]
    InvalidEntries(#[from] bincode::Error),
}

impl IntoResponse for RpcError {
    fn into_response(self) -> Response {
        match self {
            Self::Fjall(_)
            | Self::ShredDeser(_)
            | Self::ShredRecovery(_)
            | Self::Deshred(_)
            | Self::InvalidEntries(_) => {
                Response::InternalServerError().with_text(self.to_string())
            }
        }
    }
}

pub struct DebugRpcInit {
    pub listen_addr: SocketAddr,
    pub shred_store: ShredStore,
}

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

async fn get_slot(
    shred_store: Context<'_, ShredStore>,
    Path(slot): Path<u64>,
) -> Result<Json<Vec<Entry>>, RpcError> {
    let shred_store = shred_store.0.clone();

    let exec = glommio::executor();
    let unsorted_shreds = exec
        .spawn_blocking(move || shred_store.get_slot_shreds(slot))
        .await?;
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

    Ok(Json(entries))
}

async fn get_stored_shreds_raw(
    shred_store: Context<'_, ShredStore>,
    Path(slot): Path<u64>,
) -> Result<Json<Vec<String>>, RpcError> {
    let shred_store = shred_store.0.clone();
    let shreds = shred_store
        .get_slot_shreds(slot)?
        .into_iter()
        .map(|s| BASE64_STANDARD.encode(s))
        .collect::<Vec<_>>();
    Ok(Json(shreds))
}

pub async fn debug_rpc_listener(init: DebugRpcInit) {
    Ohkami::new((
        Context::new(init.shred_store),
        "/slot_entries/:slot".GET(get_slot),
        "/stored_shreds/:slot".GET(get_stored_shreds_raw),
    ))
    .howl(init.listen_addr)
    .await
}

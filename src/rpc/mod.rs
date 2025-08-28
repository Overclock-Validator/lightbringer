use std::{collections::BTreeMap, net::SocketAddr};

use ohkami::{IntoResponse, Json, Ohkami, Path, Response, Route, fang::Context};
use solana_entry::entry::Entry;
use solana_ledger::shred::{self, Shred, ShredType, Shredder};
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

pub fn sort_shreds_by_type(shreds: Vec<Shred>) -> (Vec<Shred>, Vec<Shred>) {
    let mut data_shreds: Vec<Shred> = vec![];
    let mut coding_shreds: Vec<Shred> = vec![];

    for s in shreds {
        if s.shred_type() == ShredType::Data {
            data_shreds.push(s);
        } else {
            coding_shreds.push(s);
        }
    }

    data_shreds.sort_by_key(|x| x.index());
    coding_shreds.sort_by_key(|x| x.index());

    (data_shreds, coding_shreds)
}

pub fn process_shreds_with_recovery(
    shreds: Vec<Shred>,
) -> Result<(Vec<Shred>, Vec<Shred>), RpcError> {
    // Perform recovery on shreds
    let recovery: Vec<Shred> = shred::recover(shreds.clone(), &Default::default())
        .map_err(RpcError::ShredRecovery)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(RpcError::ShredRecovery)?;

    // Combine original and recovered shreds
    let all_shreds: Vec<Shred> = [shreds, recovery].concat();

    // Sort into data and coding shreds
    Ok(sort_shreds_by_type(all_shreds))
}

pub fn deshred_to_entries(data_shreds: &[Shred]) -> Result<Vec<Entry>, RpcError> {
    let shreds = data_shreds.iter().map(Shred::payload);
    let deshred_payload = Shredder::deshred(shreds).map_err(RpcError::Deshred)?;
    let deshred_entries: Vec<Entry> = bincode::deserialize(&deshred_payload)?;
    Ok(deshred_entries)
}

async fn get_slot(
    shred_store: Context<'_, ShredStore>,
    Path(slot): Path<u64>,
) -> Result<Json<Vec<Entry>>, RpcError> {
    let shred_store = shred_store.0.clone();
    // TODO: this blocks the current thread, we should probably implement a separate thread for fjall
    // spawn_blocking can't be used with ohkami right now :|
    let unsorted_shreds = shred_store.get_slot_shreds(slot)?;
    let mut shreds_for_slot = BTreeMap::<u32, Vec<Shred>>::new();
    log::info!("found {} shreds for slot", unsorted_shreds.len());

    for shred in unsorted_shreds {
        let deser =
            Shred::new_from_serialized_shred(shred.to_vec()).map_err(RpcError::ShredDeser)?;
        shreds_for_slot
            .entry(deser.fec_set_index())
            .or_default()
            .push(deser);
    }
    let mut entries = Vec::<Entry>::new();
    for (batch_index, shred_list) in shreds_for_slot {
        let coding = shred_list.iter().find_map(|s| match s {
            Shred::ShredCode(c) => Some(c.coding_header()),
            Shred::ShredData(_) => None,
        });
        log::info!(
            "decoding {batch_index}, slot: {slot}, shreds_cnt {}, header: {coding:?}",
            shred_list.len()
        );
        let (data_shreds, _coding_shreds) = process_shreds_with_recovery(shred_list)?;
        log::info!(
            "deshreding {batch_index}, slot: {slot}, shreds {:?}",
            data_shreds
        );
        let mut new_entries = deshred_to_entries(&data_shreds)?;
        entries.append(&mut new_entries);
    }

    Ok(Json(entries))
}

pub async fn debug_rpc_listener(init: DebugRpcInit) {
    Ohkami::new((
        Context::new(init.shred_store),
        "/slot_entries/:slot".GET(get_slot),
    ))
    .howl(init.listen_addr)
    .await
}

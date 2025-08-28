use std::net::SocketAddr;

use ohkami::{IntoResponse, Json, Ohkami, Path, Response, Route, fang::Context};
use solana_entry::entry::Entry;
use solana_ledger::shred::{Shred, Shredder};
use thiserror::Error;

use crate::store::shred::ShredStore;

#[derive(Error, Debug)]
pub enum RpcError {
    #[error("database error: {0}")]
    Fjall(#[from] fjall::Error),
    #[error("invalid shreds for slot: {0}")]
    InvalidShred(#[from] solana_ledger::shred::Error),
    #[error("failed to deserialize entries: {0}")]
    InvalidEntries(#[from] bincode::Error),
}

impl IntoResponse for RpcError {
    fn into_response(self) -> Response {
        match self {
            Self::Fjall(_) => Response::InternalServerError().with_text(self.to_string()),
            Self::InvalidShred(_) => Response::InternalServerError().with_text(self.to_string()),
            Self::InvalidEntries(_) => Response::InternalServerError().with_text(self.to_string()),
        }
    }
}

pub struct DebugRpcInit {
    pub listen_addr: SocketAddr,
    pub shred_store: ShredStore,
}

async fn get_slot(
    shred_store: Context<'_, ShredStore>,
    Path(slot): Path<u64>,
) -> Result<Json<Vec<Entry>>, RpcError> {
    let shred_store = shred_store.0.clone();
    // TODO: this blocks the current thread, we should probably implement a separate thread for fjall
    // spawn_blocking can't be used with ohkami right now :|
    let shreds = shred_store
        .get_slot_shreds(slot)?
        .into_iter()
        .map(|raw_shred| Shred::new_from_serialized_shred(raw_shred.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    let recovered = Shredder::try_recovery(shreds, &Default::default())?;

    let raw_entries = Shredder::deshred(recovered.iter().map(|s| s.payload()))?;
    let entries: Vec<Entry> = bincode::deserialize(&raw_entries)?;

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

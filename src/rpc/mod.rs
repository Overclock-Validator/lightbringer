use std::{borrow::Cow, convert::Infallible, fmt, net::SocketAddr};

use base64::{Engine, prelude::BASE64_STANDARD};
use ohkami::{
    IntoResponse, Json, Ohkami, Path, Response, Route, claw::content::IntoContent, fang::Context,
};
use thiserror::Error;

use crate::{grpc_slot_stream, store::shred::ShredStore, util::shred::get_slot_entries_from_store};

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

struct ProtoBufResponse<T>(T);

impl<T: prost::Message> IntoContent for ProtoBufResponse<T> {
    const CONTENT_TYPE: &'static str = "application/x-protobuf";

    fn into_content(self) -> Result<Cow<'static, [u8]>, impl fmt::Display> {
        Ok::<_, Infallible>(Cow::Owned(self.0.encode_to_vec()))
    }
}

pub struct DebugRpcInit {
    pub listen_addr: SocketAddr,
    pub shred_store: ShredStore,
}

async fn get_slot(
    shred_store: Context<'_, ShredStore>,
    Path(slot): Path<u64>,
) -> Result<ProtoBufResponse<grpc_slot_stream::slot_stream_pb::SlotResponse>, RpcError> {
    let shred_store = shred_store.0.clone();
    let exec = glommio::executor();
    let entries = exec
        .spawn_blocking(move || get_slot_entries_from_store(&shred_store, slot))
        .await?;

    Ok(ProtoBufResponse(
        grpc_slot_stream::slot_stream_pb::SlotResponse {
            entries: entries.into_iter().map(|e| e.into()).collect(),
            slot,
        },
    ))
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

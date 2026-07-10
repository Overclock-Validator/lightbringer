use isahc::{AsyncReadResponseExt, HttpClient, Request};
use jsonrpc_types::{MethodCall, Params};
use serde::de::DeserializeOwned;
use solana_commitment_config::CommitmentConfig;
use solana_epoch_info::EpochInfo;
use solana_epoch_schedule::EpochSchedule;
use solana_rpc_client_types::{
    config::{RpcBlockConfig, RpcContextConfig, RpcLeaderScheduleConfig},
    request::RpcRequest,
    response::RpcLeaderSchedule,
};
use solana_sdk::clock::Slot;
use solana_transaction_status_client_types::{EncodedConfirmedBlock, TransactionDetails};
use thiserror::Error;

const MAINNET_RPC_NODE: &str = "https://api.mainnet-beta.solana.com";

#[derive(Debug, Error)]
pub enum SolanaRpcError {
    #[error("invalid http request: {0}")]
    Http(#[from] isahc::http::Error),
    #[error("server error: {0}")]
    JsonRpc(#[from] jsonrpc_types::Error),
    #[error("http client error: {0}")]
    Isahc(#[from] isahc::Error),
    #[error("serde error: {0}")]
    SerDe(#[from] serde_json::Error),
    #[error("hash decode error: {0}")]
    Bs58(#[from] bs58::decode::Error),
}

#[derive(Clone)]
pub struct SolanaRpcClient {
    client: HttpClient,
    rpc_url: String,
}

impl Default for SolanaRpcClient {
    fn default() -> Self {
        let client = HttpClient::new().unwrap();
        Self {
            client,
            rpc_url: MAINNET_RPC_NODE.into(),
        }
    }
}

impl SolanaRpcClient {
    pub fn new(rpc_url: String) -> Self {
        let client = HttpClient::new().unwrap();
        Self { client, rpc_url }
    }

    async fn send<R: DeserializeOwned + Unpin>(
        &self,
        req: RpcRequest,
        params: jsonrpc_types::Params,
    ) -> Result<R, SolanaRpcError> {
        let req = MethodCall::new(req.to_string(), Some(params), 1.into());
        let http_req = Request::post(&self.rpc_url)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&req).unwrap())?;
        let res: jsonrpc_types::Output<R> = self.client.send_async(http_req).await?.json().await?;

        match res {
            jsonrpc_types::Output::Success(s) => Ok(s.result),
            jsonrpc_types::Output::Failure(f) => Err(f.error.into()),
        }
    }

    pub async fn get_leader_schedule(
        &self,
        slot: Option<u64>,
    ) -> Result<Option<RpcLeaderSchedule>, SolanaRpcError> {
        let commitment_config = RpcLeaderScheduleConfig {
            commitment: Some(CommitmentConfig::processed()),
            ..Default::default()
        };
        let commitment_config_val = serde_json::to_value(commitment_config).unwrap();
        self.send(
            RpcRequest::GetLeaderSchedule,
            Params::Array(vec![slot.into(), commitment_config_val]),
        )
        .await
    }

    pub async fn get_blockhash(&self, slot: u64) -> Result<[u8; 32], SolanaRpcError> {
        let commitment_config = RpcBlockConfig {
            commitment: Some(CommitmentConfig::confirmed()),
            transaction_details: Some(TransactionDetails::None),
            ..Default::default()
        };
        let commitment_config_val = serde_json::to_value(commitment_config).unwrap();
        let res: EncodedConfirmedBlock = self
            .send(
                RpcRequest::GetBlock,
                Params::Array(vec![slot.into(), commitment_config_val]),
            )
            .await?;
        let mut block_hash = [0u8; 32];
        bs58::decode(res.blockhash).onto(&mut block_hash)?;
        Ok(block_hash)
    }

    pub async fn get_blocks(&self, start_slot: u64) -> Result<Vec<Slot>, SolanaRpcError> {
        let commitment_config = RpcContextConfig {
            commitment: Some(CommitmentConfig::confirmed()),
            min_context_slot: None,
        };
        let commitment_config_val = serde_json::to_value(commitment_config).unwrap();
        self.send(
            RpcRequest::GetBlock,
            Params::Array(vec![start_slot.into(), commitment_config_val]),
        )
        .await
    }

    pub async fn get_epoch_info(
        &self,
        slot: Option<u64>,
    ) -> Result<Option<EpochInfo>, SolanaRpcError> {
        let commitment_config = RpcContextConfig {
            commitment: Some(CommitmentConfig::processed()),
            min_context_slot: slot,
        };
        let commitment_config_val = serde_json::to_value(commitment_config).unwrap();
        self.send(
            RpcRequest::GetEpochInfo,
            Params::Array(vec![commitment_config_val]),
        )
        .await
    }

    pub async fn get_epoch_schedule(&self) -> Result<EpochSchedule, SolanaRpcError> {
        self.send(RpcRequest::GetEpochSchedule, Params::Array(vec![]))
            .await
    }

    /// Debug RPC on a patched Alpenglow node only; the oracle used to validate that a
    /// snapshot-derived rank map matches the node's own `epoch_stakes_from_slot`. Never call
    /// this in production - see `crate::alpenglow::snapshot`.
    #[cfg(test)]
    pub async fn get_alpenglow_rank_map(
        &self,
        slot: u64,
    ) -> Result<solana_rpc_client_types::response::RpcAlpenglowRankMap, SolanaRpcError> {
        self.send(RpcRequest::GetAlpenglowRankMap, Params::Array(vec![slot.into()]))
            .await
    }

    /// Test-only: production gets the cluster's shred version for free from the gossip
    /// service it already runs. Tests don't run gossip, so this looks it up via RPC instead
    /// (every node in a cluster reports the same shred version).
    #[cfg(test)]
    pub async fn get_shred_version(&self) -> Result<u16, SolanaRpcError> {
        let identity: solana_rpc_client_types::response::RpcIdentity =
            self.send(RpcRequest::GetIdentity, Params::Array(vec![])).await?;
        let nodes: Vec<solana_rpc_client_types::response::RpcContactInfo> =
            self.send(RpcRequest::GetClusterNodes, Params::Array(vec![])).await?;
        nodes
            .into_iter()
            .find(|node| node.pubkey == identity.identity)
            .and_then(|node| node.shred_version)
            .ok_or_else(|| {
                jsonrpc_types::Error::invalid_params("node did not report a shred version").into()
            })
    }
}

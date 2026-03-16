use anyhow::anyhow;
use isahc::{AsyncReadResponseExt, HttpClient, Request};
use jsonrpc_types::{MethodCall, Params};
use serde::de::DeserializeOwned;
use solana_commitment_config::CommitmentConfig;
use solana_epoch_info::EpochInfo;
use solana_rpc_client_types::{
    config::{RpcBlockConfig, RpcContextConfig, RpcLeaderScheduleConfig},
    request::RpcRequest,
    response::RpcLeaderSchedule,
};
use solana_sdk::clock::Slot;
use solana_transaction_status_client_types::{EncodedConfirmedBlock, TransactionDetails};

const MAINNET_RPC_NODE: &str = "https://api.mainnet-beta.solana.com";

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
    ) -> anyhow::Result<R> {
        let req = MethodCall::new(req.to_string(), Some(params), 1.into());
        let http_req = Request::post(&self.rpc_url)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&req)?)?;
        let res: jsonrpc_types::Output<R> = self.client.send_async(http_req).await?.json().await?;

        match res {
            jsonrpc_types::Output::Success(s) => Ok(s.result),
            jsonrpc_types::Output::Failure(f) => Err(anyhow!("RPC Error: {}", f.error)),
        }
    }

    pub async fn get_leader_schedule(
        &self,
        slot: Option<u64>,
    ) -> anyhow::Result<Option<RpcLeaderSchedule>> {
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

    pub async fn get_blockhash(&self, slot: u64) -> anyhow::Result<[u8; 32]> {
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

    pub async fn get_blocks(&self, start_slot: u64) -> anyhow::Result<Vec<Slot>> {
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

    pub async fn get_epoch_info(&self, slot: Option<u64>) -> anyhow::Result<Option<EpochInfo>> {
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
}

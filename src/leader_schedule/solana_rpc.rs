use anyhow::anyhow;
use isahc::{AsyncReadResponseExt, HttpClient, Request};
use jsonrpc_types::{MethodCall, Params};
use serde::de::DeserializeOwned;
use solana_epoch_info::EpochInfo;
use solana_rpc_client_types::{
    config::{RpcContextConfig, RpcLeaderScheduleConfig},
    request::RpcRequest,
    response::RpcLeaderSchedule,
};
use solana_sdk::commitment_config::CommitmentConfig;

const MAINNET_RPC_NODE: &str = "https://api.mainnet-beta.solana.com";

#[derive(Clone)]
pub struct SolanaRpcClient(HttpClient);

impl Default for SolanaRpcClient {
    fn default() -> Self {
        let client = HttpClient::new().unwrap();
        Self(client)
    }
}

impl SolanaRpcClient {
    async fn send<R: DeserializeOwned + Unpin>(
        &self,
        req: RpcRequest,
        params: jsonrpc_types::Params,
    ) -> anyhow::Result<R> {
        let req = MethodCall::new(req.to_string(), Some(params), 1.into());
        let http_req = Request::post(MAINNET_RPC_NODE)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&req)?)?;
        let res: jsonrpc_types::Output<R> = self.0.send_async(http_req).await?.json().await?;

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

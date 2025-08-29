use anyhow::anyhow;
use isahc::{AsyncReadResponseExt, HttpClient, Request};
use jsonrpc_types::{MethodCall, Params};
use serde::de::DeserializeOwned;
use solana_epoch_info::EpochInfo;
use solana_rpc_client_types::{request::RpcRequest, response::RpcLeaderSchedule};

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

    pub async fn get_leader_schedule(&self) -> anyhow::Result<Option<RpcLeaderSchedule>> {
        self.send(RpcRequest::GetLeaderSchedule, Params::Array(vec![]))
            .await
    }

    pub async fn get_epoch_info(&self) -> anyhow::Result<Option<EpochInfo>> {
        self.send(RpcRequest::GetEpochInfo, Params::Array(vec![]))
            .await
    }
}

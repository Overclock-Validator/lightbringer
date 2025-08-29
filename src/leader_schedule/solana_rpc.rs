use anyhow::anyhow;
use isahc::{AsyncReadResponseExt, HttpClient, Request};
use jsonrpc_types::{MethodCall, Params};
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
    pub async fn get_leader_schedule(&self) -> Result<Option<RpcLeaderSchedule>, anyhow::Error> {
        let req = MethodCall::new(
            RpcRequest::GetLeaderSchedule.to_string(),
            Some(Params::Array(vec![])),
            1.into(),
        );
        let http_req = Request::post(MAINNET_RPC_NODE)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&req)?)?;
        let res: jsonrpc_types::Output<Option<RpcLeaderSchedule>> =
            self.0.send_async(http_req).await?.json().await?;

        match res {
            jsonrpc_types::Output::Success(s) => Ok(s.result),
            jsonrpc_types::Output::Failure(f) => Err(anyhow!("RPC Error: {}", f.error)),
        }
    }
}

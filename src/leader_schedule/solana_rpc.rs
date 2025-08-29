use isahc::{AsyncReadResponseExt, HttpClient};
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
        let req =
            RpcRequest::GetLeaderSchedule.build_request_json(1, serde_json::Value::Array(vec![]));
        Ok(self
            .0
            .post_async(MAINNET_RPC_NODE, serde_json::to_vec(&req)?)
            .await?
            .json()
            .await?)
    }
}

mod glue;
mod rpc_types;

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};
use futures::FutureExt;
use glommio::{spawn_local, timer::timeout};
use http::Uri;
use jsonrpc_types::{Id, MethodCall, SubscriptionNotification};
use uuid::Uuid;
use wtx::{
    rng::Xorshift64,
    web_socket::{
        FrameVector, OpCode, WebSocket, WebSocketBuffer, WebSocketConnector, WebSocketPayloadOrigin,
    },
};

use crate::{
    block_conf::{
        glue::MaybeTlsStream,
        rpc_types::{BlockSubscribeParams, MinBlockNotif},
    },
    solana_rpc::SolanaRpcClient,
};

pub struct BlockConfUpdate {
    pub slot: u64,
    pub block_hash: [u8; 32],
}

type Ws = WebSocket<(), Xorshift64, MaybeTlsStream, WebSocketBuffer, true>;

pub struct BlockConfStream {
    rpc: SolanaRpcClient,
    ws: Option<Ws>,
    ws_url: Uri,
    subscription_id: u64,
    last_ping: Instant,
    catchup_slots: VecDeque<BlockConfUpdate>,
    last_slot: Option<u64>,
}

impl BlockConfStream {
    async fn subscribe(ws_url: &Uri) -> Result<(Ws, u64, Instant)> {
        let is_tls = ws_url
            .scheme_str()
            .ok_or_else(|| anyhow!("No scheme in ws_url"))?
            == "wss";
        let host = ws_url.host().ok_or_else(|| anyhow!("No host in ws_url"))?;
        let port = ws_url.port_u16().unwrap_or(if is_tls { 443 } else { 80 });

        let wtx_stream = MaybeTlsStream::new(is_tls, host, port).await?;
        let mut ws = WebSocketConnector::default()
            .connect(wtx_stream, &wtx::misc::Uri::new(&ws_url.to_string()))
            .await?;

        // the ping frame is necessary :|
        ws.write_frame(&mut FrameVector::new_fin(OpCode::Ping, Vec::new().into()))
            .await?;
        let last_ping = Instant::now();

        let sub_req_id = Id::Str(Uuid::new_v4().into());
        let mut frame_buffer = Vec::new().into();
        while let Ok(frame) = ws
            .read_frame(&mut frame_buffer, WebSocketPayloadOrigin::Adaptive)
            .await
        {
            match frame.op_code() {
                OpCode::Binary | OpCode::Text => {
                    let Ok(res) =
                        serde_json::from_slice::<jsonrpc_types::Success<u64>>(frame.payload())
                    else {
                        continue;
                    };
                    if res.id != sub_req_id {
                        continue;
                    }
                    return Ok((ws, res.result, last_ping));
                }
                OpCode::Pong => {
                    let req = MethodCall::new(
                        "blockSubscribe",
                        Some(jsonrpc_types::Params::Array(vec![
                            serde_json::Value::from("all"),
                            serde_json::to_value(BlockSubscribeParams::default()).unwrap(),
                        ])),
                        sub_req_id.clone(),
                    );
                    let req_ser = serde_json::to_vec(&req).unwrap();
                    ws.write_frame(&mut FrameVector::new_fin(OpCode::Text, req_ser.into()))
                        .await?;
                }
                _ => (),
            }
        }

        Err(anyhow!("Failed to subscribe to block confirmations"))
    }

    pub async fn new(rpc: SolanaRpcClient, ws_url: Uri) -> Result<Self> {
        let (ws, subscription_id, last_ping) = Self::subscribe(&ws_url).await?;
        Ok(Self {
            rpc,
            ws: Some(ws),
            ws_url,
            subscription_id,
            last_ping,
            catchup_slots: VecDeque::new(),
            last_slot: None,
        })
    }

    async fn mark_for_resubscribe(&mut self) -> Result<()> {
        self.ws = None;
        let Some(last_slot) = self.last_slot else {
            return Ok(());
        };

        let catchup_blocks = self.rpc.get_blocks(last_slot).await?;
        self.catchup_slots = VecDeque::with_capacity(catchup_blocks.len());
        for slot in catchup_blocks.into_iter().skip(1) {
            self.catchup_slots.push_back(BlockConfUpdate {
                slot,
                block_hash: self.rpc.get_blockhash(slot).await?,
            });
        }

        Ok(())
    }

    async fn next_from_ws(&mut self) -> Result<BlockConfUpdate> {
        let mut frame_buffer = Vec::new().into();
        let ws = if let Some(ws) = self.ws.as_mut() {
            ws
        } else {
            let (ws, subscription_id, last_ping) = Self::subscribe(&self.ws_url).await?;
            self.ws = Some(ws);
            self.subscription_id = subscription_id;
            self.last_ping = last_ping;
            self.ws.as_mut().unwrap()
        };

        loop {
            if self.last_ping.elapsed() >= Duration::from_secs(50) {
                ws.write_frame(&mut FrameVector::new_fin(OpCode::Ping, Vec::new().into()))
                    .await?;
                self.last_ping = Instant::now();
            }

            let frame = ws
                .read_frame(&mut frame_buffer, WebSocketPayloadOrigin::Consistent)
                .await?;
            let payload = match frame.op_code() {
                OpCode::Binary | OpCode::Text => frame.payload(),
                _ => continue,
            };
            let Ok(notif) =
                serde_json::from_slice::<SubscriptionNotification<MinBlockNotif>>(payload)
            else {
                continue;
            };
            if notif.method != "blockNotification"
                || notif.params.subscription != Id::Num(self.subscription_id)
            {
                continue;
            }

            let info = notif.params.result.value;
            let mut block_hash = [0u8; 32];
            if bs58::decode(&info.block.blockhash)
                .onto(&mut block_hash)
                .is_err()
            {
                continue;
            }
            return Ok(BlockConfUpdate {
                slot: info.slot,
                block_hash,
            });
        }
    }

    async fn next_inner(&mut self) -> Result<BlockConfUpdate> {
        loop {
            if let Some(update) = self.catchup_slots.pop_front() {
                return Ok(update);
            }
            match timeout(Duration::from_secs(5), self.next_from_ws().map(Ok)).await {
                Ok(Ok(update)) => {
                    if self.last_slot.unwrap_or_default() < update.slot {
                        return Ok(update);
                    }
                }
                Ok(Err(e)) => {
                    log::warn!("block conf ws error: {e}, resubscribing...");
                    self.mark_for_resubscribe().await?;
                }
                Err(_) => {
                    log::warn!("block conf ws timeout, resubscribing...");
                    self.mark_for_resubscribe().await?;
                }
            }
        }
    }

    pub async fn next(&mut self) -> Result<BlockConfUpdate> {
        let update = self.next_inner().await?;
        self.last_slot = Some(update.slot);
        Ok(update)
    }
}

impl Drop for BlockConfStream {
    fn drop(&mut self) {
        let mut ws = self.ws.take().expect("drop called twice?!");
        spawn_local(async move {
            _ = ws
                .write_frame(&mut FrameVector::new_fin(OpCode::Close, Vec::new().into()))
                .await;
        })
        .detach();
    }
}

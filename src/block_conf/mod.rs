mod glue;
mod rpc_types;

use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use glommio::spawn_local;
use http::Uri;
use jsonrpc_types::{Id, MethodCall, SubscriptionNotification};
use uuid::Uuid;
use wtx::{
    rng::Xorshift64,
    web_socket::{
        FrameVector, OpCode, WebSocket, WebSocketBuffer, WebSocketConnector, WebSocketPayloadOrigin,
    },
};

use crate::block_conf::{
    glue::MaybeTlsStream,
    rpc_types::{BlockSubscribeParams, MinBlockNotif},
};

const BLOCK_CONF_PING_INTERVAL: Duration = Duration::from_secs(50);
const BLOCK_CONF_RECONNECT_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const BLOCK_CONF_RECONNECT_MAX_BACKOFF: Duration = Duration::from_secs(30);

pub struct BlockConfUpdate {
    pub slot: u64,
    pub block_hash: [u8; 32],
}

pub struct BlockConfStream {
    ws_url: Uri,
    ws: Option<WebSocket<(), Xorshift64, MaybeTlsStream, WebSocketBuffer, true>>,
    subscription_id: u64,
    last_ping: Instant,
}

impl BlockConfStream {
    async fn connect(
        ws_url: &Uri,
    ) -> Result<(
        WebSocket<(), Xorshift64, MaybeTlsStream, WebSocketBuffer, true>,
        u64,
        Instant,
    )> {
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

    pub async fn new(ws_url: Uri) -> Result<Self> {
        let (ws, subscription_id, last_ping) = Self::connect(&ws_url).await?;
        Ok(Self {
            ws_url,
            ws: Some(ws),
            subscription_id,
            last_ping,
        })
    }

    async fn reconnect_with_backoff(&mut self, reason: &str) -> Result<()> {
        let mut backoff = BLOCK_CONF_RECONNECT_INITIAL_BACKOFF;

        loop {
            log::warn!(
                "block confirmation websocket disconnected ({reason}); reconnecting to {} in {:?}",
                self.ws_url,
                backoff
            );
            glommio::timer::sleep(backoff).await;

            match Self::connect(&self.ws_url).await {
                Ok((ws, subscription_id, last_ping)) => {
                    self.ws = Some(ws);
                    self.subscription_id = subscription_id;
                    self.last_ping = last_ping;
                    log::info!(
                        "reconnected block confirmation websocket to {} with subscription {}",
                        self.ws_url,
                        self.subscription_id
                    );
                    return Ok(());
                }
                Err(err) => {
                    log::warn!(
                        "failed to reconnect block confirmation websocket to {}: {err}",
                        self.ws_url
                    );
                    backoff = std::cmp::min(backoff * 2, BLOCK_CONF_RECONNECT_MAX_BACKOFF);
                }
            }
        }
    }

    pub async fn next(&mut self) -> Result<BlockConfUpdate> {
        let mut frame_buffer = Vec::new().into();

        loop {
            enum NextAction {
                Continue,
                Reconnect(String),
                Update(BlockConfUpdate),
            }

            let action = {
                let ws = self.ws.as_mut().expect("websocket accessed after drop?!");
                if self.last_ping.elapsed() >= BLOCK_CONF_PING_INTERVAL {
                    if let Err(err) = ws
                        .write_frame(&mut FrameVector::new_fin(OpCode::Ping, Vec::new().into()))
                        .await
                    {
                        NextAction::Reconnect(format!("failed to send ping: {err}"))
                    } else {
                        self.last_ping = Instant::now();
                        match ws
                            .read_frame(&mut frame_buffer, WebSocketPayloadOrigin::Consistent)
                            .await
                        {
                            Ok(frame) => match frame.op_code() {
                                OpCode::Binary | OpCode::Text => {
                                    let payload = frame.payload();
                                    match serde_json::from_slice::<
                                        SubscriptionNotification<MinBlockNotif>,
                                    >(payload)
                                    {
                                        Ok(notif) => {
                                            if notif.method != "blockNotification"
                                                || notif.params.subscription
                                                    != Id::Num(self.subscription_id)
                                            {
                                                NextAction::Continue
                                            } else {
                                                let info = notif.params.result.value;
                                                let mut block_hash = [0u8; 32];
                                                if bs58::decode(&info.block.blockhash)
                                                    .onto(&mut block_hash)
                                                    .is_err()
                                                {
                                                    NextAction::Continue
                                                } else {
                                                    NextAction::Update(BlockConfUpdate {
                                                        slot: info.slot,
                                                        block_hash,
                                                    })
                                                }
                                            }
                                        }
                                        Err(_) => NextAction::Continue,
                                    }
                                }
                                OpCode::Close => {
                                    NextAction::Reconnect("server sent close frame".to_string())
                                }
                                _ => NextAction::Continue,
                            },
                            Err(err) => NextAction::Reconnect(format!(
                                "failed to read confirmation frame: {err}"
                            )),
                        }
                    }
                } else {
                    match ws
                        .read_frame(&mut frame_buffer, WebSocketPayloadOrigin::Consistent)
                        .await
                    {
                        Ok(frame) => match frame.op_code() {
                            OpCode::Binary | OpCode::Text => {
                                let payload = frame.payload();
                                match serde_json::from_slice::<
                                    SubscriptionNotification<MinBlockNotif>,
                                >(payload)
                                {
                                    Ok(notif) => {
                                        if notif.method != "blockNotification"
                                            || notif.params.subscription
                                                != Id::Num(self.subscription_id)
                                        {
                                            NextAction::Continue
                                        } else {
                                            let info = notif.params.result.value;
                                            let mut block_hash = [0u8; 32];
                                            if bs58::decode(&info.block.blockhash)
                                                .onto(&mut block_hash)
                                                .is_err()
                                            {
                                                NextAction::Continue
                                            } else {
                                                NextAction::Update(BlockConfUpdate {
                                                    slot: info.slot,
                                                    block_hash,
                                                })
                                            }
                                        }
                                    }
                                    Err(_) => NextAction::Continue,
                                }
                            }
                            OpCode::Close => {
                                NextAction::Reconnect("server sent close frame".to_string())
                            }
                            _ => NextAction::Continue,
                        },
                        Err(err) => NextAction::Reconnect(format!(
                            "failed to read confirmation frame: {err}"
                        )),
                    }
                }
            };

            match action {
                NextAction::Continue => continue,
                NextAction::Reconnect(reason) => {
                    self.ws = None;
                    self.reconnect_with_backoff(&reason).await?;
                    continue;
                }
                NextAction::Update(update) => return Ok(update),
            }
        }
    }
}

impl Drop for BlockConfStream {
    fn drop(&mut self) {
        if let Some(mut ws) = self.ws.take() {
            spawn_local(async move {
                _ = ws
                    .write_frame(&mut FrameVector::new_fin(OpCode::Close, Vec::new().into()))
                    .await;
            })
            .detach();
        }
    }
}

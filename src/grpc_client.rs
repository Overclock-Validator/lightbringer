use solana_entry::entry::Entry;
use tokio::runtime;
use tokio_stream::StreamExt;
use tonic::{Request, transport::Channel};

use crate::pb::{SlotStreamRequest, slot_stream_client::SlotStreamClient};

mod pb {
    tonic::include_proto!("slot_stream");
}

async fn async_main() -> anyhow::Result<()> {
    let channel = Channel::from_static("http://127.0.0.1:3001")
        .connect()
        .await?;
    let mut client = SlotStreamClient::new(channel);
    let req = Request::new(SlotStreamRequest {});

    let mut stream = client.stream_slots(req).await?.into_inner();

    while let Some(resp) = stream.next().await {
        match resp {
            Ok(resp) => {
                let raw_entries = resp.data;
                let Ok(entries) = serde_json::from_str::<Vec<Entry>>(&raw_entries) else {
                    log::warn!("received invalid entries {raw_entries}");
                    continue;
                };
                let txn_count = entries.iter().fold(0usize, |txn_count, entry| {
                    txn_count + entry.transactions.len()
                });
                log::info!("received slot {}, transactions: {txn_count}", resp.slot);
            }
            Err(e) => {
                log::error!("stream error {e}");
                break;
            }
        }
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    simple_logger::init_with_level(log::Level::Info)?;
    let rt = runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async_main())
}

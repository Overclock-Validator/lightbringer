use glommio::{executor, spawn_local};
use kanal::AsyncReceiver;
use solana_ledger::shred::{Shred, ShredType};

use crate::{
    thread_manager::CancelRx,
    types::{PacketInfo, ShredInfoView},
};

pub struct ShredRes {
    data: Option<ShredInfoView>,
    code: Option<ShredInfoView>,
}

// TODO: store last 500k slots only
// TODO: use a more efficient storage format in memory (Storing all coding shreds & data shreds vs Reconstructing from 32 shreds)
#[derive(Clone)]
pub struct ShredStore {
    shred_partition: fjall::Partition,
    version: u16,
}

impl ShredStore {
    pub fn new(keyspace: &fjall::Keyspace, version: u16) -> anyhow::Result<Self> {
        let partition = keyspace.open_partition("shred_store", Default::default())?;

        Ok(Self {
            shred_partition: partition,
            version,
        })
    }

    pub async fn packet_listener_loop(self, exit: CancelRx, rx: AsyncReceiver<PacketInfo>) {
        let task = spawn_local(async move {
            let executor = executor();
            while let Ok(shred) = rx.recv().await {
                let Ok(deser_shred) = Shred::new_from_serialized_shred(shred.to_vec()) else {
                    log::debug!("received invalid shred on network");
                    continue;
                };
                let slot = deser_shred.slot();
                let index = deser_shred.index();
                if deser_shred.version() != self.version {
                    continue;
                }

                let this = self.clone();
                spawn_local(executor.spawn_blocking(move || {
                    let res = this.store_shred(slot, index, shred, deser_shred.shred_type());
                    if let Err(e) = res {
                        log::warn!("failed to store shred {e}");
                    }
                }))
                .detach();
            }
            log::warn!("shred store thread died?!")
        });
        exit.await;
        task.cancel().await;
    }

    fn store_shred(
        &self,
        slot: u64,
        shred_index: u32,
        shred: PacketInfo,
        shred_type: ShredType,
    ) -> anyhow::Result<()> {
        // slot_number::le_bytes | shred_index::le_bytes | shred_type
        let mut key = [0; 13];
        key[0..8].copy_from_slice(&slot.to_le_bytes());
        key[8..12].copy_from_slice(&shred_index.to_le_bytes());
        key[12] = shred_type as u8;

        self.shred_partition.insert(key, shred.as_slice())?;

        Ok(())
    }

    pub fn get_shred(&self, slot: u64, shred_index: u32) -> anyhow::Result<ShredRes> {
        let mut shred_prefix = [0; 12];
        shred_prefix[0..8].copy_from_slice(&slot.to_le_bytes());
        shred_prefix[8..12].copy_from_slice(&shred_index.to_le_bytes());

        let shreds = self.shred_partition.prefix(&shred_prefix);
        let mut res = ShredRes {
            data: None,
            code: None,
        };

        for shred_res in shreds {
            let (shred_key, shred) = shred_res?;
            let shred_type = shred_key[12];
            if shred_type == ShredType::Data as u8 {
                res.data = Some(shred);
            } else if shred_type == ShredType::Code as u8 {
                res.code = Some(shred);
            } else {
                log::warn!("unknown shred type: {}", shred_type);
            }
        }

        Ok(res)
    }

    pub fn get_slot_shreds(&self, slot: u64) -> fjall::Result<Vec<ShredInfoView>> {
        let mut shred_prefix = [0; 8];
        shred_prefix[0..8].copy_from_slice(&slot.to_le_bytes());

        let res = self
            .shred_partition
            .prefix(&shred_prefix)
            .map(|shred_res| shred_res.map(|(_, v)| v))
            .collect::<fjall::Result<_>>()?;

        Ok(res)
    }
}

use glommio::{executor, spawn_local};
use kanal::AsyncReceiver;
use solana_ledger::shred::{self, ShredType};

use crate::{
    thread_manager::CancelRx,
    types::{PacketInfo, ShredInfoView},
};

pub struct ShredRes {
    data: Option<ShredInfoView>,
    code: Option<ShredInfoView>,
}

#[derive(Clone)]
pub struct SlotRaw {
    pub slot: u64,
    pub shreds: Vec<PacketInfo>,
}

// TODO: store last 500k slots only
// TODO: use a more efficient storage format in memory (Storing all coding shreds & data shreds vs Reconstructing from 32 shreds)
#[derive(Clone)]
pub struct ShredStore {
    ks: fjall::Keyspace,
    shred_partition: fjall::Partition,
}

impl ShredStore {
    pub fn new(keyspace: fjall::Keyspace) -> anyhow::Result<Self> {
        let partition = keyspace.open_partition("shred_store", Default::default())?;

        Ok(Self {
            ks: keyspace,
            shred_partition: partition,
        })
    }

    pub async fn slot_listener_loop(self, exit: CancelRx, rx: AsyncReceiver<SlotRaw>) {
        let task = spawn_local(async move {
            let executor = executor();
            while let Ok(slot) = rx.recv().await {
                let this = self.clone();
                spawn_local(executor.spawn_blocking(move || {
                    if let Err(e) = this.store_slot(slot.slot, slot.shreds) {
                        log::warn!("failed to store slot {e}");
                    }
                }))
                .detach();
            }
            log::warn!("shred store thread died?!")
        });
        exit.await;
        task.cancel().await;
    }

    fn store_slot(&self, slot: u64, shreds: Vec<PacketInfo>) -> anyhow::Result<()> {
        let mut batch = self.ks.batch();
        for shred in shreds {
            let shred_info = shred::layout::get_shred_id(&shred)
                .expect("received invalid shred from slot meta?!");
            let mut key = [0; 13];
            key[0..8].copy_from_slice(&slot.to_le_bytes());

            key[8..12].copy_from_slice(&shred_info.index().to_le_bytes());
            key[12] = match shred_info.shred_type() {
                shred::ShredType::Data => ShredType::Data,
                shred::ShredType::Code => ShredType::Code,
            } as u8;
            batch.insert(&self.shred_partition, key, shred.as_slice());
        }
        batch.commit()?;
        self.ks.persist(fjall::PersistMode::SyncAll)?;

        Ok(())
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

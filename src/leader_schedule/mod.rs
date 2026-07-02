use std::str::FromStr;

use anyhow::anyhow;
use glommio::timer::sleep;
use lrumap::LruBTreeMap;
use solana_rpc_client_types::response::RpcLeaderSchedule;
use solana_sdk::pubkey::Pubkey;

use crate::solana_rpc::{SolanaRpcClient, SolanaRpcError};

const SLOTS_PER_EPOCH: usize = 432000;

pub struct LeaderScheduleStore {
    // fairly inefficient implementation, which does slot => pubkey
    // eventually we should implement a range-map like implementation
    leaders: LruBTreeMap<u64, Pubkey>,
    max_slot: u64,
}

impl Default for LeaderScheduleStore {
    fn default() -> Self {
        // 1.2 * number of slots per epoch
        let leaders = LruBTreeMap::new((SLOTS_PER_EPOCH * 12) / 10);
        Self {
            leaders,
            max_slot: Default::default(),
        }
    }
}

impl LeaderScheduleStore {
    pub fn store_leaders(&mut self, leaders: RpcLeaderSchedule, epoch_start_slot: u64) {
        for (leader, relative_slots) in leaders.into_iter() {
            let Ok(parsed) = Pubkey::from_str(&leader) else {
                log::warn!("received invalid leader from rpc: {leader}, ignoring");
                continue;
            };
            for relative_slot in relative_slots {
                let slot = epoch_start_slot + relative_slot as u64;
                _ = self.leaders.push(slot, parsed);
                self.max_slot = self.max_slot.max(slot);
            }
        }
    }
}

pub struct LeaderScheduleSync {
    store: LeaderScheduleStore,
    rpc: SolanaRpcClient,
}

impl LeaderScheduleSync {
    pub async fn new_synced(rpc: SolanaRpcClient) -> anyhow::Result<Self> {
        let mut store = LeaderScheduleStore::default();
        let schedule = rpc
            .get_leader_schedule(None)
            .await?
            .ok_or_else(|| anyhow!("leader schedule was None?!"))?;
        let epoch_info = rpc
            .get_epoch_info(None)
            .await?
            .ok_or_else(|| anyhow!("epoch info was None?!"))?;
        store.store_leaders(schedule, epoch_info.absolute_slot - epoch_info.slot_index);

        Ok(Self { store, rpc })
    }

    pub async fn get_leader_for_slot_ensure_synced(&mut self, slot: u64) -> Option<Pubkey> {
        if let Some(pubkey) = self.store.leaders.get(&slot) {
            return Some(*pubkey);
        }
        let diff = slot.saturating_sub(self.store.max_slot);
        // either the slot is too old or too new
        if diff == 0 || diff > SLOTS_PER_EPOCH as u64 {
            return None;
        }
        let (epoch_info, schedule) = loop {
            let epoch_info = match self.rpc.get_epoch_info(Some(slot)).await {
                Ok(Some(info)) => info,
                Ok(None) => {
                    log::info!("get_epoch_info was None for slot: {slot}, retrying in 2s...");
                    sleep(std::time::Duration::from_secs(2)).await;
                    continue;
                }
                Err(SolanaRpcError::JsonRpc(e))
                    if e.message == "Minimum context slot has not been reached" =>
                {
                    log::info!("get_epoch_info was None for slot: {slot}, retrying in 2s...");
                    sleep(std::time::Duration::from_secs(2)).await;
                    continue;
                }
                Err(e) => {
                    log::warn!("failed to get epoch info for slot: {slot}, {e} ignoring shred");
                    return None;
                }
            };
            if epoch_info.absolute_slot < slot {
                log::info!(
                    "epoch info absolute slot {} is less than requested slot {slot}, retrying in 2s...",
                    epoch_info.absolute_slot
                );
                sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }

            match self.rpc.get_leader_schedule(Some(slot)).await {
                Ok(Some(schedule)) => break (epoch_info, schedule),
                Ok(None) => {
                    log::warn!("leader schedule was None for slot: {slot}, retrying in 2s...");
                    sleep(std::time::Duration::from_secs(2)).await;
                    continue;
                }
                Err(e) => {
                    log::warn!(
                        "failed to get leader schedule for slot: {slot}, {e} ignoring shred"
                    );
                    return None;
                }
            };
        };

        self.store
            .store_leaders(schedule, epoch_info.absolute_slot - epoch_info.slot_index);

        self.store.leaders.get(&slot).copied()
    }
}

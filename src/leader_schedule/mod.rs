mod solana_rpc;

use std::str::FromStr;

use anyhow::anyhow;
use lru::LruCache;
use solana_rpc_client_types::response::RpcLeaderSchedule;
use solana_sdk::pubkey::Pubkey;

use crate::leader_schedule::solana_rpc::SolanaRpcClient;

const SLOTS_PER_EPOCH: usize = 432000;

pub struct LeaderScheduleStore {
    // fairly inefficient implementation, which does slot => pubkey
    // eventually we should implement a range-map like implementation
    leaders: LruCache<u64, Pubkey>,
    max_slot: u64,
}

impl Default for LeaderScheduleStore {
    fn default() -> Self {
        // 1.2 * number of slots per epoch
        let leaders = LruCache::new(((SLOTS_PER_EPOCH * 12) / 10).try_into().unwrap());
        Self {
            leaders,
            max_slot: Default::default(),
        }
    }
}

impl LeaderScheduleStore {
    pub fn store_leaders(&mut self, leaders: RpcLeaderSchedule) {
        for (leader, slots) in leaders.into_iter() {
            let Ok(parsed) = Pubkey::from_str(&leader) else {
                log::warn!("received invalid leader from rpc: {leader}, ignoring");
                continue;
            };
            for slot in slots {
                _ = self.leaders.put(slot as u64, parsed);
                self.max_slot = self.max_slot.max(slot as u64);
            }
        }
    }
}

pub struct LeaderScheduleSync {
    store: LeaderScheduleStore,
    rpc: SolanaRpcClient,
}

impl LeaderScheduleSync {
    pub async fn new_synced() -> anyhow::Result<Self> {
        let mut store = LeaderScheduleStore::default();
        let rpc = SolanaRpcClient::default();
        let schedule = rpc
            .get_leader_schedule()
            .await?
            .ok_or_else(|| anyhow!("leader schedule was None?!"))?;
        store.store_leaders(schedule);

        Ok(Self { store, rpc })
    }

    pub async fn get_leader_for_slot_ensure_synced(&mut self, slot: u64) -> Option<Pubkey> {
        if let Some(pubkey) = self.store.leaders.get(&slot) {
            return Some(*pubkey);
        }
        let diff = self.store.max_slot;
        // either the slot is too old or too new
        if diff == 0 || diff > SLOTS_PER_EPOCH as u64 {
            return None;
        }
        let schedule = match self.rpc.get_leader_schedule().await {
            Ok(Some(schedule)) => schedule,
            Ok(None) => {
                log::warn!("leader schedule was None for slot: {slot}, ignoring shred");
                return None;
            }
            Err(e) => {
                log::warn!("failed to get leader schedule for slot: {slot}, {e} ignoring shred");
                return None;
            }
        };
        self.store.store_leaders(schedule);

        self.store.leaders.get(&slot).copied()
    }
}

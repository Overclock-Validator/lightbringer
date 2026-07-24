use std::{sync::Arc, thread::JoinHandle};

use glommio::spawn_local;
use solana_ledger::shred::{self};
use solana_sdk::{pubkey::Pubkey, signature::Signature};

use crate::{
    leader_schedule::LeaderScheduleSync, repair::repair_nonce, solana_rpc::SolanaRpcClient,
    thread_manager::CancelRx, types::PacketInfo,
};

type SigCacheKey = (Signature, Pubkey, [u8; 32]);

const PACKET_PROCESSOR_THREADS: usize = 4;

#[derive(Clone)]
struct PacketProcessor {
    sig_cache: Arc<scc::HashCache<SigCacheKey, ()>>,
    meta_tx: kanal::Sender<PacketInfo>,
    overlay_tx: Option<kanal::Sender<PacketInfo>>,
}

impl PacketProcessor {
    fn new(
        meta_tx: kanal::Sender<PacketInfo>,
        overlay_tx: Option<kanal::Sender<PacketInfo>>,
    ) -> Self {
        let sig_cache = scc::HashCache::with_capacity(0, 262144);
        Self {
            sig_cache: Arc::new(sig_cache),
            meta_tx,
            overlay_tx,
        }
    }

    fn validate_packet(&self, packet: &PacketInfo, leader: Pubkey) -> bool {
        let Some(sig) = shred::wire::get_signature(packet) else {
            return false;
        };
        let Some(data) = shred::wire::get_merkle_root(packet) else {
            return false;
        };
        let key: SigCacheKey = (sig, leader, data.to_bytes());

        if self.sig_cache.contains_sync(&key) {
            return true;
        }

        if key.0.verify(key.1.as_array(), &key.2) {
            _ = self.sig_cache.put_sync(key, ());
            true
        } else {
            false
        }
    }

    fn filter_packet(&self, packet: PacketInfo, leader: Pubkey) {
        let valid = self.validate_packet(&packet, leader);
        if !valid && repair_nonce(&packet).is_some() {
            log::warn!("filtered out repair packet as it didn't verify");
        }
        if valid {
            if let Some(overlay_tx) = &self.overlay_tx
                && let Err(e) = overlay_tx.send(packet.clone())
            {
                log::warn!("failed to send validated packet to overlay: {e}");
            }
            if let Err(e) = self.meta_tx.send(packet) {
                log::warn!("failed to send packet to slot meta: {e}");
            }
        }
    }
}
struct PacketProcessorPool {
    _jobs: Vec<JoinHandle<()>>,
    senders: Vec<kanal::AsyncSender<(PacketInfo, Pubkey)>>,
    leader_schedule: LeaderScheduleSync,
}

impl PacketProcessorPool {
    fn new(
        threads: usize,
        meta_tx: kanal::Sender<PacketInfo>,
        overlay_tx: Option<kanal::Sender<PacketInfo>>,
        leader_schedule: LeaderScheduleSync,
    ) -> Self {
        let mut jobs = vec![];
        let mut senders = Vec::with_capacity(threads);
        for _ in 0..threads {
            let (tx, rx) = kanal::bounded_async(4096);
            senders.push(tx);
            let meta_tx = meta_tx.clone();
            let overlay_tx = overlay_tx.clone();
            let handle = std::thread::spawn(move || {
                let rx = rx.to_sync();
                let processor = PacketProcessor::new(meta_tx, overlay_tx);
                while let Ok((shred, pubkey)) = rx.recv() {
                    processor.filter_packet(shred, pubkey);
                }
            });
            jobs.push(handle);
        }

        Self {
            _jobs: jobs,
            senders,
            leader_schedule,
        }
    }

    async fn enqueue(&mut self, shred: PacketInfo) {
        let Some(shred_id) = shred::layout::get_index(&shred) else {
            return;
        };
        let Some(slot) = shred::layout::get_slot(&shred) else {
            return;
        };
        let Some(leader) = self
            .leader_schedule
            .get_leader_for_slot_ensure_synced(slot)
            .await
        else {
            return;
        };
        _ = self.senders[shred_id as usize % self.senders.len()]
            .send((shred, leader))
            .await;
    }
}

pub async fn packet_filter_loop(
    exit: CancelRx,
    rx: kanal::AsyncReceiver<PacketInfo>,
    meta_tx: kanal::Sender<PacketInfo>,
    rpc: SolanaRpcClient,
    overlay_tx: Option<kanal::Sender<PacketInfo>>,
) {
    let leader_schedule = LeaderScheduleSync::new_synced(rpc)
        .await
        .expect("failed to initialize leader schedule");
    let task = spawn_local(async move {
        let mut pool = PacketProcessorPool::new(
            PACKET_PROCESSOR_THREADS,
            meta_tx,
            overlay_tx,
            leader_schedule,
        );
        while let Ok(packet) = rx.recv().await {
            pool.enqueue(packet).await;
        }
    });
    exit.await;
    task.cancel().await;
}

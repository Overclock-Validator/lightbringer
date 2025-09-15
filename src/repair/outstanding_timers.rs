use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use glommio::spawn_local;
use kanal::AsyncSender;
use solana_ledger::shred::Nonce;

use crate::{
    repair::{peer_manager::RepairRequestMapper, socket::RepairSocketRequestBatch},
    thread_manager::CancelRx,
};

#[derive(Clone, Copy, PartialEq)]
pub enum OutstandingRequestKind {
    WindowIndex,
    HighestWindowIndex,
}

pub type SlotRequestMap = BTreeMap<(Nonce, SocketAddr), (OutstandingRequestKind, u32)>;
const REPAIR_SLOT_TIMEOUT: Duration = Duration::from_millis(200);

#[derive(Clone, Default)]
pub struct OutstandingTimerStore {
    inner: Arc<scc::HashMap<u64, (SlotRequestMap, Instant)>>,
}

impl OutstandingTimerStore {
    pub async fn remove(
        &self,
        slot: u64,
        nonce: Nonce,
        socket: SocketAddr,
    ) -> Option<(OutstandingRequestKind, u32)> {
        let mut slot_map = self.inner.get_async(&slot).await?;
        let res = slot_map.0.remove(&(nonce, socket))?;
        std::mem::drop(slot_map);

        self.inner.remove_if_async(&slot, |v| v.0.is_empty()).await;
        Some(res)
    }

    pub async fn contains(&self, slot: u64) -> bool {
        self.inner.contains_async(&slot).await
    }

    // try to insert a new slot,
    // returning false if the slot already exists
    pub async fn try_insert(&self, slot: u64, reqs: SlotRequestMap) -> bool {
        self.inner
            .insert_async(slot, (reqs, Instant::now() + REPAIR_SLOT_TIMEOUT))
            .await
            .is_ok()
    }

    pub async fn extend_requests(&self, slot: u64, mut reqs: SlotRequestMap) {
        self.inner
            .entry_async(slot)
            .await
            .and_modify(|(existing_reqs, _)| {
                existing_reqs.append(&mut reqs);
            })
            .or_insert((reqs, Instant::now() + REPAIR_SLOT_TIMEOUT));
    }

    pub async fn timeout_watcher_loop(
        self,
        exit: CancelRx,
        send_socket: AsyncSender<RepairSocketRequestBatch>,
        mut mapper: RepairRequestMapper,
    ) {
        let task = spawn_local(async move {
            loop {
                glommio::timer::sleep(Duration::from_millis(500)).await;
                let mut socket_reqs = Vec::new();
                self.inner
                    .iter_mut_async(|mut entry| {
                        if entry.1.1 > Instant::now() {
                            return true;
                        }
                        log::info!("slot {}, repair time out", entry.0);

                        let mut new_reqs = SlotRequestMap::default();
                        socket_reqs.extend(entry.1.0.values().filter_map(|&(kind, shred)| {
                            let (socket, nonce, repair_raw) = match kind {
                                OutstandingRequestKind::WindowIndex => {
                                    mapper.map_bounded_shred(entry.0, shred)
                                }
                                OutstandingRequestKind::HighestWindowIndex => {
                                    mapper.map_unbounded_shred(entry.0, shred)
                                }
                            }?;
                            new_reqs.insert((nonce, socket), (kind, shred));

                            Some((socket, repair_raw))
                        }));

                        entry.1.0 = new_reqs;
                        entry.1.1 = Instant::now() + REPAIR_SLOT_TIMEOUT;

                        true
                    })
                    .await;
                if let Err(e) = send_socket.send(socket_reqs).await {
                    log::warn!("repair socket rx died?! {e}");
                    break;
                }
            }
        });
        exit.await;
        task.cancel().await;
    }
}

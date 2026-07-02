use std::collections::BTreeMap;

use kanal::AsyncReceiver;
use lrumap::{LruBTreeMap, LruMap};

use crate::{
    alpenglow::{
        block_id::compute_block_id,
        cert::{AlpenglowCertificateVerifier, parse_final_certificates},
        shred::recover_data_shreds,
    },
    block_conf::BlockConfUpdate,
    store::shred::SlotRaw,
};

const MAX_REORDERED_SLOTS: usize = 32;
const MAX_UNMATCHED_CANDIDATES: usize = 2_048;
const MAX_UNMATCHED_FINALIZATIONS: usize = 2_048;

pub struct AlpenglowBlockConfUpdate {
    pub update: BlockConfUpdate,
    pub slot: SlotRaw,
}

pub struct AlpenglowBlockConfStream {
    rx: AsyncReceiver<SlotRaw>,
    verifier: AlpenglowCertificateVerifier,
    candidates: LruBTreeMap<(u64, [u8; 32]), SlotRaw>,
    finalized: LruBTreeMap<(u64, [u8; 32]), ()>,
    pending: BTreeMap<u64, AlpenglowBlockConfUpdate>,
    next_slot: Option<u64>,
}

impl AlpenglowBlockConfStream {
    pub fn new(rx: AsyncReceiver<SlotRaw>, verifier: AlpenglowCertificateVerifier) -> Self {
        Self {
            rx,
            verifier,
            candidates: LruBTreeMap::new(MAX_UNMATCHED_CANDIDATES),
            finalized: LruBTreeMap::new(MAX_UNMATCHED_FINALIZATIONS),
            pending: BTreeMap::new(),
            next_slot: None,
        }
    }

    pub async fn next(&mut self) -> Option<AlpenglowBlockConfUpdate> {
        loop {
            if let Some(update) = self.pop_ready() {
                return Some(update);
            }

            let slot = self.rx.recv().await.ok()?;
            let slot_num = slot.slot;
            let shreds = match recover_data_shreds(&slot.shreds) {
                Ok(shreds) => shreds,
                Err(e) => {
                    log::warn!("failed to recover alpenglow data shreds for slot {slot_num}: {e}");
                    continue;
                }
            };
            let slot = SlotRaw {
                slot: slot_num,
                shreds,
            };

            let block_hash = match compute_block_id(&slot.shreds) {
                Ok(block_hash) => block_hash,
                Err(e) => {
                    log::warn!("failed to compute alpenglow block id for slot {slot_num}: {e}");
                    continue;
                }
            };

            let final_certificates = parse_final_certificates(&slot.shreds);
            self.candidates.push((slot_num, block_hash), slot);

            for final_certificate in final_certificates {
                match self
                    .verifier
                    .verify_final_certificate(final_certificate)
                    .await
                {
                    Ok(finalization) => {
                        self.finalized
                            .push((finalization.slot, finalization.block_id), ());
                    }
                    Err(e) => {
                        log::warn!("failed to verify alpenglow finalization certificate: {e}");
                    }
                }
            }

            self.promote_finalized_candidates();
        }
    }

    fn promote_finalized_candidates(&mut self) {
        let finalized = self
            .finalized
            .iter()
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();
        for key @ (slot_num, block_hash) in finalized {
            if self.next_slot.is_some_and(|next| slot_num < next) {
                self.remove_finalized(&key);
                self.remove_candidate(&key);
                continue;
            }
            let Some(slot) = self.remove_candidate(&key) else {
                continue;
            };
            self.remove_finalized(&key);
            self.pending.insert(
                slot_num,
                AlpenglowBlockConfUpdate {
                    update: BlockConfUpdate {
                        slot: slot_num,
                        block_hash,
                    },
                    slot,
                },
            );
        }
    }

    fn remove_candidate(&mut self, key: &(u64, [u8; 32])) -> Option<SlotRaw> {
        self.candidates.entry(key).map(|entry| entry.take().1)
    }

    fn remove_finalized(&mut self, key: &(u64, [u8; 32])) -> Option<()> {
        self.finalized.entry(key).map(|entry| entry.take().1)
    }

    fn pop_ready(&mut self) -> Option<AlpenglowBlockConfUpdate> {
        let next_slot = match self.next_slot {
            Some(next_slot) => next_slot,
            None => {
                let slot = *self.pending.first_key_value()?.0;
                self.next_slot = Some(slot);
                slot
            }
        };

        let slot = if self.pending.contains_key(&next_slot) {
            next_slot
        } else if self.pending.len() > MAX_REORDERED_SLOTS {
            *self.pending.first_key_value()?.0
        } else {
            return None;
        };

        let update = self.pending.remove(&slot)?;
        self.next_slot = Some(slot.saturating_add(1));
        Some(update)
    }
}

pub mod block_id;
pub mod cert;
pub mod shred;
pub mod snapshot;

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        env,
        sync::{Arc, OnceLock},
    };

    use bs58;
    use solana_hash::Hash;

    use crate::{
        alpenglow::{
            block_id::compute_block_id,
            cert::{AlpenglowCertificateVerifier, parse_final_certificates},
            snapshot::SnapshotSource,
        },
        solana_rpc::SolanaRpcClient,
        store::shred::SHRED_KEYSPACE,
        types::{PacketInfo, PacketView},
    };

    fn packet_from_bytes(bytes: &[u8]) -> PacketInfo {
        let mut packet = PacketView::new();
        packet
            .try_extend_from_slice(bytes)
            .expect("stored shred exceeds packet size");
        Arc::new(packet)
    }

    fn slot_from_key(key: &[u8]) -> Option<u64> {
        let slot = <[u8; 8]>::try_from(key.get(0..8)?).ok()?;
        Some(u64::from_be_bytes(slot))
    }

    /// Opened once and shared across tests in this process - fjall only allows one open
    /// handle onto a given store, and `cargo test` runs test functions concurrently.
    fn open_synced_shred_store() -> Option<fjall::Keyspace> {
        static KEYSPACE: OnceLock<Option<fjall::Keyspace>> = OnceLock::new();
        KEYSPACE
            .get_or_init(|| {
                let path = env::var("LIGHTBRINGER_ALPENGLOW_SHRED_STORE").ok()?;
                let db = fjall::Database::builder(path).open().unwrap();
                Some(db.keyspace(SHRED_KEYSPACE, Default::default).unwrap())
            })
            .clone()
    }

    fn read_slot_shreds(shred_keyspace: &fjall::Keyspace, slot: u64) -> Vec<PacketInfo> {
        let prefix = slot.to_be_bytes();
        shred_keyspace
            .prefix(prefix)
            .map(|item| {
                let value = item.value().unwrap();
                packet_from_bytes(&value)
            })
            .collect()
    }

    fn stored_slot_bounds(shred_keyspace: &fjall::Keyspace) -> Option<(u64, u64)> {
        let mut bounds = None::<(u64, u64)>;
        for item in shred_keyspace.iter() {
            let key = item.key().unwrap();
            let Some(slot) = slot_from_key(&key) else {
                continue;
            };
            bounds = Some(match bounds {
                Some((min, max)) => (min.min(slot), max.max(slot)),
                None => (slot, slot),
            });
        }
        bounds
    }

    fn stored_slots(shred_keyspace: &fjall::Keyspace, start: u64, end: u64) -> Vec<u64> {
        let mut start_key = [0u8; 12];
        start_key[..8].copy_from_slice(&start.to_be_bytes());
        let mut end_key = [0xffu8; 12];
        end_key[..8].copy_from_slice(&end.to_be_bytes());
        let mut slots = BTreeMap::<u64, ()>::new();
        for item in shred_keyspace.range(start_key..=end_key) {
            let key = item.key().unwrap();
            let Some(slot) = slot_from_key(&key) else {
                continue;
            };
            slots.insert(slot, ());
        }
        slots.into_keys().collect()
    }

    /// `LIGHTBRINGER_ALPENGLOW_TEST_START`/`_END` narrow the scan; without them, the whole
    /// store is scanned once to find its slot bounds.
    fn test_slot_range(shred_keyspace: &fjall::Keyspace) -> (u64, u64) {
        let start = env::var("LIGHTBRINGER_ALPENGLOW_TEST_START")
            .ok()
            .and_then(|s| s.parse().ok());
        let end = env::var("LIGHTBRINGER_ALPENGLOW_TEST_END")
            .ok()
            .and_then(|s| s.parse().ok());
        match (start, end) {
            (Some(start), Some(end)) => (start, end),
            _ => stored_slot_bounds(shred_keyspace).expect("shred store has no slots"),
        }
    }

    #[test]
    fn synced_alpenglow_block_ids_match_footer_certificates() {
        let Some(shred_keyspace) = open_synced_shred_store() else {
            eprintln!("set LIGHTBRINGER_ALPENGLOW_SHRED_STORE to run this fixture test");
            return;
        };

        let (start, end) = test_slot_range(&shred_keyspace);
        let slots = stored_slots(&shred_keyspace, start, end);
        assert!(!slots.is_empty(), "synced shred store has no tested slots");

        let mut block_ids = BTreeMap::<u64, [u8; 32]>::new();
        let mut final_certificate_count = 0usize;

        for slot in slots {
            let shreds = read_slot_shreds(&shred_keyspace, slot);
            if shreds.is_empty() {
                continue;
            }

            let block_id = match compute_block_id(&shreds) {
                Ok(block_id) => block_id,
                Err(e) => {
                    eprintln!("slot {slot}: failed to compute alpenglow block id: {e}");
                    continue;
                }
            };
            block_ids.insert(slot, block_id);

            for final_certificate in parse_final_certificates(&shreds) {
                final_certificate_count += 1;
                let Some(local_block_id) = block_ids.get(&final_certificate.slot) else {
                    continue;
                };
                assert_eq!(
                    *local_block_id,
                    final_certificate.block_id.to_bytes(),
                    "slot {} footer cert for slot {} references {} but local block id is {}",
                    slot,
                    final_certificate.slot,
                    final_certificate.block_id,
                    Hash::new_from_array(*local_block_id),
                );
            }
        }

        assert!(
            final_certificate_count > 0,
            "tested slots contained no final certificates"
        );
    }

    /// Oracle check (doc §8.1): the snapshot-derived `epoch_stakes[E]` must equal the patched
    /// node's own `getAlpenglowRankMap(slot∈E)` entry-for-entry - rank order, compressed BLS
    /// pubkey, per-entry stake, and total stake.
    #[test]
    fn snapshot_rank_maps_match_alpenglow_rank_map_oracle() {
        let Ok(verify_rpc) = env::var("LIGHTBRINGER_ALPENGLOW_VERIFY_RPC") else {
            eprintln!("set LIGHTBRINGER_ALPENGLOW_VERIFY_RPC to run this oracle test");
            return;
        };

        glommio::LocalExecutor::default().run(async {
            let rpc = SolanaRpcClient::new(verify_rpc.clone());
            let epoch_schedule = rpc
                .get_epoch_schedule()
                .await
                .expect("get_epoch_schedule failed");

            let snapshot_source = SnapshotSource::new(verify_rpc);
            let rank_maps = snapshot_source
                .fetch_epoch_rank_maps()
                .expect("failed to fetch snapshot epoch rank maps");
            assert!(
                !rank_maps.is_empty(),
                "snapshot manifest carried no versioned epoch stakes"
            );

            let mut checked_epochs = 0usize;
            for (&epoch, local) in &rank_maps {
                let slot = epoch_schedule.get_first_slot_in_epoch(epoch);
                let oracle = rpc
                    .get_alpenglow_rank_map(slot)
                    .await
                    .unwrap_or_else(|e| panic!("getAlpenglowRankMap({slot}) failed: {e}"));
                assert_eq!(
                    oracle.epoch, epoch,
                    "oracle resolved slot {slot} to epoch {} instead of {epoch}",
                    oracle.epoch
                );
                assert_eq!(
                    oracle.total_stake, local.total_stake,
                    "epoch {epoch}: total stake mismatch"
                );
                assert_eq!(
                    oracle.entries.len(),
                    local.rank_map.len(),
                    "epoch {epoch}: rank map length mismatch"
                );

                for (rank, oracle_entry) in oracle.entries.iter().enumerate() {
                    let local_entry = local
                        .rank_map
                        .get_pubkey_stake_entry(rank)
                        .unwrap_or_else(|| panic!("epoch {epoch}: local rank map missing rank {rank}"));
                    assert_eq!(oracle_entry.rank as usize, rank);
                    assert_eq!(
                        oracle_entry.stake,
                        local_entry.stake.get(),
                        "epoch {epoch} rank {rank}: stake mismatch"
                    );
                    let local_compressed =
                        bs58::encode(local_entry.bls_pubkey.to_bytes_compressed()).into_string();
                    assert_eq!(
                        oracle_entry.bls_pubkey_compressed, local_compressed,
                        "epoch {epoch} rank {rank}: BLS pubkey mismatch"
                    );
                }
                checked_epochs += 1;
            }

            assert!(checked_epochs > 0, "no epochs were checked against the oracle");
        });
    }

    /// E2e check (doc §8.2): stored footer certificates must verify against the
    /// snapshot-derived rank map for their epoch.
    #[test]
    fn stored_final_certificates_verify_against_snapshot_rank_map() {
        let (Some(shred_keyspace), Ok(verify_rpc)) = (
            open_synced_shred_store(),
            env::var("LIGHTBRINGER_ALPENGLOW_VERIFY_RPC"),
        ) else {
            eprintln!(
                "set LIGHTBRINGER_ALPENGLOW_SHRED_STORE and LIGHTBRINGER_ALPENGLOW_VERIFY_RPC to run this e2e test"
            );
            return;
        };

        let (start, end) = test_slot_range(&shred_keyspace);
        let slots = stored_slots(&shred_keyspace, start, end);
        assert!(!slots.is_empty(), "synced shred store has no tested slots");

        glommio::LocalExecutor::default().run(async {
            let rpc = SolanaRpcClient::new(verify_rpc.clone());
            let shred_version = rpc
                .get_shred_version()
                .await
                .expect("get_shred_version failed");
            let snapshot_source = SnapshotSource::new(verify_rpc);
            let mut verifier =
                AlpenglowCertificateVerifier::new(rpc, snapshot_source, shred_version);

            let mut verified_count = 0usize;
            let mut failed_count = 0usize;
            for slot in slots {
                let shreds = read_slot_shreds(&shred_keyspace, slot);
                if shreds.is_empty() {
                    continue;
                }
                for final_certificate in parse_final_certificates(&shreds) {
                    let cert_slot = final_certificate.slot;
                    match verifier.verify_final_certificate(final_certificate).await {
                        Ok(finalization) => {
                            assert_eq!(finalization.slot, cert_slot);
                            verified_count += 1;
                        }
                        Err(e) => {
                            failed_count += 1;
                            eprintln!("slot {slot}: cert for slot {cert_slot} failed to verify: {e}");
                        }
                    }
                }
            }

            assert!(
                verified_count > 0,
                "tested slots contained no verifiable final certificates"
            );
            assert_eq!(
                failed_count, 0,
                "{failed_count} stored certificates failed to verify against the snapshot rank map"
            );
        });
    }
}

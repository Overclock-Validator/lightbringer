use std::{collections::BTreeMap, num::NonZeroU64, sync::Arc};

use agave_bls_cert_verify::cert_verify::verify_certificate;
use agave_votor_messages::{
    certificate::CertificateType, consensus_message::Block,
    unverified_vote_message::UnverifiedCertificate,
};
use anyhow::{Result, anyhow, bail};
use solana_bls_signatures::pubkey::{PopVerified, PubkeyAffine as BlsPubkeyAffine};
use solana_clock::Epoch;
use solana_entry::block_component::{
    BlockComponent, BlockFinalizationCert, VersionedBlockFooter, VersionedBlockMarker,
};
use solana_epoch_schedule::EpochSchedule;
use solana_ledger::shred::{Shred, ShredType};
use solana_runtime::epoch_stakes::BLSPubkeyToRankMap;

use crate::{
    alpenglow::{block_id::get_data, snapshot::SnapshotSource},
    solana_rpc::SolanaRpcClient,
    types::PacketInfo,
};

/// How many of the most recent epochs' rank maps to keep cached. A single snapshot fetch
/// covers the current and next epoch, so this is just a small safety margin.
const RETAINED_RANK_MAP_EPOCHS: u64 = 3;

pub struct VerifiedFinalization {
    pub slot: u64,
    pub block_id: [u8; 32],
}

struct RankMap {
    rank_map: Arc<BLSPubkeyToRankMap>,
    total_stake: NonZeroU64,
}

impl RankMap {
    fn get(&self, rank: usize) -> Option<(NonZeroU64, PopVerified<BlsPubkeyAffine>)> {
        self.rank_map
            .get_pubkey_stake_entry(rank)
            .map(|entry| (entry.stake, entry.bls_pubkey))
    }

    fn len(&self) -> usize {
        self.rank_map.len()
    }
}

/// Verifies Alpenglow finalization certificates against the node's own frozen
/// `epoch_stakes`, read out of an incremental snapshot manifest (see
/// `crate::alpenglow::snapshot`). Never reconstructs stakes from live account state and
/// never depends on a debug RPC oracle in production.
pub struct AlpenglowCertificateVerifier {
    rpc: SolanaRpcClient,
    snapshot_source: SnapshotSource,
    epoch_schedule: Option<EpochSchedule>,
    rank_maps: BTreeMap<Epoch, RankMap>,
    /// Mixed into the signed vote payload (`VotePayloadToSign`); must match the target
    /// cluster's shred version or every signature check fails regardless of the rank map.
    shred_version: u16,
}

impl AlpenglowCertificateVerifier {
    pub fn new(rpc: SolanaRpcClient, snapshot_source: SnapshotSource, shred_version: u16) -> Self {
        Self {
            rpc,
            snapshot_source,
            epoch_schedule: None,
            rank_maps: BTreeMap::new(),
            shred_version,
        }
    }

    pub async fn verify_final_certificate(
        &mut self,
        final_cert: BlockFinalizationCert,
    ) -> Result<VerifiedFinalization> {
        let cert_epoch = self.epoch_for_slot(final_cert.slot).await?;
        self.ensure_rank_map(cert_epoch).await?;
        let rank_map = self
            .rank_maps
            .get(&cert_epoch)
            .ok_or_else(|| anyhow!("missing alpenglow rank map for epoch {cert_epoch}"))?;

        let slot = final_cert.slot;
        let block_id = final_cert.block_id;
        let block = Block { slot, block_id };
        if let Some(notar_aggregate) = final_cert.notar_aggregate {
            let notarize_cert = UnverifiedCertificate {
                cert_type: CertificateType::Notarize(block),
                signature: notar_aggregate
                    .uncompress_signature()
                    .map_err(|e| anyhow!("invalid notarize BLS signature: {e:?}"))?,
                bitmap: notar_aggregate.into_bitmap(),
                shred_version: self.shred_version,
            };
            let finalize_cert = UnverifiedCertificate {
                cert_type: CertificateType::Finalize(slot),
                signature: final_cert
                    .final_aggregate
                    .uncompress_signature()
                    .map_err(|e| anyhow!("invalid finalize BLS signature: {e:?}"))?,
                bitmap: final_cert.final_aggregate.into_bitmap(),
                shred_version: self.shred_version,
            };

            Self::verify(rank_map, notarize_cert)?;
            Self::verify(rank_map, finalize_cert)?;
        } else {
            let cert = UnverifiedCertificate {
                cert_type: CertificateType::FinalizeFast(block),
                signature: final_cert
                    .final_aggregate
                    .uncompress_signature()
                    .map_err(|e| anyhow!("invalid fast-finalize BLS signature: {e:?}"))?,
                bitmap: final_cert.final_aggregate.into_bitmap(),
                shred_version: self.shred_version,
            };
            Self::verify(rank_map, cert)?;
        }

        Ok(VerifiedFinalization {
            slot,
            block_id: block_id.to_bytes(),
        })
    }

    /// Signature and stake-threshold verification are both handled by `verify_certificate`.
    fn verify(rank_map: &RankMap, cert: UnverifiedCertificate) -> Result<()> {
        let cert_type = cert.cert_type;
        verify_certificate(cert, rank_map.len(), rank_map.total_stake, |rank| {
            rank_map.get(rank)
        })
        .map_err(|e| anyhow!("failed to verify {cert_type:?}: {e}"))?;
        Ok(())
    }

    async fn epoch_for_slot(&mut self, slot: u64) -> Result<Epoch> {
        if self.epoch_schedule.is_none() {
            self.epoch_schedule = Some(self.rpc.get_epoch_schedule().await?);
        }
        Ok(self
            .epoch_schedule
            .as_ref()
            .expect("epoch schedule populated above")
            .get_epoch(slot))
    }

    /// Ensures `rank_maps` has an entry for `cert_epoch`, fetching a fresh snapshot only
    /// when it's missing. Every snapshot carries the current and next epoch's stakes, so
    /// this only does network work once per epoch boundary.
    ///
    /// The fetch itself (HTTP GET, zstd decode, tar walk, bincode deserialize) is
    /// synchronous end-to-end - `zstd`/`tar` only expose blocking `Read`-based APIs, so
    /// there's no async path through them regardless of the HTTP client. `spawn_blocking`
    /// runs it on glommio's blocking thread pool instead of the reactor thread.
    async fn ensure_rank_map(&mut self, cert_epoch: Epoch) -> Result<()> {
        if self.rank_maps.contains_key(&cert_epoch) {
            return Ok(());
        }

        let snapshot_source = self.snapshot_source.clone();
        let fetched = glommio::executor()
            .spawn_blocking(move || snapshot_source.fetch_epoch_rank_maps())
            .await?;

        for (epoch, entry) in fetched {
            let Some(total_stake) = NonZeroU64::new(entry.total_stake) else {
                log::warn!("alpenglow snapshot rank map for epoch {epoch} has zero total stake");
                continue;
            };
            self.rank_maps.insert(
                epoch,
                RankMap {
                    rank_map: entry.rank_map,
                    total_stake,
                },
            );
        }

        let newest_epoch = *self.rank_maps.keys().next_back().unwrap_or(&cert_epoch);
        let oldest_retained_epoch = newest_epoch.saturating_sub(RETAINED_RANK_MAP_EPOCHS - 1);
        self.rank_maps
            .retain(|epoch, _| *epoch >= oldest_retained_epoch);

        if !self.rank_maps.contains_key(&cert_epoch) {
            bail!(
                "alpenglow snapshot manifest did not contain a rank map for epoch {cert_epoch}"
            );
        }
        Ok(())
    }
}

pub fn parse_final_certificates(shreds: &[PacketInfo]) -> Vec<BlockFinalizationCert> {
    shreds
        .iter()
        .filter_map(|raw_shred| {
            let shred = Shred::new_from_serialized_shred(raw_shred.as_slice().to_vec()).ok()?;
            if shred.shred_type() != ShredType::Data {
                return None;
            }
            parse_final_certificate(&shred)
        })
        .collect()
}

fn parse_final_certificate(shred: &Shred) -> Option<BlockFinalizationCert> {
    let payload = get_data(shred)?;
    if !BlockComponent::infer_is_block_marker(payload).unwrap_or(false) {
        return None;
    }
    let component: BlockComponent = wincode::deserialize(payload).ok()?;
    let VersionedBlockMarker::V1(marker) = component.as_marker()?;
    let VersionedBlockFooter::V1(footer) = marker.as_block_footer()?;
    footer.block_final_cert.clone()
}

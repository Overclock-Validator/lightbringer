use std::collections::BTreeMap;

use anyhow::{Result, anyhow, bail};
use solana_entry::block_component::{
    BlockComponent, VersionedBlockHeader, VersionedBlockMarker, VersionedUpdateParent,
};
use solana_hash::Hash;
use solana_ledger::shred::{
    self, DATA_SHREDS_PER_FEC_BLOCK, SIZE_OF_DATA_SHRED_HEADERS, Shred, ShredFlags, ShredType,
    merkle_tree::MerkleTree,
};
use solana_sha256_hasher::hashv;

use crate::types::PacketInfo;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ParentInfo {
    parent_slot: u64,
    parent_block_id: Hash,
    replay_fec_set_index: u32,
}

impl ParentInfo {
    fn block(self) -> (u64, Hash) {
        (self.parent_slot, self.parent_block_id)
    }

    fn has_update_parent(self) -> bool {
        self.replay_fec_set_index > 0
    }

    fn populated_from_block_header(self) -> bool {
        self.replay_fec_set_index == 0
    }

    fn validate_update_parent_slot(self, slot: u64) -> Result<()> {
        if self.has_update_parent() && leader_slot_index(slot) != 0 {
            bail!("slot {slot} has update-parent marker outside first leader slot");
        }
        Ok(())
    }

    fn validate_shred_parent(self, slot: u64, shred_parent_slot: u64) -> Result<()> {
        if !verify_shred_slots(slot, self.parent_slot) {
            bail!(
                "slot {slot} has invalid alpenglow parent slot {}",
                self.parent_slot
            );
        }
        if self.populated_from_block_header() && self.parent_slot != shred_parent_slot {
            bail!(
                "slot {slot} block-header parent {} does not match shred parent {shred_parent_slot}",
                self.parent_slot
            );
        }
        if self.has_update_parent() && self.parent_slot > shred_parent_slot {
            bail!(
                "slot {slot} update-parent slot {} is greater than shred parent {shred_parent_slot}",
                self.parent_slot
            );
        }
        Ok(())
    }

    fn should_replace(slot: u64, new: Self, prev: Self) -> Result<bool> {
        let (update_parent, block_header, should_replace) = match (
            new.populated_from_block_header(),
            prev.populated_from_block_header(),
        ) {
            (true, false) => (prev, new, false),
            (false, true) => (new, prev, true),
            (false, false) if new == prev => return Ok(false),
            (false, false) => bail!("slot {slot} has multiple update-parent markers"),
            (true, true) if new == prev => return Ok(false),
            (true, true) => bail!("slot {slot} has multiple block headers"),
        };

        if update_parent.block() == block_header.block() {
            bail!("slot {slot} update-parent matches block-header parent");
        }
        if update_parent.parent_slot > block_header.parent_slot {
            bail!("slot {slot} update-parent slot is greater than block-header parent slot");
        }
        Ok(should_replace)
    }
}

pub fn compute_block_id(shreds: &[PacketInfo]) -> Result<[u8; 32]> {
    let mut data_shreds = BTreeMap::new();
    let mut fec_roots = BTreeMap::new();
    let mut slot = None;
    let mut shred_parent_slot = None;
    let mut last_index = None;

    for raw_shred in shreds {
        let shred = Shred::new_from_serialized_shred(raw_shred.as_slice().to_vec())
            .map_err(|e| anyhow!("invalid shred: {e:?}"))?;
        let shred_slot = shred.slot();
        if slot
            .replace(shred_slot)
            .is_some_and(|prev| prev != shred_slot)
        {
            bail!("completed slot batch contains multiple slots");
        }

        if shred.shred_type() != ShredType::Data {
            continue;
        }

        let fec_set_index = shred.fec_set_index();
        let merkle_root = shred
            .merkle_root()
            .map_err(|e| anyhow!("invalid shred merkle root: {e:?}"))?;
        if fec_roots
            .insert(fec_set_index, merkle_root)
            .is_some_and(|prev| prev != merkle_root)
        {
            bail!("slot {shred_slot} has conflicting merkle roots for FEC set {fec_set_index}");
        }

        let parent_slot = shred
            .parent()
            .map_err(|e| anyhow!("invalid shred parent: {e:?}"))?;
        if shred_parent_slot
            .replace(parent_slot)
            .is_some_and(|prev| prev != parent_slot)
        {
            bail!("slot {shred_slot} has conflicting shred-header parent slots");
        }

        if shred.last_in_slot() {
            let index = shred.index();
            if last_index.replace(index).is_some_and(|prev| prev != index) {
                bail!("slot {shred_slot} has conflicting last shred indexes");
            }
        }

        data_shreds.entry(shred.index()).or_insert(shred);
    }

    let slot = slot.ok_or_else(|| anyhow!("cannot compute alpenglow block id without shreds"))?;
    let shred_parent_slot =
        shred_parent_slot.ok_or_else(|| anyhow!("slot {slot} has no data shreds"))?;
    let last_index =
        last_index.ok_or_else(|| anyhow!("slot {slot} has no last-in-slot data shred"))?;

    for index in 0..=last_index {
        if !data_shreds.contains_key(&index) {
            bail!("slot {slot} is missing data shred {index}");
        }
    }

    let fec_set_count = last_index / DATA_SHREDS_PER_FEC_BLOCK as u32 + 1;
    let parent_info = parse_parent_info(slot, shred_parent_slot, &data_shreds)?;
    let leaves = (0..fec_set_count)
        .map(|i| {
            let fec_set_index = i * DATA_SHREDS_PER_FEC_BLOCK as u32;
            fec_roots
                .get(&fec_set_index)
                .copied()
                .ok_or(shred::Error::InvalidMerkleRoot)
        })
        .chain(std::iter::once(Ok(hashv(&[
            &parent_info.parent_slot.to_le_bytes(),
            parent_info.parent_block_id.as_ref(),
            &fec_set_count.to_le_bytes(),
        ]))));

    let merkle_tree = MerkleTree::try_new_with_len(leaves, fec_set_count as usize + 1)
        .map_err(|e| anyhow!("failed to build double merkle tree: {e:?}"))?;
    Ok(merkle_tree.root().to_bytes())
}

fn parse_parent_info(
    slot: u64,
    shred_parent_slot: u64,
    data_shreds: &BTreeMap<u32, Shred>,
) -> Result<ParentInfo> {
    let mut parent_info = None;
    let header = parse_block_header(
        data_shreds
            .get(&0)
            .ok_or_else(|| anyhow!("slot {slot} missing data shred 0"))?,
    );
    apply_parent_info(slot, shred_parent_slot, &mut parent_info, header)?;

    for shred in data_shreds.values() {
        let Some(update_parent) = parse_update_parent(shred, data_shreds) else {
            continue;
        };
        apply_parent_info(
            slot,
            shred_parent_slot,
            &mut parent_info,
            Some(update_parent),
        )?;
    }

    parent_info.ok_or_else(|| anyhow!("slot {slot} has no alpenglow block header"))
}

fn apply_parent_info(
    slot: u64,
    shred_parent_slot: u64,
    parent_info: &mut Option<ParentInfo>,
    new_parent_info: Option<ParentInfo>,
) -> Result<()> {
    let Some(new_parent_info) = new_parent_info else {
        return Ok(());
    };
    new_parent_info.validate_update_parent_slot(slot)?;
    new_parent_info.validate_shred_parent(slot, shred_parent_slot)?;
    if let Some(prev) = *parent_info
        && !ParentInfo::should_replace(slot, new_parent_info, prev)?
    {
        return Ok(());
    }
    *parent_info = Some(new_parent_info);
    Ok(())
}

fn parse_block_header(shred: &Shred) -> Option<ParentInfo> {
    if shred.index() != 0 {
        return None;
    }
    let payload = get_data(shred)?;
    if !BlockComponent::infer_is_block_marker(payload).unwrap_or(false) {
        return None;
    }
    let component: BlockComponent = wincode::deserialize(payload).ok()?;
    let VersionedBlockMarker::V1(marker) = component.as_marker()?;
    let VersionedBlockHeader::V1(header) = marker.as_block_header()?;
    Some(ParentInfo {
        parent_slot: header.parent_slot,
        parent_block_id: header.parent_block_id,
        replay_fec_set_index: 0,
    })
}

fn parse_update_parent(
    current_shred: &Shred,
    data_shreds: &BTreeMap<u32, Shred>,
) -> Option<ParentInfo> {
    let current_index = current_shred.index();
    let fec_set_index = current_shred.fec_set_index();
    let (target_shred, target_fec_set_index) = if current_shred.data_complete() {
        let next_fec_set_index = fec_set_index + DATA_SHREDS_PER_FEC_BLOCK as u32;
        (data_shreds.get(&next_fec_set_index)?, next_fec_set_index)
    } else if current_index.is_multiple_of(DATA_SHREDS_PER_FEC_BLOCK as u32) && current_index > 0 {
        let prev_shred = data_shreds.get(&(current_index - 1))?;
        let flags = shred::layout::get_flags(prev_shred.payload()).ok()?;
        if !flags.contains(ShredFlags::DATA_COMPLETE_SHRED) {
            return None;
        }
        (current_shred, fec_set_index)
    } else {
        return None;
    };

    let payload = get_data(target_shred)?;
    if !BlockComponent::infer_is_block_marker(payload).unwrap_or(false) {
        return None;
    }
    let component: BlockComponent = wincode::deserialize(payload).ok()?;
    let VersionedBlockMarker::V1(marker) = component.as_marker()?;
    let VersionedUpdateParent::V1(update_parent) = marker.as_update_parent()?;
    Some(ParentInfo {
        parent_slot: update_parent.new_parent_slot,
        parent_block_id: update_parent.new_parent_block_id,
        replay_fec_set_index: target_fec_set_index,
    })
}

fn leader_slot_index(slot: u64) -> usize {
    slot as usize % 4
}

fn verify_shred_slots(slot: u64, parent: u64) -> bool {
    (slot == 0 && parent == 0) || parent < slot
}

pub(crate) fn get_data(shred: &Shred) -> Option<&[u8]> {
    let payload = shred.payload();
    let size = get_data_size(payload)? as usize;
    if !(SIZE_OF_DATA_SHRED_HEADERS..=payload.len()).contains(&size) {
        return None;
    }
    payload.get(SIZE_OF_DATA_SHRED_HEADERS..size)
}

fn get_data_size(shred: &[u8]) -> Option<u16> {
    let bytes = <[u8; 2]>::try_from(shred.get(86..88)?).ok()?;
    Some(u16::from_le_bytes(bytes))
}

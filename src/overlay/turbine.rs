use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use solana_ledger::shred::Shred;
use solana_sdk::pubkey::Pubkey;

/// Deterministic retransmit-peer selection seeded by (shred id, pubkey) —
/// identities, not socket addresses, per nat-traversal.md §6.7: a NATed
/// node has no unique stable address, its pubkey is the only stable name.
#[derive(Clone, Debug)]
pub struct TurbineTree {
    local: Pubkey,
    fanout: usize,
}

impl TurbineTree {
    pub fn new(local: Pubkey, fanout: usize) -> Self {
        Self {
            local,
            fanout: fanout.max(1),
        }
    }

    pub fn retransmit_peers(&self, payload: &[u8], peers: &[Pubkey]) -> Vec<Pubkey> {
        let Some(indexed) = self.indexed_tree(payload, peers) else {
            return Vec::new();
        };
        let (local_index, shuffled) = indexed;
        retransmit_indices(local_index, self.fanout, shuffled.len())
            .filter_map(|index| shuffled.get(index).copied())
            .collect()
    }

    /// Peers for a locally-originated shred. The origin acts as the leader
    /// for this shred: when the shuffle makes it the tree root it fans out
    /// to the first layer, otherwise it hands the shred to the shuffled
    /// root (which then retransmits through `retransmit_peers`). Reusing
    /// the child fan-out here would silently drop every shred whose
    /// shuffle placed the origin off-root.
    pub fn origin_peers(&self, payload: &[u8], peers: &[Pubkey]) -> Vec<Pubkey> {
        let Some((local_index, shuffled)) = self.indexed_tree(payload, peers) else {
            return Vec::new();
        };
        if local_index == 0 {
            retransmit_indices(0, self.fanout, shuffled.len())
                .filter_map(|index| shuffled.get(index).copied())
                .collect()
        } else {
            shuffled.first().copied().into_iter().collect()
        }
    }

    fn indexed_tree(&self, payload: &[u8], peers: &[Pubkey]) -> Option<(usize, Vec<Pubkey>)> {
        let mut nodes = Vec::with_capacity(peers.len() + 1);
        nodes.push(self.local);
        nodes.extend(peers.iter().copied().filter(|peer| *peer != self.local));
        nodes.sort_unstable();
        nodes.dedup();

        let seed = shred_seed(payload);
        nodes.sort_by_key(|pubkey| {
            let mut hasher = DefaultHasher::new();
            seed.hash(&mut hasher);
            pubkey.hash(&mut hasher);
            hasher.finish()
        });

        let local_index = nodes.iter().position(|pubkey| *pubkey == self.local)?;
        Some((local_index, nodes))
    }
}

fn shred_seed(payload: &[u8]) -> u64 {
    if let Ok(shred) = Shred::new_from_serialized_shred(payload.to_vec()) {
        let id = shred.id();
        let mut hasher = DefaultHasher::new();
        id.slot().hash(&mut hasher);
        id.index().hash(&mut hasher);
        return hasher.finish();
    }

    let mut hasher = DefaultHasher::new();
    payload.hash(&mut hasher);
    hasher.finish()
}

fn retransmit_indices(
    local_index: usize,
    fanout: usize,
    node_len: usize,
) -> impl Iterator<Item = usize> {
    let offset = local_index.saturating_sub(1) % fanout;
    let anchor = local_index - offset;
    let step = if local_index == 0 { 1 } else { fanout };
    (anchor * fanout + offset + 1..node_len)
        .step_by(step)
        .take(fanout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_retransmits_first_layer() {
        let got = retransmit_indices(0, 3, 10).collect::<Vec<_>>();
        assert_eq!(got, vec![1, 2, 3]);
    }

    #[test]
    fn non_root_retransmits_next_layer_stride() {
        let got = retransmit_indices(2, 3, 20).collect::<Vec<_>>();
        assert_eq!(got, vec![5, 8, 11]);
    }

    #[test]
    fn origin_always_emits_somewhere() {
        let local = Pubkey::new_unique();
        let peer = Pubkey::new_unique();
        let tree = TurbineTree::new(local, 8);
        // Whatever position the shuffle assigns, an originated shred must
        // leave the source when at least one peer exists.
        for byte in 0u8..32 {
            let payload = vec![byte; 64];
            let got = tree.origin_peers(&payload, &[peer]);
            assert_eq!(got, vec![peer], "payload seed {byte}");
        }
    }

    #[test]
    fn shuffle_is_identity_seeded_and_deterministic() {
        let local = Pubkey::new_unique();
        let peers: Vec<Pubkey> = (0..8).map(|_| Pubkey::new_unique()).collect();
        let tree = TurbineTree::new(local, 3);
        let payload = vec![9u8; 128];
        let first = tree.retransmit_peers(&payload, &peers);
        let second = tree.retransmit_peers(&payload, &peers);
        assert_eq!(first, second);
        // Duplicate peer entries collapse: same node listed twice must not
        // occupy two tree slots.
        let mut doubled = peers.clone();
        doubled.extend_from_slice(&peers);
        assert_eq!(tree.retransmit_peers(&payload, &doubled), first);
    }
}

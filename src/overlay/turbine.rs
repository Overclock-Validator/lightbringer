use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::SocketAddr,
};

use solana_ledger::shred::Shred;

#[derive(Clone, Debug)]
pub struct TurbineTree {
    local_addr: SocketAddr,
    fanout: usize,
}

impl TurbineTree {
    pub fn new(local_addr: SocketAddr, fanout: usize) -> Self {
        Self {
            local_addr,
            fanout: fanout.max(1),
        }
    }

    pub fn retransmit_peers(&self, payload: &[u8], peers: &[SocketAddr]) -> Vec<SocketAddr> {
        let Some(indexed) = self.indexed_tree(payload, peers) else {
            return Vec::new();
        };
        let (local_index, shuffled) = indexed;
        retransmit_indices(local_index, self.fanout, shuffled.len())
            .filter_map(|index| shuffled.get(index).copied())
            .collect()
    }

    fn indexed_tree(
        &self,
        payload: &[u8],
        peers: &[SocketAddr],
    ) -> Option<(usize, Vec<SocketAddr>)> {
        let mut nodes = Vec::with_capacity(peers.len() + 1);
        nodes.push(self.local_addr);
        nodes.extend(
            peers
                .iter()
                .copied()
                .filter(|peer| *peer != self.local_addr),
        );
        nodes.sort_unstable();
        nodes.dedup();

        let seed = shred_seed(payload);
        nodes.sort_by_key(|addr| {
            let mut hasher = DefaultHasher::new();
            seed.hash(&mut hasher);
            addr.hash(&mut hasher);
            hasher.finish()
        });

        let local_index = nodes.iter().position(|addr| *addr == self.local_addr)?;
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
}

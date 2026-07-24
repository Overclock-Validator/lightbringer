use solana_ledger::shred::Nonce;

use crate::types::PacketView;

mod outstanding_timers;
mod peer_manager;
pub mod request;
pub mod socket;

pub use peer_manager::SolanaRepairPeers;

pub fn repair_nonce(packet: &PacketView) -> Option<Nonce> {
    let nonce_offset = packet.len().checked_sub(4)?;
    let nonce_raw_le = <[u8; 4]>::try_from(packet.get(nonce_offset..)?).ok()?;
    Some(Nonce::from_le_bytes(nonce_raw_le))
}

#[derive(Clone, Copy, PartialEq)]
enum OutstandingRequestKind {
    WindowIndex,
    HighestWindowIndex,
}

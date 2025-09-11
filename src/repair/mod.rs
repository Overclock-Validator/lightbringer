use solana_ledger::shred::Nonce;

use crate::types::PacketView;

pub mod request;
pub mod socket;

pub fn repair_nonce(packet: &PacketView) -> Option<Nonce> {
    let nonce_offset = packet.len().checked_sub(4)?;
    let nonce_raw_le = <[u8; 4]>::try_from(packet.get(nonce_offset..)?).ok()?;
    Some(Nonce::from_le_bytes(nonce_raw_le))
}

use std::sync::Arc;

use arrayvec::ArrayVec;
use fjall::UserValue;
use solana_sdk::packet;

pub type PacketView = ArrayVec<u8, { packet::PACKET_DATA_SIZE }>;
pub type PacketInfo = Arc<PacketView>;
pub type ShredInfoView = UserValue;

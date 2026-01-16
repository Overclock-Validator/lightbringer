use std::sync::Arc;

use arrayvec::ArrayVec;
use fjall::UserValue;

pub type PacketView = ArrayVec<u8, { solana_packet::PACKET_DATA_SIZE }>;
pub type PacketInfo = Arc<PacketView>;
pub type ShredInfoView = UserValue;

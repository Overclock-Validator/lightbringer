use std::sync::Arc;

use arrayvec::ArrayVec;
use fjall::UserValue;
use solana_sdk::packet;

pub type ShredRaw = ArrayVec<u8, { packet::PACKET_DATA_SIZE }>;
pub type ShredInfo = Arc<ShredRaw>;
pub type ShredInfoView = UserValue;

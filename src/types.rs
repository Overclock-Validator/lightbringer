use std::sync::Arc;

use arrayvec::ArrayVec;
use fjall::UserValue;
use solana_sdk::packet;

pub type ShredInfo = Arc<ArrayVec<u8, { packet::PACKET_DATA_SIZE }>>; 
pub type ShredInfoView = UserValue;
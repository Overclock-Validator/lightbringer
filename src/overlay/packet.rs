use std::net::SocketAddr;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use super::gossip::OverlayPeer;

pub const OVERLAY_PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum OverlayFrame {
    Shred {
        version: u16,
        origin: SocketAddr,
        payload: Vec<u8>,
    },
    PeerAdvertisement {
        version: u16,
        peer: OverlayPeer,
    },
}

impl OverlayFrame {
    pub fn shred(origin: SocketAddr, payload: Vec<u8>) -> Self {
        Self::Shred {
            version: OVERLAY_PROTOCOL_VERSION,
            origin,
            payload,
        }
    }

    pub fn peer_advertisement(peer: OverlayPeer) -> Self {
        Self::PeerAdvertisement {
            version: OVERLAY_PROTOCOL_VERSION,
            peer,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(Into::into)
    }

    pub fn decode(raw: &[u8]) -> Result<Self> {
        let frame = bincode::deserialize::<Self>(raw)?;
        let version = match &frame {
            Self::Shred { version, .. } => *version,
            Self::PeerAdvertisement { version, .. } => *version,
        };
        if version != OVERLAY_PROTOCOL_VERSION {
            return Err(anyhow!("unsupported overlay protocol version {version}"));
        }
        Ok(frame)
    }
}

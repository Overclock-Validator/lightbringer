use std::net::SocketAddr;

use anyhow::{Result, anyhow};

use super::{
    gossip::SignedPeerAdvert,
    punch::{ConnectRequest, ConnectResponse},
};

/// v1 is not frozen; this layout replaces the earlier bincode envelope. A
/// fixed two-byte header (version, frame type) precedes a type-specific
/// body. Shred bodies are the raw shred bytes running to the end of the
/// datagram — the QUIC datagram boundary already delimits them, so no
/// length prefix — which keeps a maximum 1228-byte shred frame at 1230
/// bytes, inside the 1242-byte datagram budget at the 1280 path MTU
/// (`transport::OVERLAY_INITIAL_MTU`). There is no origin field; retransmit
/// loop suppression is the core's bounded shred dedup.
pub const OVERLAY_PROTOCOL_VERSION: u8 = 1;

/// Bytes of framing prepended to a shred payload.
pub const SHRED_FRAME_OVERHEAD: usize = 2;

const FRAME_SHRED: u8 = 0;
const FRAME_PEER_ADVERTISEMENT: u8 = 1;
const FRAME_ADDRESS_OBSERVATION: u8 = 2;
const FRAME_DIALBACK_REQUEST: u8 = 3;
const FRAME_DIALBACK_RESULT: u8 = 4;
const FRAME_CONNECT_REQUEST: u8 = 5;
const FRAME_CONNECT_RESPONSE: u8 = 6;

#[derive(Clone, Debug)]
pub enum OverlayFrame {
    Shred { payload: Vec<u8> },
    PeerAdvertisement { advert: SignedPeerAdvert },
    /// nat-traversal.md §6.2 step 1: "I see your public mapping as
    /// `observed`." Sent over an established connection; the receiver tags it
    /// with the sending peer's identity/address to classify its own NAT. No
    /// signature — the QUIC connection already authenticates the observer,
    /// and a lie only misinforms the observed node about its own address.
    AddressObservation { observed: SocketAddr },
    /// nat-traversal.md §6.2 step 3: "please confirm my reachability." The
    /// helper dials the requester's *own* observed source from a fresh port
    /// (§9: never a third-party address — no reflection vector), so the
    /// request carries a correlation nonce and, since P4, an optional port
    /// override: the probe target's IP stays pinned to the request's source,
    /// but a §6.3 gateway-mapped port on that same NAT may be probed.
    DialBackRequest {
        nonce: u64,
        probe_port: Option<u16>,
    },
    /// The helper's verdict: `ok` iff the fresh-source handshake completed
    /// with the requester's expected identity.
    DialBackResult { nonce: u64, ok: bool },
    /// P5 §6.5: signed end-origin request relayed by a connected shared peer.
    ConnectRequest { request: ConnectRequest },
    /// P5 §6.5: signed target response routed back through the same relay.
    ConnectResponse { response: ConnectResponse },
}

impl OverlayFrame {
    pub fn shred(payload: Vec<u8>) -> Self {
        Self::Shred { payload }
    }

    pub fn peer_advertisement(advert: SignedPeerAdvert) -> Self {
        Self::PeerAdvertisement { advert }
    }

    pub fn address_observation(observed: SocketAddr) -> Self {
        Self::AddressObservation { observed }
    }

    pub fn dialback_request(nonce: u64, probe_port: Option<u16>) -> Self {
        Self::DialBackRequest { nonce, probe_port }
    }

    pub fn dialback_result(nonce: u64, ok: bool) -> Self {
        Self::DialBackResult { nonce, ok }
    }

    pub fn connect_request(request: ConnectRequest) -> Self {
        Self::ConnectRequest { request }
    }

    pub fn connect_response(response: ConnectResponse) -> Self {
        Self::ConnectResponse { response }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        match self {
            Self::Shred { payload } => {
                let mut out = Vec::with_capacity(SHRED_FRAME_OVERHEAD + payload.len());
                out.push(OVERLAY_PROTOCOL_VERSION);
                out.push(FRAME_SHRED);
                out.extend_from_slice(payload);
                Ok(out)
            }
            Self::PeerAdvertisement { advert } => {
                let mut out = vec![OVERLAY_PROTOCOL_VERSION, FRAME_PEER_ADVERTISEMENT];
                bincode::serialize_into(&mut out, advert)?;
                Ok(out)
            }
            Self::AddressObservation { observed } => {
                let mut out = vec![OVERLAY_PROTOCOL_VERSION, FRAME_ADDRESS_OBSERVATION];
                bincode::serialize_into(&mut out, observed)?;
                Ok(out)
            }
            Self::DialBackRequest { nonce, probe_port } => {
                let mut out = vec![OVERLAY_PROTOCOL_VERSION, FRAME_DIALBACK_REQUEST];
                bincode::serialize_into(&mut out, &(nonce, probe_port))?;
                Ok(out)
            }
            Self::DialBackResult { nonce, ok } => {
                let mut out = vec![OVERLAY_PROTOCOL_VERSION, FRAME_DIALBACK_RESULT];
                bincode::serialize_into(&mut out, &(nonce, ok))?;
                Ok(out)
            }
            Self::ConnectRequest { request } => {
                let mut out = vec![OVERLAY_PROTOCOL_VERSION, FRAME_CONNECT_REQUEST];
                bincode::serialize_into(&mut out, request)?;
                Ok(out)
            }
            Self::ConnectResponse { response } => {
                let mut out = vec![OVERLAY_PROTOCOL_VERSION, FRAME_CONNECT_RESPONSE];
                bincode::serialize_into(&mut out, response)?;
                Ok(out)
            }
        }
    }

    pub fn decode(raw: &[u8]) -> Result<Self> {
        let [version, frame_type, body @ ..] = raw else {
            return Err(anyhow!("truncated overlay frame ({} bytes)", raw.len()));
        };
        if *version != OVERLAY_PROTOCOL_VERSION {
            return Err(anyhow!("unsupported overlay protocol version {version}"));
        }
        match *frame_type {
            FRAME_SHRED => Ok(Self::Shred {
                payload: body.to_vec(),
            }),
            FRAME_PEER_ADVERTISEMENT => Ok(Self::PeerAdvertisement {
                advert: bincode::deserialize(body)?,
            }),
            FRAME_ADDRESS_OBSERVATION => Ok(Self::AddressObservation {
                observed: bincode::deserialize(body)?,
            }),
            FRAME_DIALBACK_REQUEST => {
                let (nonce, probe_port) = bincode::deserialize(body)?;
                Ok(Self::DialBackRequest { nonce, probe_port })
            }
            FRAME_DIALBACK_RESULT => {
                let (nonce, ok) = bincode::deserialize(body)?;
                Ok(Self::DialBackResult { nonce, ok })
            }
            FRAME_CONNECT_REQUEST => Ok(Self::ConnectRequest {
                request: bincode::deserialize(body)?,
            }),
            FRAME_CONNECT_RESPONSE => Ok(Self::ConnectResponse {
                response: bincode::deserialize(body)?,
            }),
            other => Err(anyhow!("unknown overlay frame type {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use arrayvec::ArrayVec;
    use solana_sdk::{signature::Keypair, signer::Signer};

    use super::*;
    use crate::overlay::gossip::{PeerAdvert, Reachability, RepairEndpoint};

    #[test]
    fn shred_frame_overhead_is_two_bytes() {
        let payload = vec![7u8; 1228];
        let raw = OverlayFrame::shred(payload.clone()).encode().unwrap();
        assert_eq!(raw.len(), payload.len() + SHRED_FRAME_OVERHEAD);
        match OverlayFrame::decode(&raw).unwrap() {
            OverlayFrame::Shred { payload: got } => assert_eq!(got, payload),
            other => panic!("decoded wrong frame: {other:?}"),
        }
    }

    #[test]
    fn advert_roundtrips_and_stays_small() {
        let keypair = Keypair::new();
        let mut addrs = ArrayVec::new();
        addrs.push("203.0.113.7:65410".parse().unwrap());
        let advert = PeerAdvert {
            pubkey: keypair.pubkey(),
            advert_seq: 42,
            ttl_ms: 30_000,
            reachability: Reachability::Direct(addrs),
            repair: RepairEndpoint::Udp("203.0.113.7:65411".parse().unwrap()),
        };
        let signed = SignedPeerAdvert::sign(advert.clone(), &keypair).unwrap();
        let raw = OverlayFrame::peer_advertisement(signed).encode().unwrap();
        assert!(raw.len() < 300, "advert frame unexpectedly large: {}", raw.len());
        match OverlayFrame::decode(&raw).unwrap() {
            OverlayFrame::PeerAdvertisement { advert: got } => {
                assert!(got.verify());
                assert_eq!(got.advert, advert);
            }
            other => panic!("decoded wrong frame: {other:?}"),
        }
    }

    #[test]
    fn p3_control_frames_roundtrip_and_stay_tiny() {
        // Address observation and dial-back frames are datagrams and must sit
        // far under the 1242-byte budget (nat-traversal.md §6.2/§6.2.3).
        let observed: SocketAddr = "198.51.100.7:40000".parse().unwrap();
        let obs = OverlayFrame::address_observation(observed).encode().unwrap();
        assert!(obs.len() < 32, "observation frame too large: {}", obs.len());
        match OverlayFrame::decode(&obs).unwrap() {
            OverlayFrame::AddressObservation { observed: got } => assert_eq!(got, observed),
            other => panic!("decoded wrong frame: {other:?}"),
        }

        for probe_port in [None, Some(51_000u16)] {
            let req = OverlayFrame::dialback_request(0xDEAD_BEEF, probe_port)
                .encode()
                .unwrap();
            assert!(req.len() < 16);
            match OverlayFrame::decode(&req).unwrap() {
                OverlayFrame::DialBackRequest { nonce, probe_port: got } => {
                    assert_eq!((nonce, got), (0xDEAD_BEEF, probe_port));
                }
                other => panic!("decoded wrong frame: {other:?}"),
            }
        }

        for ok in [true, false] {
            let res = OverlayFrame::dialback_result(7, ok).encode().unwrap();
            assert!(res.len() < 16);
            match OverlayFrame::decode(&res).unwrap() {
                OverlayFrame::DialBackResult { nonce, ok: got } => {
                    assert_eq!((nonce, got), (7, ok));
                }
                other => panic!("decoded wrong frame: {other:?}"),
            }
        }
    }

    #[test]
    fn rejects_wrong_version_unknown_type_and_truncation() {
        let mut raw = OverlayFrame::shred(vec![1, 2, 3]).encode().unwrap();
        raw[0] = OVERLAY_PROTOCOL_VERSION + 1;
        assert!(OverlayFrame::decode(&raw).is_err());
        raw[0] = OVERLAY_PROTOCOL_VERSION;
        raw[1] = 200;
        assert!(OverlayFrame::decode(&raw).is_err());
        assert!(OverlayFrame::decode(&[OVERLAY_PROTOCOL_VERSION]).is_err());
        assert!(OverlayFrame::decode(&[]).is_err());
    }
}

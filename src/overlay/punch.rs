//! P5 hole-punch wire primitives (nat-traversal.md §6.5).
//!
//! Punch probes deliberately do not travel inside QUIC. They share the
//! overlay UDP socket, but their first byte has the QUIC fixed bit clear, so
//! `OverlayQuicTransport` can demultiplex them before handing a datagram to
//! quinn-proto. The nonce selects a bounded negotiated session and the
//! Ed25519 signature authenticates a peer-reflexive source before it can
//! replace a candidate.

use anyhow::{Result, anyhow};
use arrayvec::ArrayVec;
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    signer::Signer,
};

use super::nat::{AllocatorProfile, NatClass};

/// The first byte intentionally has QUIC's fixed bit (`0x40`) clear. The
/// remaining magic protects the transport from treating arbitrary non-QUIC
/// traffic as a punch probe.
pub const PUNCH_PROBE_MAGIC: [u8; 4] = [0x21, b'L', b'B', b'P'];
pub const PUNCH_PROBE_VERSION: u8 = 1;

/// NAT knowledge carried in the signed ConnectRequest/ConnectResponse. It is
/// an optimization hint only: an unknown profile falls back to the plain
/// same-socket punch, never to a correctness-critical path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatProfile {
    pub class: Option<NatClass>,
    pub allocator: Option<AllocatorProfile>,
    /// Explicitly opt-in capability for the bounded birthday volley. The
    /// peer must see this signed bit before it emits a high-port spray.
    pub birthday_punch: bool,
    /// Current observed external IP. A change is a new NAT generation and
    /// invalidates the peer-pair outcome cache (§6.5.1 rung 4).
    pub generation: Option<std::net::IpAddr>,
}

/// Candidate capacity matches the advert's `Reachability` bound. Keeping it
/// in the signed envelope means a via never has to trust or synthesize a
/// destination address.
pub const MAX_PUNCH_CANDIDATES: usize = 4;

/// Signed origin envelope for a P5 ConnectRequest. The frame itself travels
/// over authenticated overlay QUIC, but a `via` forwards it, so the target
/// must verify the initiator independently.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub nonce: u64,
    pub origin: Pubkey,
    pub target: Pubkey,
    pub candidates: ArrayVec<std::net::SocketAddr, MAX_PUNCH_CANDIDATES>,
    pub nat_profile: NatProfile,
    pub signature: Signature,
}

/// Signed answer from the target. `target` means the initiator to which a via
/// must route the response; `origin` is the answering peer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectResponse {
    pub nonce: u64,
    pub origin: Pubkey,
    pub target: Pubkey,
    pub candidates: ArrayVec<std::net::SocketAddr, MAX_PUNCH_CANDIDATES>,
    pub nat_profile: NatProfile,
    pub signature: Signature,
}

fn request_signing_bytes(
    nonce: u64,
    origin: Pubkey,
    target: Pubkey,
    candidates: &ArrayVec<std::net::SocketAddr, MAX_PUNCH_CANDIDATES>,
    nat_profile: NatProfile,
) -> Result<Vec<u8>> {
    Ok(bincode::serialize(&(nonce, origin, target, candidates, nat_profile))?)
}

fn response_signing_bytes(
    nonce: u64,
    origin: Pubkey,
    target: Pubkey,
    candidates: &ArrayVec<std::net::SocketAddr, MAX_PUNCH_CANDIDATES>,
    nat_profile: NatProfile,
) -> Result<Vec<u8>> {
    Ok(bincode::serialize(&(nonce, origin, target, candidates, nat_profile))?)
}

impl ConnectRequest {
    pub fn sign(
        nonce: u64,
        target: Pubkey,
        candidates: ArrayVec<std::net::SocketAddr, MAX_PUNCH_CANDIDATES>,
        nat_profile: NatProfile,
        keypair: &Keypair,
    ) -> Result<Self> {
        let origin = keypair.pubkey();
        let signature = keypair.sign_message(&request_signing_bytes(
            nonce,
            origin,
            target,
            &candidates,
            nat_profile,
        )?);
        Ok(Self {
            nonce,
            origin,
            target,
            candidates,
            nat_profile,
            signature,
        })
    }

    pub fn verify(&self) -> bool {
        request_signing_bytes(
            self.nonce,
            self.origin,
            self.target,
            &self.candidates,
            self.nat_profile,
        )
        .map(|bytes| self.signature.verify(self.origin.as_ref(), &bytes))
        .unwrap_or(false)
    }
}

impl ConnectResponse {
    pub fn sign(
        nonce: u64,
        target: Pubkey,
        candidates: ArrayVec<std::net::SocketAddr, MAX_PUNCH_CANDIDATES>,
        nat_profile: NatProfile,
        keypair: &Keypair,
    ) -> Result<Self> {
        let origin = keypair.pubkey();
        let signature = keypair.sign_message(&response_signing_bytes(
            nonce,
            origin,
            target,
            &candidates,
            nat_profile,
        )?);
        Ok(Self {
            nonce,
            origin,
            target,
            candidates,
            nat_profile,
            signature,
        })
    }

    pub fn verify(&self) -> bool {
        response_signing_bytes(
            self.nonce,
            self.origin,
            self.target,
            &self.candidates,
            self.nat_profile,
        )
        .map(|bytes| self.signature.verify(self.origin.as_ref(), &bytes))
        .unwrap_or(false)
    }
}

/// A raw, signed same-socket probe. The nonce is negotiated over authenticated
/// overlay connections; the signature makes the source identity explicit so a
/// via peer (or an off-path sender) cannot install an unauthenticated prflx
/// candidate merely by learning the nonce.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PunchProbe {
    pub nonce: u64,
    pub origin: Pubkey,
    pub signature: Signature,
}

impl PunchProbe {
    fn signing_bytes(nonce: u64, origin: Pubkey) -> [u8; 40] {
        let mut bytes = [0u8; 40];
        bytes[..8].copy_from_slice(&nonce.to_le_bytes());
        bytes[8..].copy_from_slice(origin.as_ref());
        bytes
    }

    pub fn sign(nonce: u64, keypair: &Keypair) -> Self {
        let origin = keypair.pubkey();
        Self {
            nonce,
            origin,
            signature: keypair.sign_message(&Self::signing_bytes(nonce, origin)),
        }
    }

    pub fn verify(&self) -> bool {
        self.signature
            .verify(self.origin.as_ref(), &Self::signing_bytes(self.nonce, self.origin))
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(4 + 1 + 128);
        out.extend_from_slice(&PUNCH_PROBE_MAGIC);
        out.push(PUNCH_PROBE_VERSION);
        bincode::serialize_into(&mut out, self)?;
        Ok(out)
    }

    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() < PUNCH_PROBE_MAGIC.len() + 1
            || raw[..PUNCH_PROBE_MAGIC.len()] != PUNCH_PROBE_MAGIC
        {
            return Err(anyhow!("not a Lightbringer punch probe"));
        }
        if raw[PUNCH_PROBE_MAGIC.len()] != PUNCH_PROBE_VERSION {
            return Err(anyhow!("unsupported punch probe version"));
        }
        Ok(bincode::deserialize(&raw[PUNCH_PROBE_MAGIC.len() + 1..])?)
    }

    pub fn looks_like(raw: &[u8]) -> bool {
        raw.len() >= PUNCH_PROBE_MAGIC.len()
            && raw[..PUNCH_PROBE_MAGIC.len()] == PUNCH_PROBE_MAGIC
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_probe_is_non_quic_signed_and_roundtrips() {
        let keypair = Keypair::new();
        let raw = PunchProbe::sign(0xDEAD_BEEF, &keypair).encode().unwrap();
        assert_eq!(raw[0] & 0x40, 0, "QUIC fixed bit must stay clear");
        let decoded = PunchProbe::decode(&raw).unwrap();
        assert!(decoded.verify());
        assert_eq!(decoded.origin, keypair.pubkey());
    }

    #[test]
    fn malformed_or_tampered_probe_is_inert() {
        assert!(!PunchProbe::looks_like(&[0x40, b'L', b'B', b'P']));
        assert!(PunchProbe::decode(&PUNCH_PROBE_MAGIC).is_err());
        let keypair = Keypair::new();
        let mut raw = PunchProbe::sign(7, &keypair).encode().unwrap();
        *raw.last_mut().unwrap() ^= 1;
        let decoded = PunchProbe::decode(&raw).unwrap();
        assert!(!decoded.verify());
    }

    #[test]
    fn signaling_envelopes_bind_origin_target_candidates_and_profile() {
        let origin = Keypair::new();
        let target = Keypair::new().pubkey();
        let mut candidates = ArrayVec::new();
        candidates.push("198.51.100.8:51000".parse().unwrap());
        let request = ConnectRequest::sign(
            9,
            target,
            candidates,
            NatProfile {
                class: Some(NatClass::PortDependent),
                allocator: Some(AllocatorProfile::Sequential { stride: 1 }),
                birthday_punch: false,
                generation: Some("198.51.100.8".parse().unwrap()),
            },
            &origin,
        )
        .unwrap();
        assert!(request.verify());
        let mut tampered = request;
        tampered.target = Keypair::new().pubkey();
        assert!(!tampered.verify());
    }
}

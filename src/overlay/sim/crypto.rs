//! Seed-derived crypto plumbing for low-seam determinism (nat-traversal.md
//! §6.9): node keypairs derive from the run seed, quinn's endpoint RNG and
//! connection-id generation are seeded through `TransportOptions`, the
//! stateless-reset key is deterministic, and rustls runs with a custom
//! `CryptoProvider` whose `SecureRandom` is seed-driven. The one entropy
//! source outside these seams is ring's internal ECDHE key generation
//! (`rustls::crypto::SecureRandom` documents that kx randomness is
//! provider-internal), which changes ciphertext bytes but not packet
//! counts, sizes, or timing — see `trace.rs`.

use std::sync::{Arc, Mutex};

use rand::{RngCore, SeedableRng, rngs::StdRng};
use rustls::crypto::{CryptoProvider, GetRandomFailed, SecureRandom};
use solana_entry::entry::create_ticks;
use solana_ledger::shred::{ProcessShredsStats, ReedSolomonCache, Shredder};
use solana_sdk::{
    hash::Hash,
    signature::Keypair,
    signer::keypair::keypair_from_seed,
};

/// Deterministic 32 bytes for `(seed, host, label)`.
pub fn derive_bytes(seed: u64, host: u32, label: &str) -> [u8; 32] {
    solana_sha256_hasher::hashv(&[
        b"overlay-sim",
        &seed.to_le_bytes(),
        &host.to_le_bytes(),
        label.as_bytes(),
    ])
    .to_bytes()
}

pub fn derive_u64(seed: u64, host: u32, label: &str) -> u64 {
    u64::from_le_bytes(derive_bytes(seed, host, label)[..8].try_into().unwrap())
}

pub fn derive_keypair(seed: u64, host: u32) -> Keypair {
    keypair_from_seed(&derive_bytes(seed, host, "keypair"))
        .expect("32-byte seed always yields a keypair")
}

struct SeededSecureRandom {
    rng: Mutex<StdRng>,
}

impl std::fmt::Debug for SeededSecureRandom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SeededSecureRandom")
    }
}

impl SecureRandom for SeededSecureRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        self.rng
            .lock()
            .map_err(|_| GetRandomFailed)?
            .fill_bytes(buf);
        Ok(())
    }
}

/// The ring provider with its `SecureRandom` replaced by a seeded generator.
/// `secure_random` needs a `'static` borrow, so one small allocation is
/// leaked per provider — one per simulated node per run.
pub fn seeded_provider(seed: u64, host: u32) -> Arc<CryptoProvider> {
    let random: &'static SeededSecureRandom = Box::leak(Box::new(SeededSecureRandom {
        rng: Mutex::new(StdRng::from_seed(derive_bytes(seed, host, "tls-random"))),
    }));
    Arc::new(CryptoProvider {
        secure_random: random,
        ..rustls::crypto::ring::default_provider()
    })
}

/// Deterministic HMAC-style key for quinn stateless-reset tokens. Sim-only:
/// a keyed SHA-256 is enough for reset-token generation determinism.
pub struct SeededResetKey {
    key: [u8; 32],
}

impl SeededResetKey {
    pub fn new(seed: u64, host: u32) -> Self {
        Self {
            key: derive_bytes(seed, host, "reset-key"),
        }
    }

    fn digest(&self, data: &[u8]) -> [u8; 32] {
        solana_sha256_hasher::hashv(&[&self.key, data]).to_bytes()
    }
}

impl quinn_proto::crypto::HmacKey for SeededResetKey {
    fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
        signature_out.copy_from_slice(&self.digest(data));
    }

    fn signature_len(&self) -> usize {
        32
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), quinn_proto::crypto::CryptoError> {
        if self.digest(data).as_slice() == signature {
            Ok(())
        } else {
            Err(quinn_proto::crypto::CryptoError)
        }
    }
}

/// Real synthetic shreds: seed-derived leader keypair, deterministic tick
/// entries, real merkle shredding + Ed25519 signatures. Returns data-shred
/// payloads ready to inject as overlay source packets.
pub fn make_signed_shreds(seed: u64, slot: u64, shred_version: u16) -> Vec<Vec<u8>> {
    let leader = derive_keypair(seed, u32::MAX);
    let start_hash = Hash::new_from_array(derive_bytes(seed, slot as u32, "entry-hash"));
    let entries = create_ticks(8, 1, start_hash);
    let shredder =
        Shredder::new(slot, slot.saturating_sub(1), 0, shred_version).expect("valid slot pair");
    shredder
        .make_merkle_shreds_from_entries(
            &leader,
            &entries,
            true,
            Hash::default(),
            0,
            0,
            &ReedSolomonCache::default(),
            &mut ProcessShredsStats::default(),
        )
        .filter(|shred| shred.is_data())
        .map(|shred| shred.payload().as_ref().to_vec())
        .collect()
}

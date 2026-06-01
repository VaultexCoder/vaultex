use std::time::{SystemTime, UNIX_EPOCH};

use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;

use crate::errors::{CryptoError, Result};
use crate::identity::IdentityKeyPair;

/// Recommended signed prekey rotation interval: 7 days (in seconds).
pub const SIGNED_PREKEY_ROTATION_INTERVAL: u64 = 7 * 24 * 60 * 60;

/// Grace period for retaining the old signed prekey after rotation: 24 hours.
pub const SIGNED_PREKEY_GRACE_PERIOD: u64 = 24 * 60 * 60;

/// Minimum number of one-time prekeys before replenishment is triggered.
pub const MIN_ONE_TIME_PREKEYS: u32 = 10;

/// Number of one-time prekeys to generate per replenishment batch.
pub const ONE_TIME_PREKEY_BATCH_SIZE: u32 = 50;

/// Check if a signed prekey needs rotation based on its creation timestamp.
///
/// Returns `true` if the key is older than `max_age_secs`.
#[allow(clippy::expect_used)] // SystemTime::duration_since cannot fail unless the clock is set before 1970, which is unrecoverable
pub fn needs_rotation(created_at: u64, max_age_secs: u64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs();
    now.saturating_sub(created_at) >= max_age_secs
}

/// Returns the current Unix timestamp in seconds.
#[allow(clippy::expect_used)] // SystemTime::duration_since cannot fail unless the clock is set before 1970, which is unrecoverable
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}

/// A signed prekey: an X25519 keypair signed by the identity key.
pub struct SignedPreKey {
    pub prekey_id: u32,
    pub public_key: box_::PublicKey,
    secret_key: box_::SecretKey,
    pub signature: sign::Signature,
}

impl SignedPreKey {
    /// Generate a new signed prekey, signed by the given identity key.
    #[must_use = "prekey generation result must be checked for initialization failure"]
    pub fn generate(identity: &IdentityKeyPair, prekey_id: u32) -> Result<Self> {
        sodiumoxide::init().map_err(|_| CryptoError::InitFailed)?;
        let (pk, sk) = box_::gen_keypair();
        debug_assert!(
            pk.0.iter().any(|&b| b != 0),
            "generated prekey public key is all zeros — CSPRNG failure"
        );
        let signature = identity.sign(&pk.0);
        Ok(Self {
            prekey_id,
            public_key: pk,
            secret_key: sk,
            signature,
        })
    }

    pub fn secret_key(&self) -> &box_::SecretKey {
        &self.secret_key
    }

    /// Verify this prekey's signature against an identity public key.
    pub fn verify(&self, identity_key: &sign::PublicKey) -> bool {
        sign::verify_detached(&self.signature, &self.public_key.0, identity_key)
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key.0)
    }

    pub fn signature_hex(&self) -> String {
        hex::encode(self.signature.as_ref())
    }

    /// Reconstruct a SignedPreKey from raw byte slices (for database restoration).
    pub fn from_bytes(
        prekey_id: u32,
        public_key: &[u8],
        secret_key: &[u8],
        signature: &[u8],
    ) -> Result<Self> {
        let pk = box_::PublicKey::from_slice(public_key).ok_or(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: public_key.len(),
        })?;
        let sk = box_::SecretKey::from_slice(secret_key).ok_or(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: secret_key.len(),
        })?;
        let sig =
            sign::Signature::from_bytes(signature).map_err(|_| CryptoError::InvalidKeyLength {
                expected: 64,
                actual: signature.len(),
            })?;
        Ok(Self {
            prekey_id,
            public_key: pk,
            secret_key: sk,
            signature: sig,
        })
    }
}

impl Drop for SignedPreKey {
    fn drop(&mut self) {
        // Use sodiumoxide's memzero for defense in depth — guaranteed not to be
        // optimized away by the compiler, unlike a plain zeroing loop.
        sodiumoxide::utils::memzero(&mut self.secret_key.0);
    }
}

/// A one-time prekey: a single-use X25519 keypair.
pub struct OneTimePreKey {
    pub prekey_id: u32,
    pub public_key: box_::PublicKey,
    secret_key: box_::SecretKey,
}

impl OneTimePreKey {
    #[must_use = "prekey generation result must be checked for initialization failure"]
    pub fn generate(prekey_id: u32) -> Result<Self> {
        sodiumoxide::init().map_err(|_| CryptoError::InitFailed)?;
        let (pk, sk) = box_::gen_keypair();
        debug_assert!(
            pk.0.iter().any(|&b| b != 0),
            "generated one-time prekey public key is all zeros — CSPRNG failure"
        );
        Ok(Self {
            prekey_id,
            public_key: pk,
            secret_key: sk,
        })
    }

    pub fn secret_key(&self) -> &box_::SecretKey {
        &self.secret_key
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key.0)
    }

    /// Reconstruct a OneTimePreKey from raw byte slices (for database restoration).
    pub fn from_bytes(prekey_id: u32, public_key: &[u8], secret_key: &[u8]) -> Result<Self> {
        let pk = box_::PublicKey::from_slice(public_key).ok_or(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: public_key.len(),
        })?;
        let sk = box_::SecretKey::from_slice(secret_key).ok_or(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: secret_key.len(),
        })?;
        Ok(Self {
            prekey_id,
            public_key: pk,
            secret_key: sk,
        })
    }
}

impl Drop for OneTimePreKey {
    fn drop(&mut self) {
        // Use sodiumoxide's memzero for defense in depth — guaranteed not to be
        // optimized away by the compiler, unlike a plain zeroing loop.
        sodiumoxide::utils::memzero(&mut self.secret_key.0);
    }
}

/// Generate a batch of one-time prekeys.
#[must_use = "prekey generation result must be checked for initialization failure"]
pub fn generate_one_time_prekeys(count: u32, starting_id: u32) -> Result<Vec<OneTimePreKey>> {
    let mut prekeys = Vec::with_capacity(count as usize);
    for i in 0..count {
        prekeys.push(OneTimePreKey::generate(starting_id + i)?);
    }
    Ok(prekeys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_prekey_generation_and_verify() {
        let identity = IdentityKeyPair::generate().unwrap();
        let spk = SignedPreKey::generate(&identity, 1).unwrap();

        assert!(spk.verify(&identity.public_key));
        assert_eq!(spk.prekey_id, 1);
    }

    #[test]
    fn test_signed_prekey_rejects_wrong_identity() {
        let identity = IdentityKeyPair::generate().unwrap();
        let other = IdentityKeyPair::generate().unwrap();
        let spk = SignedPreKey::generate(&identity, 1).unwrap();

        assert!(!spk.verify(&other.public_key));
    }

    #[test]
    fn test_one_time_prekey_generation() {
        let otpk = OneTimePreKey::generate(42).unwrap();
        assert_eq!(otpk.prekey_id, 42);
        assert_eq!(otpk.public_key_hex().len(), 64);
    }

    #[test]
    fn test_batch_generation() {
        let prekeys = generate_one_time_prekeys(10, 100).unwrap();
        assert_eq!(prekeys.len(), 10);
        for (i, pk) in prekeys.iter().enumerate() {
            assert_eq!(pk.prekey_id, 100 + i as u32);
        }
    }

    #[test]
    fn test_needs_rotation_fresh_key() {
        let now = current_timestamp();
        // A key created just now should not need rotation
        assert!(!needs_rotation(now, SIGNED_PREKEY_ROTATION_INTERVAL));
    }

    #[test]
    fn test_needs_rotation_expired_key() {
        let now = current_timestamp();
        // A key created 8 days ago should need rotation (interval is 7 days)
        let eight_days_ago = now - (8 * 24 * 60 * 60);
        assert!(needs_rotation(
            eight_days_ago,
            SIGNED_PREKEY_ROTATION_INTERVAL
        ));
    }

    #[test]
    fn test_needs_rotation_exactly_at_boundary() {
        let now = current_timestamp();
        // A key created exactly at the rotation interval should need rotation
        let at_boundary = now - SIGNED_PREKEY_ROTATION_INTERVAL;
        assert!(needs_rotation(at_boundary, SIGNED_PREKEY_ROTATION_INTERVAL));
    }

    #[test]
    fn test_rotation_generates_different_key() {
        let identity = IdentityKeyPair::generate().unwrap();
        let spk1 = SignedPreKey::generate(&identity, 1).unwrap();
        let spk2 = SignedPreKey::generate(&identity, 2).unwrap();

        // New key should have a different ID
        assert_ne!(spk1.prekey_id, spk2.prekey_id);
        // Public keys should differ (different random keypairs)
        assert_ne!(spk1.public_key, spk2.public_key);
        // Both should verify against the same identity
        assert!(spk1.verify(&identity.public_key));
        assert!(spk2.verify(&identity.public_key));
    }

    #[test]
    fn test_replenishment_batch_size() {
        let prekeys = generate_one_time_prekeys(ONE_TIME_PREKEY_BATCH_SIZE, 200).unwrap();
        assert_eq!(prekeys.len(), ONE_TIME_PREKEY_BATCH_SIZE as usize);
    }

    #[test]
    fn test_constants_are_sensible() {
        assert_eq!(SIGNED_PREKEY_ROTATION_INTERVAL, 604800); // 7 days in seconds
        assert_eq!(SIGNED_PREKEY_GRACE_PERIOD, 86400); // 24 hours in seconds
        const _: () = assert!(MIN_ONE_TIME_PREKEYS < ONE_TIME_PREKEY_BATCH_SIZE);
    }
}

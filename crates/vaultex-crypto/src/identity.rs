use sodiumoxide::crypto::sign;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::{CryptoError, Result};

/// An Ed25519 signing keypair used as a long-term identity key.
///
/// The secret key is zeroized on drop to prevent leaking key material.
pub struct IdentityKeyPair {
    pub public_key: sign::PublicKey,
    secret_key: SecretKeyWrapper,
}

/// Wrapper around the Ed25519 secret key that implements Zeroize.
struct SecretKeyWrapper {
    inner: sign::SecretKey,
}

impl Zeroize for SecretKeyWrapper {
    fn zeroize(&mut self) {
        // SecretKey contains a [u8; 64] — overwrite in place.
        let bytes = &mut self.inner.0;
        bytes.zeroize();
    }
}

impl Drop for SecretKeyWrapper {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SecretKeyWrapper {}

impl IdentityKeyPair {
    /// Generates a new random Ed25519 identity keypair.
    #[must_use = "key generation result must be checked for initialization failure"]
    pub fn generate() -> Result<Self> {
        sodiumoxide::init().map_err(|_| CryptoError::InitFailed)?;
        let (pk, sk) = sign::gen_keypair();
        debug_assert!(
            pk.0.iter().any(|&b| b != 0),
            "generated public key is all zeros — CSPRNG failure"
        );
        debug_assert!(
            sk.0.iter().any(|&b| b != 0),
            "generated secret key is all zeros — CSPRNG failure"
        );
        Ok(Self {
            public_key: pk,
            secret_key: SecretKeyWrapper { inner: sk },
        })
    }

    /// Creates an IdentityKeyPair from existing raw key bytes.
    #[must_use = "key construction result must be checked for invalid key length"]
    pub fn from_bytes(public_key: &[u8], secret_key: &[u8]) -> Result<Self> {
        let pk = sign::PublicKey::from_slice(public_key).ok_or(CryptoError::InvalidKeyLength {
            expected: sign::PUBLICKEYBYTES,
            actual: public_key.len(),
        })?;
        let sk = sign::SecretKey::from_slice(secret_key).ok_or(CryptoError::InvalidKeyLength {
            expected: sign::SECRETKEYBYTES,
            actual: secret_key.len(),
        })?;
        Ok(Self {
            public_key: pk,
            secret_key: SecretKeyWrapper { inner: sk },
        })
    }

    /// Signs a message with this identity's secret key.
    pub fn sign(&self, message: &[u8]) -> sign::Signature {
        sign::sign_detached(message, &self.secret_key.inner)
    }

    /// Returns a reference to the secret key (for internal use in X3DH, etc.).
    pub(crate) fn secret_key(&self) -> &sign::SecretKey {
        &self.secret_key.inner
    }

    /// Returns the secret key bytes for secure persistence (e.g., SQLCipher storage).
    /// The caller is responsible for zeroizing the returned bytes after use.
    pub fn secret_key_bytes(&self) -> [u8; 64] {
        self.secret_key.inner.0
    }

    /// Verifies a signature against a public key and message.
    pub fn verify(
        public_key: &sign::PublicKey,
        message: &[u8],
        signature: &sign::Signature,
    ) -> bool {
        sign::verify_detached(signature, message, public_key)
    }

    /// Returns a human-readable fingerprint of the public key.
    ///
    /// Format: "7F3A·C291·08BE·4D12" (first 8 bytes, grouped in pairs, separated by
    /// middle-dot).
    pub fn public_key_fingerprint(&self) -> String {
        let bytes = &self.public_key.0;
        let groups: Vec<String> = bytes[..8]
            .chunks(2)
            .map(|chunk| format!("{:02X}{:02X}", chunk[0], chunk[1]))
            .collect();
        groups.join("\u{00B7}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_sign_verify() {
        let identity = IdentityKeyPair::generate().unwrap();
        let message = b"hello, vaultex!";
        let signature = identity.sign(message);

        assert!(IdentityKeyPair::verify(
            &identity.public_key,
            message,
            &signature
        ));
    }

    #[test]
    fn test_verify_rejects_wrong_message() {
        let identity = IdentityKeyPair::generate().unwrap();
        let signature = identity.sign(b"correct message");

        assert!(!IdentityKeyPair::verify(
            &identity.public_key,
            b"wrong message",
            &signature
        ));
    }

    #[test]
    fn test_verify_rejects_wrong_key() {
        let alice = IdentityKeyPair::generate().unwrap();
        let bob = IdentityKeyPair::generate().unwrap();
        let message = b"hello";
        let signature = alice.sign(message);

        assert!(!IdentityKeyPair::verify(
            &bob.public_key,
            message,
            &signature
        ));
    }

    #[test]
    fn test_fingerprint_format() {
        let identity = IdentityKeyPair::generate().unwrap();
        let fp = identity.public_key_fingerprint();

        // Should be 4 groups of 4 hex chars separated by middle-dot
        let parts: Vec<&str> = fp.split('\u{00B7}').collect();
        assert_eq!(parts.len(), 4);
        for part in &parts {
            assert_eq!(part.len(), 4);
            assert!(part.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let original = IdentityKeyPair::generate().unwrap();
        let pk_bytes = original.public_key.0;
        let sk_bytes = original.secret_key.inner.0;

        let restored = IdentityKeyPair::from_bytes(&pk_bytes, &sk_bytes).unwrap();
        assert_eq!(original.public_key, restored.public_key);

        // Verify signing still works after reconstruction
        let msg = b"roundtrip test";
        let sig = restored.sign(msg);
        assert!(IdentityKeyPair::verify(&restored.public_key, msg, &sig));
    }

    #[test]
    fn test_from_bytes_invalid_length() {
        let result = IdentityKeyPair::from_bytes(&[0u8; 16], &[0u8; 64]);
        assert!(result.is_err());
    }
}

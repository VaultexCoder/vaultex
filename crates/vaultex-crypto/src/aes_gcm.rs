use sodiumoxide::crypto::aead::xchacha20poly1305_ietf as aead;
use zeroize::Zeroize;

use crate::errors::{CryptoError, Result};

// AES-256-GCM-equivalent authenticated encryption using XChaCha20-Poly1305 (via sodiumoxide).
//
// sodiumoxide does not expose AES-GCM directly; XChaCha20-Poly1305 is the recommended
// AEAD construction in libsodium and provides equivalent security guarantees with a
// larger nonce space (192-bit), eliminating nonce-reuse concerns for random nonces.

/// Encrypts `plaintext` with the given 256-bit `key` and optional `associated_data`.
///
/// Returns `(nonce, ciphertext)` where the nonce is randomly generated.
#[must_use = "encryption result must be used; dropping it silently discards the ciphertext"]
pub fn encrypt(
    key: &[u8; 32],
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    sodiumoxide::init().map_err(|_| CryptoError::InitFailed)?;

    let aead_key = aead::Key::from_slice(key).ok_or(CryptoError::InvalidKeyLength {
        expected: aead::KEYBYTES,
        actual: key.len(),
    })?;
    let nonce = aead::gen_nonce();
    let ciphertext = aead::seal(plaintext, associated_data, &nonce, &aead_key);

    Ok((nonce.0.to_vec(), ciphertext))
}

/// Decrypts `ciphertext` with the given 256-bit `key`, `nonce`, and optional `associated_data`.
///
/// Returns the plaintext on success. Fails if authentication tag verification fails.
#[must_use = "decryption result must be checked for authentication failure"]
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let aead_key = aead::Key::from_slice(key).ok_or(CryptoError::InvalidKeyLength {
        expected: aead::KEYBYTES,
        actual: key.len(),
    })?;
    let aead_nonce = aead::Nonce::from_slice(nonce).ok_or(CryptoError::InvalidKeyLength {
        expected: aead::NONCEBYTES,
        actual: nonce.len(),
    })?;

    let plaintext = aead::open(ciphertext, associated_data, &aead_nonce, &aead_key)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    // The caller should zeroize the plaintext after use; we return ownership.
    Ok(plaintext)
}

/// A wrapper that holds an encryption key and zeroizes it on drop.
pub struct EncryptionKey {
    key: [u8; 32],
}

impl EncryptionKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    #[must_use = "key construction result must be checked for invalid key length"]
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: slice.len(),
            });
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(slice);
        Ok(Self { key })
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    #[must_use = "encryption result must be used"]
    pub fn encrypt(&self, plaintext: &[u8], ad: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>)> {
        encrypt(&self.key, plaintext, ad)
    }

    #[must_use = "decryption result must be checked for authentication failure"]
    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], ad: Option<&[u8]>) -> Result<Vec<u8>> {
        decrypt(&self.key, nonce, ciphertext, ad)
    }
}

impl Zeroize for EncryptionKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"secret message for vaultex";
        let ad = b"associated data";

        let (nonce, ciphertext) = encrypt(&key, plaintext, Some(ad)).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, Some(ad)).unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_fails_with_wrong_key() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let plaintext = b"hello";

        let (nonce, ciphertext) = encrypt(&key, plaintext, None).unwrap();
        let result = decrypt(&wrong_key, &nonce, &ciphertext, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_fails_with_wrong_ad() {
        let key = [0x42u8; 32];
        let plaintext = b"hello";

        let (nonce, ciphertext) = encrypt(&key, plaintext, Some(b"correct ad")).unwrap();
        let result = decrypt(&key, &nonce, &ciphertext, Some(b"wrong ad"));

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_fails_with_tampered_ciphertext() {
        let key = [0x42u8; 32];
        let plaintext = b"hello";

        let (nonce, mut ciphertext) = encrypt(&key, plaintext, None).unwrap();
        ciphertext[0] ^= 0xFF; // flip bits
        let result = decrypt(&key, &nonce, &ciphertext, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_encryption_key_wrapper() {
        let ek = EncryptionKey::new([0x55u8; 32]);
        let plaintext = b"wrapped encryption";

        let (nonce, ct) = ek.encrypt(plaintext, None).unwrap();
        let pt = ek.decrypt(&nonce, &ct, None).unwrap();

        assert_eq!(&pt, plaintext);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0x42u8; 32];
        let (nonce, ciphertext) = encrypt(&key, b"", None).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, None).unwrap();
        assert!(decrypted.is_empty());
    }
}

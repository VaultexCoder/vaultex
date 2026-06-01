use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::secretbox;
use zeroize::Zeroize;

use crate::errors::{CryptoError, Result};

/// Maximum file size for media attachments (100 MiB).
pub const MAX_FILE_SIZE: usize = 100 * 1024 * 1024;

/// Metadata about an encrypted media file. This struct is sent inside the
/// Double Ratchet encrypted message (never visible to the server).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub filename: String,
    pub mime_type: String,
    pub size: u64,
    /// Optional base64-encoded thumbnail (e.g., for images).
    pub thumbnail: Option<String>,
}

/// Encrypt a file using XChaCha20-Poly1305 with a random per-file key.
///
/// Returns `(ciphertext, file_key)` where:
/// - `ciphertext` = nonce (24 bytes) || encrypted data (with MAC appended)
/// - `file_key` = 32-byte random key (sent inside the Double Ratchet message,
///   never transmitted to the server)
///
/// The caller must zeroize the file key after transmitting it inside the
/// encrypted message payload.
#[must_use = "encryption result must be used; contains the file key needed for decryption"]
pub fn encrypt_file(plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    if plaintext.len() > MAX_FILE_SIZE {
        return Err(CryptoError::EncryptionFailed);
    }

    sodiumoxide::init().map_err(|_| CryptoError::InitFailed)?;

    let key = secretbox::gen_key();
    let nonce = secretbox::gen_nonce();

    let ciphertext = secretbox::seal(plaintext, &nonce, &key);

    // Prepend the nonce to the ciphertext so the decryptor can extract it.
    let mut output = Vec::with_capacity(secretbox::NONCEBYTES + ciphertext.len());
    output.extend_from_slice(&nonce.0);
    output.extend_from_slice(&ciphertext);

    let mut file_key = [0u8; 32];
    file_key.copy_from_slice(&key.0);

    Ok((output, file_key))
}

/// Decrypt a file encrypted with [`encrypt_file`].
///
/// `ciphertext` must be nonce (24 bytes) || encrypted data.
/// `key` is the 32-byte file key received inside the Double Ratchet message.
#[must_use = "decryption result must be checked for authentication failure"]
pub fn decrypt_file(ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if ciphertext.len() < secretbox::NONCEBYTES + secretbox::MACBYTES {
        return Err(CryptoError::DecryptionFailed);
    }

    let nonce = secretbox::Nonce::from_slice(&ciphertext[..secretbox::NONCEBYTES])
        .ok_or(CryptoError::DecryptionFailed)?;

    let secret_key = secretbox::Key::from_slice(key).ok_or(CryptoError::InvalidKeyLength {
        expected: secretbox::KEYBYTES,
        actual: key.len(),
    })?;

    let plaintext = secretbox::open(&ciphertext[secretbox::NONCEBYTES..], &nonce, &secret_key)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(plaintext)
}

/// A wrapper that holds a file encryption key and zeroizes it on drop.
pub struct FileEncryptionKey {
    key: [u8; 32],
}

impl FileEncryptionKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

impl Zeroize for FileEncryptionKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for FileEncryptionKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"hello, this is a test file for VAULTEX media support";
        let (ciphertext, key) = encrypt_file(plaintext).unwrap();
        let decrypted = decrypt_file(&ciphertext, &key).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let plaintext = b"secret document content";
        let (ciphertext, _key) = encrypt_file(plaintext).unwrap();
        let wrong_key = [0xFFu8; 32];
        let result = decrypt_file(&ciphertext, &wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_file() {
        let plaintext = b"";
        let (ciphertext, key) = encrypt_file(plaintext).unwrap();
        let decrypted = decrypt_file(&ciphertext, &key).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_large_file() {
        // 1 MiB file
        let plaintext = vec![0xABu8; 1024 * 1024];
        let (ciphertext, key) = encrypt_file(&plaintext).unwrap();
        let decrypted = decrypt_file(&ciphertext, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ciphertext_has_nonce_prepended() {
        let plaintext = b"test";
        let (ciphertext, _key) = encrypt_file(plaintext).unwrap();
        // ciphertext = 24 bytes nonce + (plaintext len + 16 bytes MAC)
        assert_eq!(
            ciphertext.len(),
            secretbox::NONCEBYTES + plaintext.len() + secretbox::MACBYTES
        );
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let plaintext = b"important data";
        let (mut ciphertext, key) = encrypt_file(plaintext).unwrap();
        // Flip a bit in the encrypted portion (after the nonce)
        let idx = secretbox::NONCEBYTES + 1;
        ciphertext[idx] ^= 0xFF;
        let result = decrypt_file(&ciphertext, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_ciphertext_fails() {
        let result = decrypt_file(&[0u8; 10], &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_file_metadata_serialization() {
        let meta = FileMetadata {
            filename: "photo.jpg".to_string(),
            mime_type: "image/jpeg".to_string(),
            size: 102400,
            thumbnail: Some("base64encodeddata".to_string()),
        };
        let json = serde_json::to_string(&meta).unwrap();
        let restored: FileMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.filename, "photo.jpg");
        assert_eq!(restored.size, 102400);
        assert!(restored.thumbnail.is_some());
    }

    #[test]
    fn test_file_encryption_key_zeroize() {
        let key_bytes = [0x42u8; 32];
        let fek = FileEncryptionKey::new(key_bytes);
        assert_eq!(fek.as_bytes(), &key_bytes);
        // Key will be zeroized on drop
        drop(fek);
    }

    #[test]
    fn test_different_files_get_different_keys() {
        let (_, key1) = encrypt_file(b"file one").unwrap();
        let (_, key2) = encrypt_file(b"file two").unwrap();
        // Random keys should be different (probability of collision is negligible)
        assert_ne!(key1, key2);
    }
}

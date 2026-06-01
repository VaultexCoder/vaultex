use thiserror::Error;

/// Errors that can occur during cryptographic operations in VAULTEX.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("sodiumoxide initialization failed")]
    InitFailed,

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("HKDF expansion failed")]
    HkdfExpandFailed,

    #[error("encryption failed")]
    EncryptionFailed,

    #[error("decryption failed: ciphertext authentication failed")]
    DecryptionFailed,

    #[error("missing one-time prekey with id {0}")]
    MissingOneTimePreKey(u32),

    #[error("invalid prekey signature")]
    InvalidPreKeySignature,

    #[error("sealed sender: {0}")]
    SealedSenderError(String),

    #[error("ratchet error: {0}")]
    RatchetError(String),

    #[error("padding error: {0}")]
    PaddingError(String),

    #[error("serialization error: {0}")]
    SerializationError(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 16,
        };
        assert_eq!(err.to_string(), "invalid key length: expected 32, got 16");
    }

    #[test]
    fn test_missing_prekey_error() {
        let err = CryptoError::MissingOneTimePreKey(42);
        assert_eq!(err.to_string(), "missing one-time prekey with id 42");
    }
}

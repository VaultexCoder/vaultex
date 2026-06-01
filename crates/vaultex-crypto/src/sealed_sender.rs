use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sealedbox;

use crate::errors::{CryptoError, Result};

/// A sealed sender envelope hides the sender's identity from the server.
///
/// The sender's identity is encrypted under the recipient's public key using
/// libsodium's sealed box (anonymous authenticated encryption).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SealedSenderEnvelope {
    /// Sender identity encrypted to recipient (sealed box).
    pub encrypted_sender: Vec<u8>,
    /// The encrypted message payload.
    pub encrypted_message: Vec<u8>,
}

impl SealedSenderEnvelope {
    /// Seal a message: encrypt the sender's identity and the message body
    /// under the recipient's public key.
    ///
    /// The server cannot determine who sent the message.
    #[must_use = "sealed envelope result must be used"]
    pub fn seal(
        sender_identity_key_hex: &str,
        message: &[u8],
        recipient_public_key: &box_::PublicKey,
    ) -> Result<Vec<u8>> {
        sodiumoxide::init().map_err(|_| CryptoError::InitFailed)?;

        let encrypted_sender =
            sealedbox::seal(sender_identity_key_hex.as_bytes(), recipient_public_key);
        let encrypted_message = sealedbox::seal(message, recipient_public_key);

        let envelope = SealedSenderEnvelope {
            encrypted_sender,
            encrypted_message,
        };

        serde_json::to_vec(&envelope).map_err(|e| CryptoError::SealedSenderError(e.to_string()))
    }

    /// Unseal an envelope: decrypt sender identity and message body
    /// using the recipient's keypair.
    #[must_use = "unseal result must be checked for decryption failure"]
    pub fn unseal(
        envelope_bytes: &[u8],
        recipient_pk: &box_::PublicKey,
        recipient_sk: &box_::SecretKey,
    ) -> Result<(String, Vec<u8>)> {
        let envelope: SealedSenderEnvelope = serde_json::from_slice(envelope_bytes)
            .map_err(|e| CryptoError::SealedSenderError(e.to_string()))?;

        let sender_bytes = sealedbox::open(&envelope.encrypted_sender, recipient_pk, recipient_sk)
            .map_err(|_| {
                CryptoError::SealedSenderError("failed to decrypt sender identity".into())
            })?;

        let sender_hex = String::from_utf8(sender_bytes)
            .map_err(|e| CryptoError::SealedSenderError(e.to_string()))?;

        let message = sealedbox::open(&envelope.encrypted_message, recipient_pk, recipient_sk)
            .map_err(|_| CryptoError::SealedSenderError("failed to decrypt message".into()))?;

        Ok((sender_hex, message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_unseal_roundtrip() {
        sodiumoxide::init().unwrap();
        let (pk, sk) = box_::gen_keypair();
        let sender_hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let message = b"hello sealed sender";

        let envelope = SealedSenderEnvelope::seal(sender_hex, message, &pk).unwrap();
        let (recovered_sender, recovered_msg) =
            SealedSenderEnvelope::unseal(&envelope, &pk, &sk).unwrap();

        assert_eq!(recovered_sender, sender_hex);
        assert_eq!(recovered_msg, message);
    }

    #[test]
    fn test_unseal_fails_with_wrong_key() {
        sodiumoxide::init().unwrap();
        let (pk, _sk) = box_::gen_keypair();
        let (_pk2, sk2) = box_::gen_keypair();

        let envelope = SealedSenderEnvelope::seal("sender_key_hex", b"secret", &pk).unwrap();
        let result = SealedSenderEnvelope::unseal(&envelope, &pk, &sk2);
        assert!(result.is_err());
    }

    #[test]
    fn test_seal_hides_sender_from_server() {
        sodiumoxide::init().unwrap();
        let (pk, _sk) = box_::gen_keypair();

        let env1 = SealedSenderEnvelope::seal("sender_a", b"msg1", &pk).unwrap();
        let env2 = SealedSenderEnvelope::seal("sender_b", b"msg2", &pk).unwrap();

        // Envelopes should be different (randomized encryption)
        assert_ne!(env1, env2);
    }
}

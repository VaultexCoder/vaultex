//! Encrypted message payload structure.
//!
//! The `MessagePayload` wraps the plaintext content along with metadata
//! (such as self-destruct TTL) that is encrypted inside the Double Ratchet.
//! The server never sees any of these fields.

use serde::{Deserialize, Serialize};

use crate::padding;

/// Payload that gets encrypted inside the Double Ratchet ciphertext.
///
/// This structure is serialized to JSON before encryption, so all fields
/// are hidden from the server. The `ttl_seconds` field controls self-destruct:
/// once the recipient reads the message, a client-side timer starts and the
/// message is deleted after `ttl_seconds` have elapsed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MessagePayload {
    /// The plaintext message body.
    pub body: String,
    /// Optional self-destruct TTL in seconds. `None` means no self-destruct.
    /// When set, the recipient starts a timer on read and deletes the message
    /// after this many seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u32>,
}

impl MessagePayload {
    /// Create a new message payload without self-destruct.
    pub fn new(body: impl Into<String>) -> Self {
        Self {
            body: body.into(),
            ttl_seconds: None,
        }
    }

    /// Create a new message payload with a self-destruct TTL.
    pub fn with_ttl(body: impl Into<String>, ttl_seconds: u32) -> Self {
        Self {
            body: body.into(),
            ttl_seconds: Some(ttl_seconds),
        }
    }

    /// Serialize the payload to JSON bytes for encryption.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize a payload from JSON bytes after decryption.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Serialize the payload to padded bytes for encryption.
    ///
    /// The payload is first serialized to JSON, then padded to a power-of-2
    /// bucket size to prevent message-length analysis. This should be used
    /// instead of `to_bytes` when encrypting for the wire.
    pub fn to_padded_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let json = serde_json::to_vec(self)?;
        let padded = padding::pad_message(&json)?;
        Ok(padded)
    }

    /// Deserialize a payload from padded bytes after decryption.
    ///
    /// Removes padding first, then deserializes the JSON payload. This should
    /// be used instead of `from_bytes` when decrypting from the wire.
    pub fn from_padded_bytes(padded: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let unpadded = padding::unpad_message(padded)?;
        let payload = serde_json::from_slice(&unpadded)?;
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_without_ttl_roundtrip() {
        let payload = MessagePayload::new("hello");
        let bytes = payload.to_bytes().unwrap();
        let restored = MessagePayload::from_bytes(&bytes).unwrap();
        assert_eq!(restored.body, "hello");
        assert_eq!(restored.ttl_seconds, None);
    }

    #[test]
    fn test_payload_with_ttl_roundtrip() {
        let payload = MessagePayload::with_ttl("secret message", 30);
        let bytes = payload.to_bytes().unwrap();
        let restored = MessagePayload::from_bytes(&bytes).unwrap();
        assert_eq!(restored.body, "secret message");
        assert_eq!(restored.ttl_seconds, Some(30));
    }

    #[test]
    fn test_payload_without_ttl_omits_field() {
        let payload = MessagePayload::new("no ttl");
        let json = serde_json::to_string(&payload).unwrap();
        assert!(!json.contains("ttl_seconds"));
    }

    #[test]
    fn test_payload_with_ttl_includes_field() {
        let payload = MessagePayload::with_ttl("has ttl", 60);
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"ttl_seconds\":60"));
    }

    #[test]
    fn test_backward_compat_no_ttl_field() {
        // Simulate receiving a message from an older client that doesn't include ttl_seconds
        let json = r#"{"body":"old client message"}"#;
        let payload: MessagePayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.body, "old client message");
        assert_eq!(payload.ttl_seconds, None);
    }

    #[test]
    fn test_padded_roundtrip() {
        sodiumoxide::init().unwrap();
        let payload = MessagePayload::with_ttl("padded secret", 60);
        let padded = payload.to_padded_bytes().unwrap();
        // Padded output should be a power-of-2 bucket size (>= 256)
        assert!(padded.len() >= 256);
        assert!(padded.len().is_power_of_two() || padded.len().is_multiple_of(65536));
        let recovered = MessagePayload::from_padded_bytes(&padded).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_padded_hides_length() {
        sodiumoxide::init().unwrap();
        // Two messages of different lengths in the same bucket should have
        // the same padded size
        let short = MessagePayload::new("hi");
        let longer = MessagePayload::new("a somewhat longer message body");
        let padded_short = short.to_padded_bytes().unwrap();
        let padded_longer = longer.to_padded_bytes().unwrap();
        assert_eq!(padded_short.len(), padded_longer.len());
    }

    #[test]
    fn test_padded_encrypt_decrypt_with_ratchet() {
        use crate::double_ratchet::RatchetState;
        use sodiumoxide::crypto::box_;

        sodiumoxide::init().unwrap();
        let shared_secret = [0x42u8; 32];
        let (bob_pk, bob_sk) = box_::gen_keypair();

        let mut alice = RatchetState::init_sender(shared_secret, &bob_pk).unwrap();
        let mut bob = RatchetState::init_receiver(shared_secret, (bob_pk, bob_sk));

        let payload = MessagePayload::with_ttl("padded vanishing message", 10);
        let padded_bytes = payload.to_padded_bytes().unwrap();

        let ad = b"session-id";
        let (header, ct) = alice.encrypt(&padded_bytes, ad).unwrap();
        let pt = bob.decrypt(&header, &ct, ad).unwrap();

        let decrypted_payload = MessagePayload::from_padded_bytes(&pt).unwrap();
        assert_eq!(decrypted_payload.body, "padded vanishing message");
        assert_eq!(decrypted_payload.ttl_seconds, Some(10));
    }

    #[test]
    fn test_payload_encrypt_decrypt_with_ratchet() {
        use crate::double_ratchet::RatchetState;
        use sodiumoxide::crypto::box_;

        sodiumoxide::init().unwrap();
        let shared_secret = [0x42u8; 32];
        let (bob_pk, bob_sk) = box_::gen_keypair();

        let mut alice = RatchetState::init_sender(shared_secret, &bob_pk).unwrap();
        let mut bob = RatchetState::init_receiver(shared_secret, (bob_pk, bob_sk));

        // Alice sends a self-destructing message
        let payload = MessagePayload::with_ttl("vanishing message", 5);
        let payload_bytes = payload.to_bytes().unwrap();

        let ad = b"session-id";
        let (header, ct) = alice.encrypt(&payload_bytes, ad).unwrap();
        let pt = bob.decrypt(&header, &ct, ad).unwrap();

        let decrypted_payload = MessagePayload::from_bytes(&pt).unwrap();
        assert_eq!(decrypted_payload.body, "vanishing message");
        assert_eq!(decrypted_payload.ttl_seconds, Some(5));
    }

    #[test]
    fn test_payload_no_ttl_encrypt_decrypt_with_ratchet() {
        use crate::double_ratchet::RatchetState;
        use sodiumoxide::crypto::box_;

        sodiumoxide::init().unwrap();
        let shared_secret = [0x42u8; 32];
        let (bob_pk, bob_sk) = box_::gen_keypair();

        let mut alice = RatchetState::init_sender(shared_secret, &bob_pk).unwrap();
        let mut bob = RatchetState::init_receiver(shared_secret, (bob_pk, bob_sk));

        // Alice sends a normal (non-self-destructing) message
        let payload = MessagePayload::new("permanent message");
        let payload_bytes = payload.to_bytes().unwrap();

        let ad = b"session-id";
        let (header, ct) = alice.encrypt(&payload_bytes, ad).unwrap();
        let pt = bob.decrypt(&header, &ct, ad).unwrap();

        let decrypted_payload = MessagePayload::from_bytes(&pt).unwrap();
        assert_eq!(decrypted_payload.body, "permanent message");
        assert_eq!(decrypted_payload.ttl_seconds, None);
    }
}

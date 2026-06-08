//! Encrypted message payload structure.
//!
//! The `MessagePayload` wraps the plaintext content along with metadata
//! (such as self-destruct TTL) that is encrypted inside the Double Ratchet.
//! The server never sees any of these fields.

use serde::{Deserialize, Serialize};

use crate::errors::{CryptoError, Result};
use crate::padding;

/// Sentinel "no group" marker — 64 zero hex chars. When present in the
/// padded wire format this means the payload is a plain 1:1 DM and the
/// receiver should ignore the `group_id` field entirely. Picking a
/// fixed 64-char placeholder makes the on-the-wire JSON shape identical
/// for DM and group messages, so an observer can't infer "is this a
/// group message?" from the post-padding bucket size.
///
/// A real group identifier is generated server-side by hashing the
/// member set + creation timestamp and is overwhelmingly unlikely to
/// collide with all zeros, but the receive-side validation also
/// rejects any group_id that doesn't match a 64-char-hex shape so a
/// peer can't smuggle structured data through the field.
const GROUP_ID_PLACEHOLDER: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Expected length of a real group identifier (32 bytes → 64 hex chars).
const GROUP_ID_LEN: usize = 64;

/// Payload that gets encrypted inside the Double Ratchet ciphertext.
///
/// This structure is serialized to JSON before encryption, so all fields
/// are hidden from the server. The `ttl_seconds` field controls self-destruct:
/// once the recipient reads the message, a client-side timer starts and the
/// message is deleted after `ttl_seconds` have elapsed. The `group_id` field
/// tells the recipient which group conversation this message belongs to so
/// the UI can route it to the group view instead of the per-sender 1:1
/// thread; the field is encrypted (server-invisible) and absent for plain
/// DMs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MessagePayload {
    /// The plaintext message body.
    pub body: String,
    /// Optional self-destruct TTL in seconds. `None` means no self-destruct.
    /// When set, the recipient starts a timer on read and deletes the message
    /// after this many seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u32>,
    /// Optional group identifier (hex). When set, the recipient knows this
    /// message is part of a group conversation and routes it to the group's
    /// message list. Absent / `None` for ordinary 1:1 messages. The server
    /// never sees this field — it lives inside the Double Ratchet ciphertext.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
}

impl MessagePayload {
    /// Create a new message payload without self-destruct.
    pub fn new(body: impl Into<String>) -> Self {
        Self {
            body: body.into(),
            ttl_seconds: None,
            group_id: None,
        }
    }

    /// Create a new message payload with a self-destruct TTL.
    pub fn with_ttl(body: impl Into<String>, ttl_seconds: u32) -> Self {
        Self {
            body: body.into(),
            ttl_seconds: Some(ttl_seconds),
            group_id: None,
        }
    }

    /// Tag a payload as belonging to a group conversation. Chainable so the
    /// existing `new(...)` / `with_ttl(...)` call sites need only append
    /// `.in_group("...")` when sending a group message.
    pub fn in_group(mut self, group_id: impl Into<String>) -> Self {
        self.group_id = Some(group_id.into());
        self
    }

    /// Serialize the payload to JSON bytes for encryption.
    ///
    /// Kept for backward compatibility with callers that don't go through
    /// the padded wire path. `to_padded_bytes` is the right choice for
    /// anything that actually ships over the wire.
    pub fn to_bytes(&self) -> std::result::Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize a payload from JSON bytes after decryption.
    pub fn from_bytes(bytes: &[u8]) -> std::result::Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Serialize the payload to padded bytes for encryption.
    ///
    /// Always emits a `group_id` field on the wire — either the real
    /// 64-hex group identifier OR the [`GROUP_ID_PLACEHOLDER`] sentinel
    /// for DMs. This makes the JSON shape identical for DM and group
    /// messages, so the post-padding bucket size doesn't leak which is
    /// which. Without this normalization, the +77 byte overhead of a
    /// real group_id could push a tiny DM up to the next bucket and
    /// expose its conversation type to the server.
    pub fn to_padded_bytes(&self) -> Result<Vec<u8>> {
        let mut on_wire = self.clone();
        if on_wire.group_id.is_none() {
            on_wire.group_id = Some(GROUP_ID_PLACEHOLDER.to_string());
        }
        let json = serde_json::to_vec(&on_wire)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
        padding::pad_message(&json).map_err(Into::into)
    }

    /// Deserialize a payload from padded bytes after decryption.
    ///
    /// Removes padding, parses the JSON, then:
    /// - Treats the sentinel placeholder as "no group" (`group_id = None`)
    /// - Rejects any other non-64-hex value as malformed (a peer that
    ///   smuggled structured data through the field could try to confuse
    ///   the receiver's routing or trigger downstream bugs)
    pub fn from_padded_bytes(padded: &[u8]) -> Result<Self> {
        let unpadded = padding::unpad_message(padded)?;
        let mut payload: Self = serde_json::from_slice(&unpadded)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
        payload.normalize_group_id()?;
        Ok(payload)
    }

    /// Validate and normalize the `group_id` field after deserialization.
    /// The placeholder collapses to `None`; any other non-empty value
    /// must be exactly 64 lowercase-or-uppercase ASCII hex chars or the
    /// payload is rejected. Public so receive paths that bypass
    /// `from_padded_bytes` (e.g. legacy raw-plaintext fallback) can run
    /// the same check.
    pub fn normalize_group_id(&mut self) -> Result<()> {
        match self.group_id.as_deref() {
            None => Ok(()),
            Some(id) if id == GROUP_ID_PLACEHOLDER => {
                self.group_id = None;
                Ok(())
            }
            Some(id) if id.is_empty() => {
                self.group_id = None;
                Ok(())
            }
            Some(id) if id.len() == GROUP_ID_LEN && id.chars().all(|c| c.is_ascii_hexdigit()) => {
                Ok(())
            }
            Some(id) => Err(CryptoError::SerializationError(format!(
                "invalid group_id: expected {GROUP_ID_LEN}-char hex, got {} chars",
                id.len()
            ))),
        }
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

    /// Regression for the metadata-leak the crypto reviewer flagged:
    /// adding `group_id` to a DM used to push tiny messages into a
    /// larger padding bucket, leaking "this is a group message" to
    /// the server observer who can see ciphertext sizes. After the
    /// fix, the post-padding bucket size is identical regardless of
    /// whether the payload carries a real group_id or not.
    #[test]
    fn test_padded_size_invariant_under_group_id() {
        let dm = MessagePayload::new("hi").to_padded_bytes().unwrap();
        let group = MessagePayload::new("hi")
            .in_group("a".repeat(64))
            .to_padded_bytes()
            .unwrap();
        assert_eq!(
            dm.len(),
            group.len(),
            "DM and group padded sizes must match — the wire shape is what an observer sees",
        );
    }

    /// Round-trip: the placeholder collapses back to None on decode so
    /// downstream code (Android/Desktop messagesStore) routes the
    /// message to senderId, not to a placeholder "group".
    #[test]
    fn test_padded_roundtrip_dm_recovers_none_group_id() {
        let dm = MessagePayload::new("hi").to_padded_bytes().unwrap();
        let decoded = MessagePayload::from_padded_bytes(&dm).unwrap();
        assert_eq!(decoded.body, "hi");
        assert_eq!(decoded.group_id, None, "placeholder must collapse to None");
    }

    /// A real group id survives the padded roundtrip and stays Some.
    #[test]
    fn test_padded_roundtrip_group_id_preserved() {
        let real_id = "0123456789abcdef".repeat(4); // 64 hex chars
        let group = MessagePayload::new("hi")
            .in_group(&real_id)
            .to_padded_bytes()
            .unwrap();
        let decoded = MessagePayload::from_padded_bytes(&group).unwrap();
        assert_eq!(decoded.body, "hi");
        assert_eq!(decoded.group_id, Some(real_id));
    }

    /// Validation rejects malformed group_id (wrong length, non-hex
    /// chars). A malicious peer could otherwise smuggle structured
    /// data or routing-confusion strings through the encrypted field.
    #[test]
    fn test_normalize_group_id_rejects_garbage() {
        let mut p = MessagePayload::new("x");
        p.group_id = Some("not-hex".into());
        assert!(p.normalize_group_id().is_err());

        let mut p = MessagePayload::new("x");
        p.group_id = Some("0123".into()); // too short
        assert!(p.normalize_group_id().is_err());

        let mut p = MessagePayload::new("x");
        p.group_id = Some("z".repeat(64)); // right length, wrong charset
        assert!(p.normalize_group_id().is_err());

        let mut p = MessagePayload::new("x");
        p.group_id = Some("a".repeat(64));
        assert!(p.normalize_group_id().is_ok());
        assert_eq!(p.group_id, Some("a".repeat(64)));
    }
}

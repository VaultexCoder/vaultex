use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sealedbox;
use sodiumoxide::crypto::sign;
use zeroize::Zeroize;

use crate::errors::{CryptoError, Result};
use crate::identity::IdentityKeyPair;

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

// ── Identity-authenticated box (for ephemeral call signaling) ───────────────
//
// Encrypt a payload between two parties identified by their long-term Ed25519
// identity keys (converted to X25519 via libsodium). Used for WebRTC SDP/ICE
// (which carry IP addresses) so the relay server -- which only sees ciphertext
// -- learns nothing AND cannot forge: this is libsodium `crypto_box`
// (authenticated), keyed by the sender's identity X25519 secret and the
// recipient's identity X25519 public, with a random per-message nonce. The
// recipient verifies the message came from the *expected* sender identity, so
// a malicious relay cannot inject/MITM call setup (it lacks the sender's
// identity secret). This is stronger than an anonymous sealed box, which
// authenticates nothing about the sender.
//
// SECURITY NOTE: crypto integration -- requires Security Engineer review per
// CLAUDE.md. Primitives are libsodium only (crypto_box + the standard
// crypto_sign_ed25519_*_to_curve25519 conversion already used by X3DH).

/// Convert an Ed25519 public key to an X25519 (box) public key via libsodium.
fn ed25519_pk_to_box(pk: &sign::PublicKey) -> Result<box_::PublicKey> {
    let mut curve = [0u8; 32];
    let ret = unsafe {
        libsodium_sys::crypto_sign_ed25519_pk_to_curve25519(curve.as_mut_ptr(), pk.0.as_ptr())
    };
    if ret != 0 {
        return Err(CryptoError::SealedSenderError(
            "ed25519->x25519 public key conversion failed".into(),
        ));
    }
    box_::PublicKey::from_slice(&curve)
        .ok_or_else(|| CryptoError::SealedSenderError("invalid converted x25519 public key".into()))
}

/// Convert an Ed25519 secret key to an X25519 (box) secret key via libsodium.
fn ed25519_sk_to_box(sk: &sign::SecretKey) -> Result<box_::SecretKey> {
    let mut curve = [0u8; 32];
    let ret = unsafe {
        libsodium_sys::crypto_sign_ed25519_sk_to_curve25519(curve.as_mut_ptr(), sk.0.as_ptr())
    };
    if ret != 0 {
        return Err(CryptoError::SealedSenderError(
            "ed25519->x25519 secret key conversion failed".into(),
        ));
    }
    let out = box_::SecretKey::from_slice(&curve).ok_or_else(|| {
        CryptoError::SealedSenderError("invalid converted x25519 secret key".into())
    });
    curve.zeroize();
    out
}

/// Authenticated-encrypt `plaintext` from `sender_identity` to a recipient
/// identified by their Ed25519 identity public key. Output is `nonce ||
/// crypto_box_ciphertext`; the recipient both decrypts AND verifies it was
/// sealed by the holder of the sender identity's secret key.
#[must_use = "encrypted call payload must be sent"]
pub fn encrypt_to_identity(
    sender_identity: &IdentityKeyPair,
    recipient_identity_pk: &sign::PublicKey,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    sodiumoxide::init().map_err(|_| CryptoError::InitFailed)?;
    let sender_sk = ed25519_sk_to_box(sender_identity.secret_key())?;
    let recipient_pk = ed25519_pk_to_box(recipient_identity_pk)?;
    let nonce = box_::gen_nonce();
    let ciphertext = box_::seal(plaintext, &nonce, &recipient_pk, &sender_sk);
    let mut out = Vec::with_capacity(box_::NONCEBYTES + ciphertext.len());
    out.extend_from_slice(nonce.as_ref());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt + authenticate a payload produced by `encrypt_to_identity`,
/// verifying it came from `sender_identity_pk` (the expected peer). Fails if
/// the ciphertext was not sealed by that identity's secret key -- so a relay
/// (or anyone lacking the sender's identity secret) cannot forge it.
#[must_use = "decrypt result must be checked for auth/decryption failure"]
pub fn decrypt_from_identity(
    recipient_identity: &IdentityKeyPair,
    sender_identity_pk: &sign::PublicKey,
    sealed: &[u8],
) -> Result<Vec<u8>> {
    sodiumoxide::init().map_err(|_| CryptoError::InitFailed)?;
    if sealed.len() < box_::NONCEBYTES {
        return Err(CryptoError::SealedSenderError(
            "sealed call payload too short for nonce".into(),
        ));
    }
    let (nonce_bytes, ciphertext) = sealed.split_at(box_::NONCEBYTES);
    let nonce = box_::Nonce::from_slice(nonce_bytes)
        .ok_or_else(|| CryptoError::SealedSenderError("invalid nonce".into()))?;
    let sender_pk = ed25519_pk_to_box(sender_identity_pk)?;
    let recipient_sk = ed25519_sk_to_box(recipient_identity.secret_key())?;
    box_::open(ciphertext, &nonce, &sender_pk, &recipient_sk).map_err(|_| {
        CryptoError::SealedSenderError("failed to authenticate/decrypt call payload".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_to_identity_roundtrip() {
        sodiumoxide::init().unwrap();
        let sender = IdentityKeyPair::generate().unwrap();
        let recipient = IdentityKeyPair::generate().unwrap();
        let plaintext = b"v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n";

        let sealed = encrypt_to_identity(&sender, &recipient.public_key, plaintext).unwrap();
        assert_ne!(sealed.as_slice(), plaintext);
        let opened = decrypt_from_identity(&recipient, &sender.public_key, &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn test_decrypt_fails_for_wrong_recipient() {
        sodiumoxide::init().unwrap();
        let sender = IdentityKeyPair::generate().unwrap();
        let recipient = IdentityKeyPair::generate().unwrap();
        let attacker = IdentityKeyPair::generate().unwrap();

        let sealed = encrypt_to_identity(&sender, &recipient.public_key, b"secret sdp").unwrap();
        // Wrong recipient secret key cannot open.
        assert!(decrypt_from_identity(&attacker, &sender.public_key, &sealed).is_err());
    }

    #[test]
    fn test_decrypt_fails_for_forged_sender() {
        sodiumoxide::init().unwrap();
        // A relay/attacker who lacks the real sender's identity secret cannot
        // produce a payload that authenticates as the expected sender.
        let real_sender = IdentityKeyPair::generate().unwrap();
        let forger = IdentityKeyPair::generate().unwrap();
        let recipient = IdentityKeyPair::generate().unwrap();

        let forged = encrypt_to_identity(&forger, &recipient.public_key, b"injected sdp").unwrap();
        // Recipient expects it from real_sender -> authentication must fail.
        assert!(decrypt_from_identity(&recipient, &real_sender.public_key, &forged).is_err());
    }

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

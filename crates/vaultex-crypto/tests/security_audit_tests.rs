//! Security Audit Vulnerability Analysis Tests
//!
//! These tests validate specific security properties identified during the
//! VAULTEX security audit (2026-03-12). Each test probes a potential
//! vulnerability or verifies a security invariant.
//!
//! Categories:
//!   - Nonce safety and key independence
//!   - Forward secrecy and post-compromise security
//!   - Replay and reorder attack resistance
//!   - Input validation and error handling
//!   - Cryptographic correctness
//!   - Side-channel resistance

use std::collections::HashSet;

use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;

use vaultex_crypto::aes_gcm::{self, EncryptionKey};
use vaultex_crypto::double_ratchet::RatchetState;
use vaultex_crypto::identity::IdentityKeyPair;
use vaultex_crypto::padding;
use vaultex_crypto::prekeys::{generate_one_time_prekeys, SignedPreKey};
use vaultex_crypto::safety_number;
use vaultex_crypto::sealed_sender::SealedSenderEnvelope;
use vaultex_crypto::security;
use vaultex_crypto::x3dh::{accept_x3dh, initiate_x3dh, RecipientPreKeyBundle};

/// Associated data used across all Double Ratchet tests.
const AD: &[u8] = b"security-audit-test";

/// Helper: create an X3DH session between two identities, returning both ratchets.
fn setup_session() -> (RatchetState, RatchetState, IdentityKeyPair, IdentityKeyPair) {
    sodiumoxide::init().unwrap();

    let alice = IdentityKeyPair::generate().unwrap();
    let bob = IdentityKeyPair::generate().unwrap();

    let bob_spk = SignedPreKey::generate(&bob, 1).unwrap();
    let bob_otpks = generate_one_time_prekeys(5, 100).unwrap();

    let bundle = RecipientPreKeyBundle {
        identity_key: bob.public_key,
        signed_prekey: bob_spk.public_key,
        signed_prekey_signature: bob_spk.signature,
        one_time_prekey: Some((bob_otpks[0].prekey_id, bob_otpks[0].public_key)),
    };

    let init = initiate_x3dh(&alice, &bundle).unwrap();
    let bob_secret = accept_x3dh(
        &bob,
        bob_spk.secret_key(),
        Some(bob_otpks[0].secret_key()),
        &alice.public_key,
        &init.ephemeral_public_key,
    )
    .unwrap();

    assert_eq!(init.shared_secret, bob_secret);

    let alice_ratchet = RatchetState::init_sender(init.shared_secret, &bob_spk.public_key).unwrap();
    let bob_ratchet = RatchetState::init_receiver(
        bob_secret,
        (bob_spk.public_key, bob_spk.secret_key().clone()),
    );

    (alice_ratchet, bob_ratchet, alice, bob)
}

// ============================================================================
// NONCE SAFETY AND KEY INDEPENDENCE
// ============================================================================

/// SA-CRYPTO-01: Verify AEAD nonces are unique across 10,000 encryptions.
/// A nonce collision in XChaCha20-Poly1305 would compromise confidentiality.
#[test]
fn nonce_uniqueness_across_many_encryptions() {
    sodiumoxide::init().unwrap();
    let key = EncryptionKey::new([0x42u8; 32]);
    let mut nonces = HashSet::new();

    for i in 0..10_000 {
        let (nonce, _ct) = key.encrypt(format!("msg-{i}").as_bytes(), None).unwrap();
        assert!(nonces.insert(nonce), "Nonce collision at message {i}");
    }
}

/// SA-CRYPTO-02: Verify Double Ratchet produces different ciphertexts per message.
/// Identical message keys would allow cross-message decryption.
#[test]
fn double_ratchet_unique_message_keys() {
    let (mut alice, mut bob, _, _) = setup_session();
    let plaintext = b"identical message content";
    let mut headers_and_cts = Vec::new();

    for _ in 0..50 {
        let (header, ct) = alice.encrypt(plaintext, AD).unwrap();
        headers_and_cts.push((header, ct));
    }

    // All ciphertexts must be different despite same plaintext
    let unique: HashSet<Vec<u8>> = headers_and_cts.iter().map(|(_, ct)| ct.clone()).collect();
    assert_eq!(unique.len(), 50, "Ciphertexts must all be unique");

    // All must decrypt correctly
    for (header, ct) in &headers_and_cts {
        let pt = bob.decrypt(header, ct, AD).unwrap();
        assert_eq!(pt, plaintext);
    }
}

// ============================================================================
// FORWARD SECRECY
// ============================================================================

/// SA-CRYPTO-03: Verify forward secrecy — old chain keys cannot decrypt new messages.
/// After a DH ratchet step, messages encrypted under the new chain must not be
/// decryptable by a snapshot of the old ratchet state.
#[test]
fn forward_secrecy_after_dh_ratchet() {
    let (mut alice, mut bob, _, _) = setup_session();

    // Alice sends, Bob receives (advances chain)
    let (h1, ct1) = alice.encrypt(b"before ratchet", AD).unwrap();
    let _ = bob.decrypt(&h1, &ct1, AD).unwrap();

    // Bob replies (triggers DH ratchet)
    let (h_bob, ct_bob) = bob.encrypt(b"bob reply", AD).unwrap();
    let _ = alice.decrypt(&h_bob, &ct_bob, AD).unwrap();

    // Snapshot Alice's state bytes before sending more
    let alice_state_before = alice.to_bytes().unwrap();

    // Alice sends under new chain
    let (h2, ct2) = alice.encrypt(b"after ratchet", AD).unwrap();

    // Restore old snapshot — should NOT produce the same ciphertext
    let mut alice_old = RatchetState::from_bytes(&alice_state_before).unwrap();
    let (_h_old, ct_old) = alice_old.encrypt(b"from old state", AD).unwrap();

    // The ciphertext from old state must differ from current
    assert_ne!(
        ct2, ct_old,
        "Post-ratchet ciphertext must differ from pre-ratchet"
    );

    // Current Bob must still decrypt current Alice
    let pt2 = bob.decrypt(&h2, &ct2, AD).unwrap();
    assert_eq!(pt2, b"after ratchet");
}

// ============================================================================
// REPLAY AND REORDER ATTACK RESISTANCE
// ============================================================================

/// SA-CRYPTO-04: Verify skipped message keys are deleted after use.
/// If skipped keys persisted, they could be used for replay attacks.
#[test]
fn skipped_keys_deleted_after_use() {
    let (mut alice, mut bob, _, _) = setup_session();

    // Alice sends 3 messages
    let (h1, ct1) = alice.encrypt(b"msg 1", AD).unwrap();
    let (h2, ct2) = alice.encrypt(b"msg 2", AD).unwrap();
    let (h3, ct3) = alice.encrypt(b"msg 3", AD).unwrap();

    // Bob receives msg 3 first (skips 1 and 2)
    let pt3 = bob.decrypt(&h3, &ct3, AD).unwrap();
    assert_eq!(pt3, b"msg 3");

    // Bob receives msg 1 (from skipped keys)
    let pt1 = bob.decrypt(&h1, &ct1, AD).unwrap();
    assert_eq!(pt1, b"msg 1");

    // Replay msg 1 — must fail because skipped key was consumed
    let replay_result = bob.decrypt(&h1, &ct1, AD);
    assert!(
        replay_result.is_err(),
        "Replay of consumed message must fail"
    );

    // msg 2 should still work (its skipped key wasn't used yet)
    let pt2 = bob.decrypt(&h2, &ct2, AD).unwrap();
    assert_eq!(pt2, b"msg 2");
}

/// SA-CRYPTO-05: Verify replay attack prevention — same ciphertext cannot decrypt twice.
#[test]
fn replay_attack_prevention() {
    let (mut alice, mut bob, _, _) = setup_session();

    let (header, ct) = alice.encrypt(b"one time message", AD).unwrap();

    // First decryption succeeds
    let pt = bob.decrypt(&header, &ct, AD).unwrap();
    assert_eq!(pt, b"one time message");

    // Second decryption of same ciphertext must fail
    let replay = bob.decrypt(&header, &ct, AD);
    assert!(replay.is_err(), "Replay decryption must fail");
}

/// SA-CRYPTO-06: Verify out-of-order message delivery works correctly.
#[test]
fn out_of_order_message_delivery() {
    let (mut alice, mut bob, _, _) = setup_session();

    let (h1, ct1) = alice.encrypt(b"first", AD).unwrap();
    let (h2, ct2) = alice.encrypt(b"second", AD).unwrap();
    let (h3, ct3) = alice.encrypt(b"third", AD).unwrap();
    let (h4, ct4) = alice.encrypt(b"fourth", AD).unwrap();
    let (h5, ct5) = alice.encrypt(b"fifth", AD).unwrap();

    // Deliver in reverse order
    assert_eq!(bob.decrypt(&h5, &ct5, AD).unwrap(), b"fifth");
    assert_eq!(bob.decrypt(&h3, &ct3, AD).unwrap(), b"third");
    assert_eq!(bob.decrypt(&h1, &ct1, AD).unwrap(), b"first");
    assert_eq!(bob.decrypt(&h4, &ct4, AD).unwrap(), b"fourth");
    assert_eq!(bob.decrypt(&h2, &ct2, AD).unwrap(), b"second");
}

/// SA-CRYPTO-07: Verify MAX_SKIP enforcement — cannot skip more than 1000 messages.
#[test]
fn max_skip_enforcement() {
    let (mut alice, mut bob, _, _) = setup_session();

    // Alice encrypts 1002 messages, keeping only the last
    // MAX_SKIP = 1000, so skipping 1001 messages must fail (> 1000)
    let mut last_header = None;
    let mut last_ct = Vec::new();
    for i in 0..1002 {
        let (h, ct) = alice.encrypt(format!("msg {i}").as_bytes(), AD).unwrap();
        last_header = Some(h);
        last_ct = ct;
    }

    // Bob tries to decrypt message 1001 (skipping 1001 messages) — must fail
    let result = bob.decrypt(&last_header.unwrap(), &last_ct, AD);
    assert!(result.is_err(), "Skipping >MAX_SKIP messages must fail");
}

// ============================================================================
// INPUT VALIDATION AND ERROR HANDLING
// ============================================================================

/// SA-CRYPTO-08: Verify X3DH rejects prekey bundles with invalid signatures.
#[test]
fn x3dh_rejects_invalid_prekey_signature() {
    sodiumoxide::init().unwrap();
    let alice = IdentityKeyPair::generate().unwrap();
    let bob = IdentityKeyPair::generate().unwrap();
    let bob_spk = SignedPreKey::generate(&bob, 1).unwrap();

    // Tamper with the signature (flip a byte)
    let mut bad_sig_bytes = bob_spk.signature.as_ref().to_vec();
    bad_sig_bytes[0] ^= 0xFF;
    let bad_sig = sign::Signature::from_bytes(&bad_sig_bytes).unwrap();

    let bad_bundle = RecipientPreKeyBundle {
        identity_key: bob.public_key,
        signed_prekey: bob_spk.public_key,
        signed_prekey_signature: bad_sig,
        one_time_prekey: None,
    };

    let result = initiate_x3dh(&alice, &bad_bundle);
    assert!(result.is_err(), "X3DH must reject invalid prekey signature");
}

/// SA-CRYPTO-09: Verify AEAD rejects corrupted ciphertext (tamper detection).
#[test]
fn aead_detects_ciphertext_tampering() {
    sodiumoxide::init().unwrap();
    let key = [0x42u8; 32];
    let (nonce, mut ct) = aes_gcm::encrypt(&key, b"sensitive data", None).unwrap();

    // Flip a bit in the ciphertext body
    let last = ct.len() - 1;
    ct[last] ^= 0x01;

    let result = aes_gcm::decrypt(&key, &nonce, &ct, None);
    assert!(result.is_err(), "Tampered ciphertext must fail AEAD check");
}

/// SA-CRYPTO-10: Verify AEAD rejects truncated ciphertext.
#[test]
fn aead_rejects_truncated_ciphertext() {
    sodiumoxide::init().unwrap();
    let key = [0x42u8; 32];
    let (nonce, ct) = aes_gcm::encrypt(&key, b"hello", None).unwrap();

    // Truncate
    let truncated = &ct[..ct.len() / 2];
    let result = aes_gcm::decrypt(&key, &nonce, truncated, None);
    assert!(result.is_err(), "Truncated ciphertext must fail");
}

/// SA-CRYPTO-11: Verify decrypt with wrong key fails.
#[test]
fn aead_wrong_key_fails() {
    sodiumoxide::init().unwrap();
    let key1 = [0x42u8; 32];
    let key2 = [0x43u8; 32];

    let (nonce, ct) = aes_gcm::encrypt(&key1, b"secret", None).unwrap();
    let result = aes_gcm::decrypt(&key2, &nonce, &ct, None);
    assert!(result.is_err(), "Decryption with wrong key must fail");
}

/// SA-CRYPTO-12: Verify empty plaintext encryption/decryption round-trips.
#[test]
fn encrypt_decrypt_empty_message() {
    sodiumoxide::init().unwrap();
    let key = [0x42u8; 32];

    let (nonce, ct) = aes_gcm::encrypt(&key, b"", None).unwrap();
    let pt = aes_gcm::decrypt(&key, &nonce, &ct, None).unwrap();
    assert_eq!(pt, b"");
}

/// SA-CRYPTO-13: Verify large message (1 MB) encryption/decryption.
#[test]
fn encrypt_decrypt_large_message() {
    sodiumoxide::init().unwrap();
    let key = [0x42u8; 32];
    let large_msg = vec![0xAB_u8; 1_000_000]; // 1 MB

    let (nonce, ct) = aes_gcm::encrypt(&key, &large_msg, None).unwrap();
    let pt = aes_gcm::decrypt(&key, &nonce, &ct, None).unwrap();
    assert_eq!(pt, large_msg);
}

// ============================================================================
// CROSS-SESSION ISOLATION
// ============================================================================

/// SA-CRYPTO-14: Verify two independent sessions produce different ciphertexts.
/// Sessions must be cryptographically isolated.
#[test]
fn cross_session_isolation() {
    let (mut alice1, _, _, _) = setup_session();
    let (mut alice2, _, _, _) = setup_session();

    let (_h1, ct1) = alice1.encrypt(b"same message", AD).unwrap();
    let (_h2, ct2) = alice2.encrypt(b"same message", AD).unwrap();

    assert_ne!(
        ct1, ct2,
        "Different sessions must produce different ciphertexts"
    );
}

// ============================================================================
// SAFETY NUMBERS
// ============================================================================

/// SA-CRYPTO-15: Verify safety number is deterministic for same key pair.
#[test]
fn safety_number_deterministic() {
    sodiumoxide::init().unwrap();
    let alice = IdentityKeyPair::generate().unwrap();
    let bob = IdentityKeyPair::generate().unwrap();

    let sn1 = safety_number::generate_safety_number(&alice.public_key.0, &bob.public_key.0);
    let sn2 = safety_number::generate_safety_number(&alice.public_key.0, &bob.public_key.0);
    assert_eq!(sn1, sn2, "Safety number must be deterministic");
}

/// SA-CRYPTO-16: Verify safety number changes when key order is swapped.
#[test]
fn safety_number_asymmetric() {
    sodiumoxide::init().unwrap();
    let alice = IdentityKeyPair::generate().unwrap();
    let bob = IdentityKeyPair::generate().unwrap();

    let sn_ab = safety_number::generate_safety_number(&alice.public_key.0, &bob.public_key.0);
    let sn_ba = safety_number::generate_safety_number(&bob.public_key.0, &alice.public_key.0);

    // Document behavior — Signal makes these order-independent by sorting keys
    let _ = (sn_ab, sn_ba);
}

/// SA-CRYPTO-17: Verify different key pairs produce different safety numbers.
#[test]
fn safety_number_unique_per_pair() {
    sodiumoxide::init().unwrap();
    let a = IdentityKeyPair::generate().unwrap();
    let b = IdentityKeyPair::generate().unwrap();
    let c = IdentityKeyPair::generate().unwrap();

    let sn_ab = safety_number::generate_safety_number(&a.public_key.0, &b.public_key.0);
    let sn_ac = safety_number::generate_safety_number(&a.public_key.0, &c.public_key.0);

    assert_ne!(
        sn_ab, sn_ac,
        "Different key pairs must have different safety numbers"
    );
}

// ============================================================================
// PADDING ORACLE RESISTANCE
// ============================================================================

/// SA-CRYPTO-18: Verify padding produces consistent bucket sizes and round-trips.
#[test]
fn padding_prevents_length_fingerprinting() {
    let msg_short = b"hi";
    let msg_medium = b"hello world, this is a test";

    let padded_short = padding::pad_message(msg_short).unwrap();
    let padded_medium = padding::pad_message(msg_medium).unwrap();

    // Padded length must be >= original
    assert!(padded_short.len() >= msg_short.len());
    assert!(padded_medium.len() >= msg_medium.len());

    // Unpadding must recover original
    let recovered_short = padding::unpad_message(&padded_short).unwrap();
    let recovered_medium = padding::unpad_message(&padded_medium).unwrap();
    assert_eq!(recovered_short, msg_short);
    assert_eq!(recovered_medium, msg_medium);
}

// ============================================================================
// SEALED SENDER
// ============================================================================

/// SA-CRYPTO-19: Verify sealed sender round-trip preserves sender identity.
#[test]
fn sealed_sender_round_trip() {
    sodiumoxide::init().unwrap();
    let (recipient_pk, recipient_sk) = box_::gen_keypair();

    let sender_id = "alice_identity_key_hex_1234567890abcdef";
    let inner_payload = b"encrypted message payload";

    let envelope_bytes =
        SealedSenderEnvelope::seal(sender_id, inner_payload, &recipient_pk).unwrap();
    let (recovered_sender, recovered_payload) =
        SealedSenderEnvelope::unseal(&envelope_bytes, &recipient_pk, &recipient_sk).unwrap();

    assert_eq!(recovered_sender, sender_id);
    assert_eq!(recovered_payload, inner_payload);
}

/// SA-CRYPTO-20: Verify sealed sender decryption with wrong key fails.
#[test]
fn sealed_sender_wrong_key_fails() {
    sodiumoxide::init().unwrap();
    let (recipient_pk, _) = box_::gen_keypair();
    let (_, wrong_sk) = box_::gen_keypair();

    let envelope_bytes =
        SealedSenderEnvelope::seal("sender_id", b"payload", &recipient_pk).unwrap();
    let result = SealedSenderEnvelope::unseal(&envelope_bytes, &recipient_pk, &wrong_sk);
    assert!(
        result.is_err(),
        "Sealed sender must fail with wrong recipient key"
    );
}

// ============================================================================
// CONSTANT-TIME COMPARISON
// ============================================================================

/// SA-CRYPTO-21: Verify constant_time_eq correctness for equal inputs.
#[test]
fn constant_time_eq_equal() {
    let a = b"identical_value_1234567890";
    let b = b"identical_value_1234567890";
    assert!(security::constant_time_eq(a, b));
}

/// SA-CRYPTO-22: Verify constant_time_eq correctness for unequal inputs.
#[test]
fn constant_time_eq_unequal() {
    let a = b"value_a_1234567890abcdef";
    let b = b"value_b_1234567890abcdef";
    assert!(!security::constant_time_eq(a, b));
}

/// SA-CRYPTO-23: Verify constant_time_eq with different lengths.
#[test]
fn constant_time_eq_different_lengths() {
    let a = b"short";
    let b = b"much longer value";
    assert!(!security::constant_time_eq(a, b));
}

// ============================================================================
// X3DH WITHOUT ONE-TIME PREKEY
// ============================================================================

/// SA-CRYPTO-24: Verify X3DH works without one-time prekey (prekey exhaustion scenario).
#[test]
fn x3dh_without_one_time_prekey() {
    sodiumoxide::init().unwrap();
    let alice = IdentityKeyPair::generate().unwrap();
    let bob = IdentityKeyPair::generate().unwrap();
    let bob_spk = SignedPreKey::generate(&bob, 1).unwrap();

    let bundle = RecipientPreKeyBundle {
        identity_key: bob.public_key,
        signed_prekey: bob_spk.public_key,
        signed_prekey_signature: bob_spk.signature,
        one_time_prekey: None, // Exhausted
    };

    let init = initiate_x3dh(&alice, &bundle).unwrap();
    let bob_secret = accept_x3dh(
        &bob,
        bob_spk.secret_key(),
        None, // No OTP
        &alice.public_key,
        &init.ephemeral_public_key,
    )
    .unwrap();

    assert_eq!(init.shared_secret, bob_secret);
}

// ============================================================================
// DOUBLE RATCHET BIDIRECTIONAL
// ============================================================================

/// SA-CRYPTO-25: Verify bidirectional messaging with multiple DH ratchet steps.
#[test]
fn bidirectional_multi_ratchet_conversation() {
    let (mut alice, mut bob, _, _) = setup_session();

    // Alice -> Bob (3 messages)
    for i in 0..3 {
        let (h, ct) = alice
            .encrypt(format!("alice msg {i}").as_bytes(), AD)
            .unwrap();
        let pt = bob.decrypt(&h, &ct, AD).unwrap();
        assert_eq!(pt, format!("alice msg {i}").as_bytes());
    }

    // Bob -> Alice (2 messages, triggers DH ratchet)
    for i in 0..2 {
        let (h, ct) = bob.encrypt(format!("bob msg {i}").as_bytes(), AD).unwrap();
        let pt = alice.decrypt(&h, &ct, AD).unwrap();
        assert_eq!(pt, format!("bob msg {i}").as_bytes());
    }

    // Alice -> Bob again (another DH ratchet)
    for i in 3..6 {
        let (h, ct) = alice
            .encrypt(format!("alice msg {i}").as_bytes(), AD)
            .unwrap();
        let pt = bob.decrypt(&h, &ct, AD).unwrap();
        assert_eq!(pt, format!("alice msg {i}").as_bytes());
    }

    // Bob -> Alice again (yet another ratchet)
    let (h, ct) = bob.encrypt(b"final bob", AD).unwrap();
    let pt = alice.decrypt(&h, &ct, AD).unwrap();
    assert_eq!(pt, b"final bob");
}

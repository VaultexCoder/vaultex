use std::collections::HashMap;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::scalarmult::curve25519;
use zeroize::Zeroize;

use crate::aes_gcm;
use crate::errors::{CryptoError, Result};

type HmacSha256 = Hmac<Sha256>;

const RATCHET_INFO: &[u8] = b"VAULTEX_RATCHET";
const CHAIN_KEY_SEED: &[u8] = &[0x01];
const MSG_KEY_SEED: &[u8] = &[0x02];
/// Maximum number of skipped message keys to store per session,
/// to prevent a malicious sender from forcing unbounded memory usage.
const MAX_SKIP: u32 = 1000;

/// Header sent with each ratchet message.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MessageHeader {
    pub ratchet_public_key: [u8; 32],
    pub previous_chain_length: u32,
    pub message_number: u32,
}

/// The Double Ratchet state for one session.
pub struct RatchetState {
    root_key: [u8; 32],
    sending_chain_key: Option<[u8; 32]>,
    receiving_chain_key: Option<[u8; 32]>,
    sending_keypair: Option<(box_::PublicKey, box_::SecretKey)>,
    remote_ratchet_key: Option<box_::PublicKey>,
    send_message_number: u32,
    recv_message_number: u32,
    previous_chain_length: u32,
    /// Cached message keys for out-of-order messages, indexed by
    /// (ratchet_public_key, message_number). Per the Signal spec,
    /// skipped keys are stored so late-arriving messages can be decrypted.
    skipped_keys: HashMap<([u8; 32], u32), [u8; 32]>,
}

/// Serializable representation of the ratchet state for database persistence.
#[derive(serde::Serialize, serde::Deserialize)]
struct RatchetStateSer {
    root_key: [u8; 32],
    sending_chain_key: Option<[u8; 32]>,
    receiving_chain_key: Option<[u8; 32]>,
    sending_public_key: Option<[u8; 32]>,
    sending_secret_key: Option<[u8; 32]>,
    remote_ratchet_key: Option<[u8; 32]>,
    send_message_number: u32,
    recv_message_number: u32,
    previous_chain_length: u32,
    skipped_keys: Vec<([u8; 32], u32, [u8; 32])>,
}

impl Drop for RatchetState {
    fn drop(&mut self) {
        self.root_key.zeroize();
        if let Some(ref mut ck) = self.sending_chain_key {
            ck.zeroize();
        }
        if let Some(ref mut ck) = self.receiving_chain_key {
            ck.zeroize();
        }
        // Zeroize all cached skipped message keys
        for (_key_id, mk) in self.skipped_keys.iter_mut() {
            mk.zeroize();
        }
        self.skipped_keys.clear();
    }
}

/// KDF_RK: derive new root key and chain key from a root key and DH output.
fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    let hk = Hkdf::<Sha256>::new(Some(root_key), dh_output);
    let mut output = [0u8; 64];
    hk.expand(RATCHET_INFO, &mut output)
        .map_err(|_| CryptoError::HkdfExpandFailed)?;
    let mut new_root = [0u8; 32];
    let mut chain_key = [0u8; 32];
    new_root.copy_from_slice(&output[..32]);
    chain_key.copy_from_slice(&output[32..]);
    output.zeroize();
    Ok((new_root, chain_key))
}

/// KDF_CK: advance chain key, producing a new chain key and a message key.
fn kdf_ck(chain_key: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    let mut mac_ck =
        HmacSha256::new_from_slice(chain_key).map_err(|_| CryptoError::HkdfExpandFailed)?;
    mac_ck.update(CHAIN_KEY_SEED);
    let new_chain_key_bytes = mac_ck.finalize().into_bytes();
    let mut new_chain_key = [0u8; 32];
    new_chain_key.copy_from_slice(&new_chain_key_bytes);

    let mut mac_mk =
        HmacSha256::new_from_slice(chain_key).map_err(|_| CryptoError::HkdfExpandFailed)?;
    mac_mk.update(MSG_KEY_SEED);
    let msg_key_bytes = mac_mk.finalize().into_bytes();
    let mut msg_key = [0u8; 32];
    msg_key.copy_from_slice(&msg_key_bytes);

    Ok((new_chain_key, msg_key))
}

/// Perform a DH between our secret key and their public key.
fn dh_exchange(our_sk: &box_::SecretKey, their_pk: &box_::PublicKey) -> Result<[u8; 32]> {
    let our_scalar = curve25519::Scalar::from_slice(&our_sk.0[..32])
        .ok_or(CryptoError::RatchetError("invalid secret key".into()))?;
    let their_ge = curve25519::GroupElement::from_slice(&their_pk.0)
        .ok_or(CryptoError::RatchetError("invalid public key".into()))?;
    let shared = curve25519::scalarmult(&our_scalar, &their_ge)
        .map_err(|_| CryptoError::RatchetError("DH failed".into()))?;
    Ok(shared.0)
}

impl RatchetState {
    /// Serialize the ratchet state to bytes for database persistence.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let ser = RatchetStateSer {
            root_key: self.root_key,
            sending_chain_key: self.sending_chain_key,
            receiving_chain_key: self.receiving_chain_key,
            sending_public_key: self.sending_keypair.as_ref().map(|(pk, _)| pk.0),
            sending_secret_key: self.sending_keypair.as_ref().map(|(_, sk)| sk.0),
            remote_ratchet_key: self.remote_ratchet_key.map(|pk| pk.0),
            send_message_number: self.send_message_number,
            recv_message_number: self.recv_message_number,
            previous_chain_length: self.previous_chain_length,
            skipped_keys: self
                .skipped_keys
                .iter()
                .map(|((rpk, mn), mk)| (*rpk, *mn, *mk))
                .collect(),
        };
        serde_json::to_vec(&ser).map_err(|e| CryptoError::SerializationError(e.to_string()))
    }

    /// Deserialize a ratchet state from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let ser: RatchetStateSer = serde_json::from_slice(bytes)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
        let sending_keypair = match (ser.sending_public_key, ser.sending_secret_key) {
            (Some(pk_bytes), Some(sk_bytes)) => {
                let pk = box_::PublicKey::from_slice(&pk_bytes).ok_or_else(|| {
                    CryptoError::SerializationError("invalid sending public key".into())
                })?;
                let sk = box_::SecretKey::from_slice(&sk_bytes).ok_or_else(|| {
                    CryptoError::SerializationError("invalid sending secret key".into())
                })?;
                Some((pk, sk))
            }
            _ => None,
        };
        let remote_ratchet_key = ser
            .remote_ratchet_key
            .and_then(|b| box_::PublicKey::from_slice(&b));
        let mut skipped_keys = HashMap::new();
        for (rpk, mn, mk) in ser.skipped_keys {
            skipped_keys.insert((rpk, mn), mk);
        }
        Ok(Self {
            root_key: ser.root_key,
            sending_chain_key: ser.sending_chain_key,
            receiving_chain_key: ser.receiving_chain_key,
            sending_keypair,
            remote_ratchet_key,
            send_message_number: ser.send_message_number,
            recv_message_number: ser.recv_message_number,
            previous_chain_length: ser.previous_chain_length,
            skipped_keys,
        })
    }

    /// Initialize the ratchet as the sender (Alice) after X3DH.
    ///
    /// Alice knows Bob's signed prekey (used as initial ratchet key).
    #[must_use = "ratchet initialization result must be checked"]
    pub fn init_sender(
        shared_secret: [u8; 32],
        recipient_ratchet_key: &box_::PublicKey,
    ) -> Result<Self> {
        sodiumoxide::init().map_err(|_| CryptoError::InitFailed)?;

        let (sending_pk, sending_sk) = box_::gen_keypair();
        let dh_out = dh_exchange(&sending_sk, recipient_ratchet_key)?;
        let (root_key, sending_chain_key) = kdf_rk(&shared_secret, &dh_out)?;

        Ok(Self {
            root_key,
            sending_chain_key: Some(sending_chain_key),
            receiving_chain_key: None,
            sending_keypair: Some((sending_pk, sending_sk)),
            remote_ratchet_key: Some(*recipient_ratchet_key),
            send_message_number: 0,
            recv_message_number: 0,
            previous_chain_length: 0,
            skipped_keys: HashMap::new(),
        })
    }

    /// Initialize the ratchet as the receiver (Bob) after X3DH.
    ///
    /// Bob uses his signed prekey pair as the initial ratchet keypair.
    pub fn init_receiver(
        shared_secret: [u8; 32],
        our_ratchet_keypair: (box_::PublicKey, box_::SecretKey),
    ) -> Self {
        Self {
            root_key: shared_secret,
            sending_chain_key: None,
            receiving_chain_key: None,
            sending_keypair: Some(our_ratchet_keypair),
            remote_ratchet_key: None,
            send_message_number: 0,
            recv_message_number: 0,
            previous_chain_length: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Encrypt a plaintext message, advancing the sending chain.
    #[must_use = "encryption result must be used; the ratchet state has already advanced"]
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(MessageHeader, Vec<u8>)> {
        let ck = self
            .sending_chain_key
            .as_ref()
            .ok_or_else(|| CryptoError::RatchetError("no sending chain key".into()))?;
        let (new_ck, msg_key) = kdf_ck(ck)?;
        self.sending_chain_key = Some(new_ck);

        let sending_pk = self
            .sending_keypair
            .as_ref()
            .ok_or_else(|| CryptoError::RatchetError("no sending keypair".into()))?
            .0;

        let header = MessageHeader {
            ratchet_public_key: sending_pk.0,
            previous_chain_length: self.previous_chain_length,
            message_number: self.send_message_number,
        };
        self.send_message_number += 1;

        // Encrypt with the message key using our AEAD
        let (nonce, ciphertext) = aes_gcm::encrypt(&msg_key, plaintext, Some(associated_data))?;

        // Prepend nonce to ciphertext
        let mut output = Vec::with_capacity(nonce.len() + ciphertext.len());
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);

        Ok((header, output))
    }

    /// Decrypt a received message, performing a DH ratchet step if needed.
    ///
    /// Per the Signal Double Ratchet specification, this method:
    /// 1. Checks the skipped message key cache first (for out-of-order messages).
    /// 2. If a new ratchet public key is seen, stores skipped keys from the
    ///    current receiving chain before performing the DH ratchet step.
    /// 3. Advances the receiving chain, caching any skipped intermediate keys.
    #[must_use = "decryption result must be checked for authentication failure"]
    pub fn decrypt(
        &mut self,
        header: &MessageHeader,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        // 1. Try the skipped message key cache first (out-of-order message)
        if let Some(mut msg_key) = self
            .skipped_keys
            .remove(&(header.ratchet_public_key, header.message_number))
        {
            let result = Self::decrypt_with_key(&msg_key, ciphertext, associated_data);
            msg_key.zeroize();
            return result;
        }

        let their_pk = box_::PublicKey::from_slice(&header.ratchet_public_key).ok_or(
            CryptoError::RatchetError("invalid ratchet key in header".into()),
        )?;

        // 2. Check if we need a DH ratchet step (new ratchet public key)
        let need_ratchet = match self.remote_ratchet_key {
            Some(ref remote) => remote.0 != their_pk.0,
            None => true,
        };

        if need_ratchet {
            // Before ratcheting, cache any skipped keys from the current receiving chain
            self.skip_message_keys_for_current_chain(header.previous_chain_length)?;
            self.dh_ratchet_step(&their_pk)?;
        }

        // 3. Advance receiving chain, caching skipped keys up to the target message
        self.skip_message_keys(header.message_number)?;

        // Derive the message key for the target message number
        let ck = self
            .receiving_chain_key
            .as_ref()
            .ok_or_else(|| CryptoError::RatchetError("no receiving chain key".into()))?;
        let (new_ck, mut msg_key) = kdf_ck(ck)?;
        self.receiving_chain_key = Some(new_ck);
        self.recv_message_number = header.message_number + 1;

        let result = Self::decrypt_with_key(&msg_key, ciphertext, associated_data);
        msg_key.zeroize();
        result
    }

    /// Decrypt ciphertext using a given message key.
    fn decrypt_with_key(
        msg_key: &[u8; 32],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let nonce_len = 24; // XChaCha20-Poly1305 nonce size
        if ciphertext.len() < nonce_len {
            return Err(CryptoError::DecryptionFailed);
        }
        let nonce = &ciphertext[..nonce_len];
        let ct = &ciphertext[nonce_len..];

        aes_gcm::decrypt(msg_key, nonce, ct, Some(associated_data))
    }

    /// Cache skipped message keys from the current receiving chain up to (but not
    /// including) the given count. Called before a DH ratchet step to preserve
    /// keys for messages that haven't arrived yet from the old chain.
    fn skip_message_keys_for_current_chain(&mut self, until: u32) -> Result<()> {
        if self.receiving_chain_key.is_none() {
            return Ok(());
        }
        let remote_pk = match self.remote_ratchet_key {
            Some(ref pk) => pk.0,
            None => return Ok(()),
        };

        if until < self.recv_message_number {
            return Ok(());
        }

        let skip_count = until - self.recv_message_number;
        if skip_count > MAX_SKIP {
            return Err(CryptoError::RatchetError(
                "too many skipped messages".into(),
            ));
        }

        let mut current_ck = self
            .receiving_chain_key
            .ok_or_else(|| CryptoError::RatchetError("no receiving chain key".into()))?;
        for n in self.recv_message_number..until {
            let (new_ck, mk) = kdf_ck(&current_ck)?;
            current_ck = new_ck;
            self.skipped_keys.insert((remote_pk, n), mk);
        }
        self.receiving_chain_key = Some(current_ck);
        self.recv_message_number = until;

        Ok(())
    }

    /// Cache skipped message keys in the current receiving chain up to (but not
    /// including) the target message number.
    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        if until < self.recv_message_number {
            return Err(CryptoError::RatchetError(
                "message number already consumed".into(),
            ));
        }

        let skip_count = until - self.recv_message_number;
        if skip_count > MAX_SKIP {
            return Err(CryptoError::RatchetError(
                "too many skipped messages".into(),
            ));
        }

        let remote_pk = match self.remote_ratchet_key {
            Some(ref pk) => pk.0,
            None => {
                return Err(CryptoError::RatchetError("no remote ratchet key".into()));
            }
        };

        let mut current_ck = self
            .receiving_chain_key
            .ok_or_else(|| CryptoError::RatchetError("no receiving chain key".into()))?;

        for n in self.recv_message_number..until {
            let (new_ck, mk) = kdf_ck(&current_ck)?;
            current_ck = new_ck;
            self.skipped_keys.insert((remote_pk, n), mk);
        }
        self.receiving_chain_key = Some(current_ck);

        Ok(())
    }

    /// Perform a DH ratchet step when receiving a new ratchet key.
    fn dh_ratchet_step(&mut self, their_new_pk: &box_::PublicKey) -> Result<()> {
        self.previous_chain_length = self.send_message_number;
        self.send_message_number = 0;
        self.recv_message_number = 0;
        self.remote_ratchet_key = Some(*their_new_pk);

        // Derive receiving chain key
        let our_sk = &self
            .sending_keypair
            .as_ref()
            .ok_or_else(|| CryptoError::RatchetError("no sending keypair".into()))?
            .1;
        let dh_recv = dh_exchange(our_sk, their_new_pk)?;
        let (new_root, recv_ck) = kdf_rk(&self.root_key, &dh_recv)?;
        self.root_key = new_root;
        self.receiving_chain_key = Some(recv_ck);

        // Generate new sending keypair and derive sending chain key
        let (new_pk, new_sk) = box_::gen_keypair();
        let dh_send = dh_exchange(&new_sk, their_new_pk)?;
        let (new_root, send_ck) = kdf_rk(&self.root_key, &dh_send)?;
        self.root_key = new_root;
        self.sending_chain_key = Some(send_ck);
        self.sending_keypair = Some((new_pk, new_sk));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratchet_encrypt_decrypt() {
        sodiumoxide::init().unwrap();
        let shared_secret = [0x42u8; 32];

        // Bob's initial ratchet keypair (his signed prekey)
        let (bob_pk, bob_sk) = box_::gen_keypair();

        let mut alice = RatchetState::init_sender(shared_secret, &bob_pk).unwrap();
        let mut bob = RatchetState::init_receiver(shared_secret, (bob_pk, bob_sk));

        let ad = b"session-id";
        let (header, ct) = alice.encrypt(b"hello bob", ad).unwrap();
        let pt = bob.decrypt(&header, &ct, ad).unwrap();
        assert_eq!(&pt, b"hello bob");
    }

    #[test]
    fn test_ratchet_bidirectional() {
        sodiumoxide::init().unwrap();
        let shared_secret = [0x55u8; 32];
        let (bob_pk, bob_sk) = box_::gen_keypair();

        let mut alice = RatchetState::init_sender(shared_secret, &bob_pk).unwrap();
        let mut bob = RatchetState::init_receiver(shared_secret, (bob_pk, bob_sk));

        let ad = b"test";

        // Alice -> Bob
        let (h1, ct1) = alice.encrypt(b"msg1", ad).unwrap();
        let pt1 = bob.decrypt(&h1, &ct1, ad).unwrap();
        assert_eq!(&pt1, b"msg1");

        // Bob -> Alice
        let (h2, ct2) = bob.encrypt(b"reply1", ad).unwrap();
        let pt2 = alice.decrypt(&h2, &ct2, ad).unwrap();
        assert_eq!(&pt2, b"reply1");

        // Alice -> Bob again
        let (h3, ct3) = alice.encrypt(b"msg2", ad).unwrap();
        let pt3 = bob.decrypt(&h3, &ct3, ad).unwrap();
        assert_eq!(&pt3, b"msg2");
    }

    #[test]
    fn test_ratchet_wrong_key_fails() {
        sodiumoxide::init().unwrap();
        let shared_secret = [0x42u8; 32];
        let wrong_secret = [0x43u8; 32];
        let (bob_pk, bob_sk) = box_::gen_keypair();

        let mut alice = RatchetState::init_sender(shared_secret, &bob_pk).unwrap();
        let mut bob = RatchetState::init_receiver(wrong_secret, (bob_pk, bob_sk));

        let ad = b"test";
        let (header, ct) = alice.encrypt(b"secret", ad).unwrap();
        let result = bob.decrypt(&header, &ct, ad);
        assert!(result.is_err());
    }

    #[test]
    fn test_out_of_order_same_chain() {
        // Alice sends 3 messages; Bob receives them in reverse order (msg2, msg1, msg0).
        // The skipped key cache must store keys for msg0 and msg1 when msg2 arrives.
        sodiumoxide::init().unwrap();
        let shared_secret = [0x42u8; 32];
        let (bob_pk, bob_sk) = box_::gen_keypair();

        let mut alice = RatchetState::init_sender(shared_secret, &bob_pk).unwrap();
        let mut bob = RatchetState::init_receiver(shared_secret, (bob_pk, bob_sk));

        let ad = b"ooo-test";

        // Alice encrypts 3 messages
        let (h0, ct0) = alice.encrypt(b"message 0", ad).unwrap();
        let (h1, ct1) = alice.encrypt(b"message 1", ad).unwrap();
        let (h2, ct2) = alice.encrypt(b"message 2", ad).unwrap();

        // Bob receives message 2 first — keys for 0 and 1 should be cached
        let pt2 = bob.decrypt(&h2, &ct2, ad).unwrap();
        assert_eq!(&pt2, b"message 2");
        assert_eq!(bob.skipped_keys.len(), 2);

        // Bob receives message 0 (from cache)
        let pt0 = bob.decrypt(&h0, &ct0, ad).unwrap();
        assert_eq!(&pt0, b"message 0");
        assert_eq!(bob.skipped_keys.len(), 1);

        // Bob receives message 1 (from cache)
        let pt1 = bob.decrypt(&h1, &ct1, ad).unwrap();
        assert_eq!(&pt1, b"message 1");
        assert_eq!(bob.skipped_keys.len(), 0);
    }

    #[test]
    fn test_out_of_order_skip_first_message() {
        // Alice sends 2 messages; Bob receives only the second, then the first.
        sodiumoxide::init().unwrap();
        let shared_secret = [0x77u8; 32];
        let (bob_pk, bob_sk) = box_::gen_keypair();

        let mut alice = RatchetState::init_sender(shared_secret, &bob_pk).unwrap();
        let mut bob = RatchetState::init_receiver(shared_secret, (bob_pk, bob_sk));

        let ad = b"skip";

        let (h0, ct0) = alice.encrypt(b"first", ad).unwrap();
        let (h1, ct1) = alice.encrypt(b"second", ad).unwrap();

        // Receive second message first
        let pt1 = bob.decrypt(&h1, &ct1, ad).unwrap();
        assert_eq!(&pt1, b"second");

        // Receive first message (late arrival, from skipped key cache)
        let pt0 = bob.decrypt(&h0, &ct0, ad).unwrap();
        assert_eq!(&pt0, b"first");
    }

    #[test]
    fn test_out_of_order_across_ratchet_steps() {
        // Alice sends msg0, msg1. Bob does NOT decrypt them yet.
        // Bob sends a reply (triggering a DH ratchet step on both sides).
        // Then Alice sends msg2 (on a new ratchet chain).
        // Bob receives msg2 first (new chain), then msg0 and msg1 (old chain).
        sodiumoxide::init().unwrap();
        let shared_secret = [0x99u8; 32];
        let (bob_pk, bob_sk) = box_::gen_keypair();

        let mut alice = RatchetState::init_sender(shared_secret, &bob_pk).unwrap();
        let mut bob = RatchetState::init_receiver(shared_secret, (bob_pk, bob_sk));

        let ad = b"cross-ratchet";

        // Alice sends two messages on first sending chain
        let (h0, ct0) = alice.encrypt(b"old chain 0", ad).unwrap();
        let (h1, ct1) = alice.encrypt(b"old chain 1", ad).unwrap();

        // Bob decrypts msg0 to bootstrap his receiving chain, then replies
        let pt0 = bob.decrypt(&h0, &ct0, ad).unwrap();
        assert_eq!(&pt0, b"old chain 0");

        let (h_reply, ct_reply) = bob.encrypt(b"bob reply", ad).unwrap();
        let pt_reply = alice.decrypt(&h_reply, &ct_reply, ad).unwrap();
        assert_eq!(&pt_reply, b"bob reply");

        // Alice sends a new message on her new sending chain
        let (h2, ct2) = alice.encrypt(b"new chain 0", ad).unwrap();

        // Bob receives the new chain message first — this triggers a DH ratchet step
        // and should cache the skipped key for msg1 from the old chain
        let pt2 = bob.decrypt(&h2, &ct2, ad).unwrap();
        assert_eq!(&pt2, b"new chain 0");

        // Now Bob receives msg1 from the old chain (should be in skipped cache)
        let pt1 = bob.decrypt(&h1, &ct1, ad).unwrap();
        assert_eq!(&pt1, b"old chain 1");
    }

    #[test]
    fn test_skipped_key_consumed_once() {
        // A skipped key should only decrypt its message once; replaying
        // the same message must fail (key removed from cache after use).
        sodiumoxide::init().unwrap();
        let shared_secret = [0xAAu8; 32];
        let (bob_pk, bob_sk) = box_::gen_keypair();

        let mut alice = RatchetState::init_sender(shared_secret, &bob_pk).unwrap();
        let mut bob = RatchetState::init_receiver(shared_secret, (bob_pk, bob_sk));

        let ad = b"replay";

        let (h0, ct0) = alice.encrypt(b"unreplayed", ad).unwrap();
        let (h1, ct1) = alice.encrypt(b"target", ad).unwrap();

        // Skip msg0, decrypt msg1
        let pt1 = bob.decrypt(&h1, &ct1, ad).unwrap();
        assert_eq!(&pt1, b"target");

        // Decrypt msg0 from cache
        let pt0 = bob.decrypt(&h0, &ct0, ad).unwrap();
        assert_eq!(&pt0, b"unreplayed");

        // Replaying msg0 must fail — key already consumed
        let result = bob.decrypt(&h0, &ct0, ad);
        assert!(result.is_err());
    }

    #[test]
    fn test_in_order_still_works() {
        // Ensure the normal in-order path hasn't regressed.
        sodiumoxide::init().unwrap();
        let shared_secret = [0xBBu8; 32];
        let (bob_pk, bob_sk) = box_::gen_keypair();

        let mut alice = RatchetState::init_sender(shared_secret, &bob_pk).unwrap();
        let mut bob = RatchetState::init_receiver(shared_secret, (bob_pk, bob_sk));

        let ad = b"in-order";

        for i in 0u32..10 {
            let msg = format!("message {}", i);
            let (h, ct) = alice.encrypt(msg.as_bytes(), ad).unwrap();
            let pt = bob.decrypt(&h, &ct, ad).unwrap();
            assert_eq!(pt, msg.as_bytes());
            // No skipped keys when messages arrive in order
            assert_eq!(bob.skipped_keys.len(), 0);
        }
    }
}

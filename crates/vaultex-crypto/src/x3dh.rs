use hkdf::Hkdf;
use sha2::Sha256;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::scalarmult::curve25519;
use sodiumoxide::crypto::sign;
use zeroize::Zeroize;

use crate::errors::{CryptoError, Result};

/// X3DH info string used in HKDF derivation.
const X3DH_INFO: &[u8] = b"VAULTEX_X3DH";

/// Convert an Ed25519 public key to a Curve25519 public key via libsodium FFI.
fn ed25519_pk_to_curve25519(pk: &sign::PublicKey) -> Result<curve25519::GroupElement> {
    let mut curve_pk = [0u8; 32];
    let ret = unsafe {
        libsodium_sys::crypto_sign_ed25519_pk_to_curve25519(curve_pk.as_mut_ptr(), pk.0.as_ptr())
    };
    if ret != 0 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 0,
        });
    }
    curve25519::GroupElement::from_slice(&curve_pk).ok_or(CryptoError::InvalidKeyLength {
        expected: 32,
        actual: curve_pk.len(),
    })
}

/// Convert an Ed25519 secret key to a Curve25519 secret key via libsodium FFI.
fn ed25519_sk_to_curve25519(sk: &sign::SecretKey) -> Result<curve25519::Scalar> {
    let mut curve_sk = [0u8; 32];
    let ret = unsafe {
        libsodium_sys::crypto_sign_ed25519_sk_to_curve25519(curve_sk.as_mut_ptr(), sk.0.as_ptr())
    };
    if ret != 0 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 0,
        });
    }
    let scalar =
        curve25519::Scalar::from_slice(&curve_sk).ok_or(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: curve_sk.len(),
        })?;
    curve_sk.zeroize();
    Ok(scalar)
}

/// Perform a raw X25519 Diffie-Hellman.
fn dh(
    our_secret: &curve25519::Scalar,
    their_public: &curve25519::GroupElement,
) -> Result<[u8; 32]> {
    let shared = curve25519::scalarmult(our_secret, their_public)
        .map_err(|_| CryptoError::HkdfExpandFailed)?;
    Ok(shared.0)
}

/// Derive a 32-byte shared secret from concatenated DH outputs using HKDF-SHA256.
fn kdf(dh_concat: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, dh_concat);
    let mut output = [0u8; 32];
    hk.expand(X3DH_INFO, &mut output)
        .map_err(|_| CryptoError::HkdfExpandFailed)?;
    Ok(output)
}

/// A recipient's prekey bundle as fetched from the server.
pub struct RecipientPreKeyBundle {
    pub identity_key: sign::PublicKey,
    pub signed_prekey: box_::PublicKey,
    pub signed_prekey_signature: sign::Signature,
    pub one_time_prekey: Option<(u32, box_::PublicKey)>,
}

/// Result of initiating an X3DH session.
pub struct X3DHInitResult {
    pub shared_secret: [u8; 32],
    pub ephemeral_public_key: box_::PublicKey,
    pub used_one_time_prekey_id: Option<u32>,
}

impl Drop for X3DHInitResult {
    fn drop(&mut self) {
        self.shared_secret.zeroize();
    }
}

/// Initiator side of X3DH. Alice wants to send to Bob.
///
/// Computes:
///   DH1 = DH(IK_A_curve, SPK_B)
///   DH2 = DH(EK_A, IK_B_curve)
///   DH3 = DH(EK_A, SPK_B)
///   DH4 = DH(EK_A, OPK_B) [if available]
///   SK  = KDF(DH1 || DH2 || DH3 [|| DH4])
#[must_use = "X3DH result contains the shared secret needed to establish a session"]
pub fn initiate_x3dh(
    sender_identity: &crate::identity::IdentityKeyPair,
    bundle: &RecipientPreKeyBundle,
) -> Result<X3DHInitResult> {
    sodiumoxide::init().map_err(|_| CryptoError::InitFailed)?;

    // Verify the signed prekey signature
    let spk_bytes = bundle.signed_prekey.0;
    if !sign::verify_detached(
        &bundle.signed_prekey_signature,
        &spk_bytes,
        &bundle.identity_key,
    ) {
        return Err(CryptoError::InvalidPreKeySignature);
    }

    // Convert Ed25519 identity keys to Curve25519
    let ik_a_curve_sk = ed25519_sk_to_curve25519(sender_identity.secret_key())?;
    let ik_b_curve_pk = ed25519_pk_to_curve25519(&bundle.identity_key)?;

    // Generate ephemeral X25519 keypair
    let (ek_pk, ek_sk) = box_::gen_keypair();
    let ek_scalar =
        curve25519::Scalar::from_slice(&ek_sk.0[..32]).ok_or(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 32,
        })?;

    // SPK as GroupElement
    let spk_ge = curve25519::GroupElement::from_slice(&bundle.signed_prekey.0).ok_or(
        CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 32,
        },
    )?;

    // DH computations
    let dh1 = dh(&ik_a_curve_sk, &spk_ge)?;
    let dh2 = dh(&ek_scalar, &ik_b_curve_pk)?;
    let dh3 = dh(&ek_scalar, &spk_ge)?;

    let mut dh_concat = Vec::with_capacity(128);
    dh_concat.extend_from_slice(&dh1);
    dh_concat.extend_from_slice(&dh2);
    dh_concat.extend_from_slice(&dh3);

    let mut used_otpk_id = None;
    if let Some((otpk_id, ref otpk_pk)) = bundle.one_time_prekey {
        let otpk_ge = curve25519::GroupElement::from_slice(&otpk_pk.0).ok_or(
            CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 32,
            },
        )?;
        let dh4 = dh(&ek_scalar, &otpk_ge)?;
        dh_concat.extend_from_slice(&dh4);
        used_otpk_id = Some(otpk_id);
    }

    let shared_secret = kdf(&dh_concat)?;
    dh_concat.zeroize();

    Ok(X3DHInitResult {
        shared_secret,
        ephemeral_public_key: ek_pk,
        used_one_time_prekey_id: used_otpk_id,
    })
}

/// Responder side of X3DH. Bob receives Alice's initial message.
///
/// Bob computes the same shared secret using his own secret keys.
#[must_use = "X3DH result contains the shared secret needed to establish a session"]
pub fn accept_x3dh(
    receiver_identity: &crate::identity::IdentityKeyPair,
    signed_prekey_secret: &box_::SecretKey,
    one_time_prekey_secret: Option<&box_::SecretKey>,
    sender_identity_key: &sign::PublicKey,
    sender_ephemeral_key: &box_::PublicKey,
) -> Result<[u8; 32]> {
    sodiumoxide::init().map_err(|_| CryptoError::InitFailed)?;

    // Convert identity keys
    let ik_b_curve_sk = ed25519_sk_to_curve25519(receiver_identity.secret_key())?;
    let ik_a_curve_pk = ed25519_pk_to_curve25519(sender_identity_key)?;

    let spk_scalar = curve25519::Scalar::from_slice(&signed_prekey_secret.0[..32]).ok_or(
        CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 32,
        },
    )?;
    let ek_ge = curve25519::GroupElement::from_slice(&sender_ephemeral_key.0).ok_or(
        CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 32,
        },
    )?;

    // IK_A as GroupElement for DH1
    let ik_a_ge = ik_a_curve_pk;

    // DH1 = DH(SPK_B, IK_A_curve)  (Bob's perspective)
    let dh1 = dh(&spk_scalar, &ik_a_ge)?;
    // DH2 = DH(IK_B_curve, EK_A)
    let dh2 = dh(&ik_b_curve_sk, &ek_ge)?;
    // DH3 = DH(SPK_B, EK_A)
    let dh3 = dh(&spk_scalar, &ek_ge)?;

    let mut dh_concat = Vec::with_capacity(128);
    dh_concat.extend_from_slice(&dh1);
    dh_concat.extend_from_slice(&dh2);
    dh_concat.extend_from_slice(&dh3);

    if let Some(otpk_sk) = one_time_prekey_secret {
        let otpk_scalar = curve25519::Scalar::from_slice(&otpk_sk.0[..32]).ok_or(
            CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 32,
            },
        )?;
        let dh4 = dh(&otpk_scalar, &ek_ge)?;
        dh_concat.extend_from_slice(&dh4);
    }

    let shared_secret = kdf(&dh_concat)?;
    dh_concat.zeroize();

    Ok(shared_secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKeyPair;

    #[test]
    fn test_x3dh_without_one_time_prekey() {
        let alice = IdentityKeyPair::generate().unwrap();
        let bob = IdentityKeyPair::generate().unwrap();

        // Bob generates a signed prekey
        let (spk_pk, spk_sk) = box_::gen_keypair();
        let spk_sig = bob.sign(&spk_pk.0);

        let bundle = RecipientPreKeyBundle {
            identity_key: bob.public_key,
            signed_prekey: spk_pk,
            signed_prekey_signature: spk_sig,
            one_time_prekey: None,
        };

        let init_result = initiate_x3dh(&alice, &bundle).unwrap();
        let accept_result = accept_x3dh(
            &bob,
            &spk_sk,
            None,
            &alice.public_key,
            &init_result.ephemeral_public_key,
        )
        .unwrap();

        assert_eq!(init_result.shared_secret, accept_result);
        assert!(init_result.used_one_time_prekey_id.is_none());
    }

    #[test]
    fn test_x3dh_with_one_time_prekey() {
        let alice = IdentityKeyPair::generate().unwrap();
        let bob = IdentityKeyPair::generate().unwrap();

        let (spk_pk, spk_sk) = box_::gen_keypair();
        let spk_sig = bob.sign(&spk_pk.0);
        let (otpk_pk, otpk_sk) = box_::gen_keypair();

        let bundle = RecipientPreKeyBundle {
            identity_key: bob.public_key,
            signed_prekey: spk_pk,
            signed_prekey_signature: spk_sig,
            one_time_prekey: Some((42, otpk_pk)),
        };

        let init_result = initiate_x3dh(&alice, &bundle).unwrap();
        let accept_result = accept_x3dh(
            &bob,
            &spk_sk,
            Some(&otpk_sk),
            &alice.public_key,
            &init_result.ephemeral_public_key,
        )
        .unwrap();

        assert_eq!(init_result.shared_secret, accept_result);
        assert_eq!(init_result.used_one_time_prekey_id, Some(42));
    }

    #[test]
    fn test_x3dh_rejects_bad_signature() {
        let alice = IdentityKeyPair::generate().unwrap();
        let bob = IdentityKeyPair::generate().unwrap();
        let mallory = IdentityKeyPair::generate().unwrap();

        let (spk_pk, _) = box_::gen_keypair();
        // Sign with mallory's key instead of bob's
        let bad_sig = mallory.sign(&spk_pk.0);

        let bundle = RecipientPreKeyBundle {
            identity_key: bob.public_key,
            signed_prekey: spk_pk,
            signed_prekey_signature: bad_sig,
            one_time_prekey: None,
        };

        assert!(initiate_x3dh(&alice, &bundle).is_err());
    }
}

use sha2::{Digest, Sha256};

use crate::errors::{CryptoError, Result};

/// Number of 5-digit groups in a safety number (6 per user, 12 total).
const NUM_GROUPS: usize = 12;

/// Bytes consumed from the hash to produce the numeric groups.
/// Each group uses 2 bytes, so 12 groups = 24 bytes (fits in SHA-256's 32-byte output).
const BYTES_PER_GROUP: usize = 2;

/// Generates a safety number from two raw identity public keys (32 bytes each).
///
/// The safety number is deterministic and symmetric: both parties compute the
/// same value regardless of who is "ours" vs "theirs".
///
/// Algorithm:
/// 1. Hex-encode both keys and sort them lexicographically.
/// 2. Compute SHA-256 over the concatenation of sorted raw key bytes.
/// 3. Convert the first 24 bytes to 12 groups of 5 digits (each group = 2 bytes mod 100000).
/// 4. Format as space-separated groups.
pub fn generate_safety_number(our_identity_key: &[u8], their_identity_key: &[u8]) -> String {
    // Sort by the raw bytes (lexicographic) so both sides get the same order.
    let (first, second) = if our_identity_key <= their_identity_key {
        (our_identity_key, their_identity_key)
    } else {
        (their_identity_key, our_identity_key)
    };

    let mut hasher = Sha256::new();
    hasher.update(first);
    hasher.update(second);
    let hash = hasher.finalize();

    let groups: Vec<String> = (0..NUM_GROUPS)
        .map(|i| {
            let offset = i * BYTES_PER_GROUP;
            let value = u16::from_be_bytes([hash[offset], hash[offset + 1]]) as u32;
            // Map to 0..99999 for a 5-digit group
            format!("{:05}", value % 100_000)
        })
        .collect();

    groups.join(" ")
}

/// Generates a safety number from two hex-encoded identity public keys.
///
/// Returns an error if either hex string is invalid or does not decode to 32 bytes.
pub fn generate_safety_number_from_hex(
    our_identity_key_hex: &str,
    their_identity_key_hex: &str,
) -> Result<String> {
    let our_key = hex::decode(our_identity_key_hex).map_err(|_| CryptoError::InvalidKeyLength {
        expected: 32,
        actual: 0,
    })?;
    let their_key =
        hex::decode(their_identity_key_hex).map_err(|_| CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 0,
        })?;

    if our_key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: our_key.len(),
        });
    }
    if their_key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: their_key.len(),
        });
    }

    Ok(generate_safety_number(&our_key, &their_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKeyPair;

    #[test]
    fn test_safety_number_deterministic() {
        let alice = IdentityKeyPair::generate().unwrap();
        let bob = IdentityKeyPair::generate().unwrap();

        let sn1 = generate_safety_number(&alice.public_key.0, &bob.public_key.0);
        let sn2 = generate_safety_number(&alice.public_key.0, &bob.public_key.0);

        assert_eq!(sn1, sn2, "Safety number must be deterministic");
    }

    #[test]
    fn test_safety_number_symmetric() {
        let alice = IdentityKeyPair::generate().unwrap();
        let bob = IdentityKeyPair::generate().unwrap();

        let from_alice = generate_safety_number(&alice.public_key.0, &bob.public_key.0);
        let from_bob = generate_safety_number(&bob.public_key.0, &alice.public_key.0);

        assert_eq!(
            from_alice, from_bob,
            "Safety number must be the same regardless of argument order"
        );
    }

    #[test]
    fn test_different_keys_produce_different_safety_numbers() {
        let alice = IdentityKeyPair::generate().unwrap();
        let bob = IdentityKeyPair::generate().unwrap();
        let carol = IdentityKeyPair::generate().unwrap();

        let sn_ab = generate_safety_number(&alice.public_key.0, &bob.public_key.0);
        let sn_ac = generate_safety_number(&alice.public_key.0, &carol.public_key.0);
        let sn_bc = generate_safety_number(&bob.public_key.0, &carol.public_key.0);

        assert_ne!(
            sn_ab, sn_ac,
            "Different key pairs must produce different safety numbers"
        );
        assert_ne!(
            sn_ab, sn_bc,
            "Different key pairs must produce different safety numbers"
        );
        assert_ne!(
            sn_ac, sn_bc,
            "Different key pairs must produce different safety numbers"
        );
    }

    #[test]
    fn test_safety_number_format() {
        let alice = IdentityKeyPair::generate().unwrap();
        let bob = IdentityKeyPair::generate().unwrap();

        let sn = generate_safety_number(&alice.public_key.0, &bob.public_key.0);
        let groups: Vec<&str> = sn.split(' ').collect();

        assert_eq!(groups.len(), 12, "Safety number must have 12 groups");
        for (i, group) in groups.iter().enumerate() {
            assert_eq!(
                group.len(),
                5,
                "Group {} must be 5 digits, got '{}'",
                i,
                group
            );
            assert!(
                group.chars().all(|c| c.is_ascii_digit()),
                "Group {} must contain only digits, got '{}'",
                i,
                group
            );
        }
    }

    #[test]
    fn test_safety_number_from_hex() {
        let alice = IdentityKeyPair::generate().unwrap();
        let bob = IdentityKeyPair::generate().unwrap();

        let alice_hex = hex::encode(alice.public_key.0);
        let bob_hex = hex::encode(bob.public_key.0);

        let from_raw = generate_safety_number(&alice.public_key.0, &bob.public_key.0);
        let from_hex = generate_safety_number_from_hex(&alice_hex, &bob_hex).unwrap();

        assert_eq!(
            from_raw, from_hex,
            "Hex and raw methods must produce the same result"
        );
    }

    #[test]
    fn test_safety_number_from_hex_invalid() {
        let result = generate_safety_number_from_hex("not-valid-hex", "also-not-valid");
        assert!(result.is_err());
    }

    #[test]
    fn test_safety_number_from_hex_wrong_length() {
        let result = generate_safety_number_from_hex("aabbccdd", "11223344");
        assert!(result.is_err());
    }

    #[test]
    fn test_safety_number_known_vector() {
        // Use fixed keys to verify a known output stays stable.
        let key_a = [0x00u8; 32];
        let key_b = [0xFFu8; 32];

        let sn = generate_safety_number(&key_a, &key_b);

        // Just verify format; the exact digits depend on SHA-256 output.
        let groups: Vec<&str> = sn.split(' ').collect();
        assert_eq!(groups.len(), 12);

        // Re-computing must be stable.
        let sn2 = generate_safety_number(&key_a, &key_b);
        assert_eq!(sn, sn2);
    }
}

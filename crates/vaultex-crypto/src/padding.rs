//! Message padding for traffic obfuscation.
//!
//! Pads messages to power-of-2 bucket sizes so that an observer cannot infer
//! message length from ciphertext size. The last two bytes of the padded output
//! store the padding length as a little-endian u16, allowing up to 65535 bytes
//! of padding. Random fill bytes precede the length suffix to prevent pattern
//! analysis.

use crate::errors::{CryptoError, Result};

/// Minimum padded message size in bytes.
const MIN_BUCKET: usize = 256;

/// Maximum single bucket size. Messages larger than this are padded to the
/// next multiple of `MAX_BUCKET`.
const MAX_BUCKET: usize = 65536;

/// Number of bytes used to encode the padding length at the end of the message.
const PAD_LEN_BYTES: usize = 4;

/// Pad a message to the next power-of-2 bucket size.
///
/// Minimum bucket: 256 bytes. Maximum bucket: 65536 bytes.
/// Messages larger than 65536 bytes are padded to the next multiple of 65536.
///
/// The padding format is:
/// `[plaintext] [random fill bytes] [pad_len as u16 LE]`
///
/// At least `PAD_LEN_BYTES` (2) bytes of padding are always added so the
/// length suffix is always present.
pub fn pad_message(plaintext: &[u8]) -> Result<Vec<u8>> {
    let target = bucket_size(plaintext.len());
    let pad_len = target - plaintext.len();

    if pad_len < PAD_LEN_BYTES {
        return Err(CryptoError::PaddingError(
            "computed padding too small for length encoding".into(),
        ));
    }

    let mut padded = Vec::with_capacity(target);
    padded.extend_from_slice(plaintext);

    // Fill padding region (excluding the final 4 length bytes) with random bytes
    let fill_len = pad_len - PAD_LEN_BYTES;
    if fill_len > 0 {
        let mut fill = vec![0u8; fill_len];
        sodiumoxide::randombytes::randombytes_into(&mut fill);
        padded.extend_from_slice(&fill);
    }

    // Append padding length as little-endian u32
    padded.extend_from_slice(&(pad_len as u32).to_le_bytes());

    debug_assert_eq!(padded.len(), target);
    Ok(padded)
}

/// Remove padding from a padded message.
///
/// Reads the last 2 bytes as a little-endian u16 padding length, validates
/// the length, and returns the original plaintext.
pub fn unpad_message(padded: &[u8]) -> Result<Vec<u8>> {
    if padded.len() < PAD_LEN_BYTES {
        return Err(CryptoError::PaddingError("padded message too short".into()));
    }

    let offset = padded.len() - PAD_LEN_BYTES;
    let len_bytes: [u8; 4] = [
        padded[offset],
        padded[offset + 1],
        padded[offset + 2],
        padded[offset + 3],
    ];
    let pad_len = u32::from_le_bytes(len_bytes) as usize;

    if pad_len < PAD_LEN_BYTES || pad_len > padded.len() {
        return Err(CryptoError::PaddingError("invalid padding length".into()));
    }

    let payload_len = padded.len() - pad_len;
    Ok(padded[..payload_len].to_vec())
}

/// Compute the bucket size for a given plaintext length.
///
/// Bucket sizes are powers of 2: 256, 512, 1024, ..., 65536.
/// The bucket must leave room for at least `PAD_LEN_BYTES` bytes of padding.
/// For messages >= MAX_BUCKET, we round up to the next multiple of MAX_BUCKET.
fn bucket_size(len: usize) -> usize {
    // We need room for at least PAD_LEN_BYTES of padding.
    let needed = len + PAD_LEN_BYTES;

    if needed <= MIN_BUCKET {
        return MIN_BUCKET;
    }

    if needed <= MAX_BUCKET {
        needed.next_power_of_two()
    } else {
        // Round up to next multiple of MAX_BUCKET
        needed.div_ceil(MAX_BUCKET) * MAX_BUCKET
    }
}

/// Generate a dummy/cover traffic message of the given padded size.
///
/// The returned bytes are random and indistinguishable from a real encrypted
/// message at the wire level. A special padding-length marker (0xFFFF) is
/// placed in the last two bytes so the recipient can detect and discard
/// dummy messages.
///
/// `size` is clamped to at least `MIN_BUCKET`.
pub fn generate_dummy_message(size: usize) -> Vec<u8> {
    let actual_size = if size < MIN_BUCKET { MIN_BUCKET } else { size };
    let mut buf = vec![0u8; actual_size];
    sodiumoxide::randombytes::randombytes_into(&mut buf);
    // Set last 4 bytes to 0xFFFFFFFF as dummy marker.
    // A real padded message can never have pad_len = u32::MAX because our
    // maximum padding is bounded by bucket sizes (at most 2 * MAX_BUCKET).
    let mark = actual_size - PAD_LEN_BYTES;
    buf[mark] = 0xFF;
    buf[mark + 1] = 0xFF;
    buf[mark + 2] = 0xFF;
    buf[mark + 3] = 0xFF;
    buf
}

/// Returns `true` if the message appears to be a dummy/cover traffic message.
///
/// Checks whether the last four bytes are the dummy marker (0xFFFFFFFF).
pub fn is_dummy_message(data: &[u8]) -> bool {
    if data.len() < PAD_LEN_BYTES {
        return false;
    }
    let offset = data.len() - PAD_LEN_BYTES;
    data[offset] == 0xFF
        && data[offset + 1] == 0xFF
        && data[offset + 2] == 0xFF
        && data[offset + 3] == 0xFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_unpad_roundtrip() {
        sodiumoxide::init().unwrap();
        let original = b"hello, vaultex!";
        let padded = pad_message(original).unwrap();
        let recovered = unpad_message(&padded).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_empty_message_pads_to_minimum() {
        sodiumoxide::init().unwrap();
        let padded = pad_message(b"").unwrap();
        assert_eq!(padded.len(), MIN_BUCKET);
        let recovered = unpad_message(&padded).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn test_all_bucket_sizes() {
        sodiumoxide::init().unwrap();
        // Messages should pad to the expected bucket sizes.
        // With PAD_LEN_BYTES = 4, a message of len L needs bucket >= L + 4.
        let cases = vec![
            (1, 256),
            (100, 256),
            (252, 256), // 252 + 4 = 256
            (253, 512), // 253 + 4 = 257 -> 512
            (256, 512),
            (300, 512),
            (508, 512),  // 508 + 4 = 512
            (509, 1024), // 509 + 4 = 513 -> 1024
            (512, 1024),
            (1000, 1024),
            (1020, 1024), // 1020 + 4 = 1024
            (1021, 2048), // 1021 + 4 = 1025 -> 2048
            (1024, 2048),
            (2044, 2048),
            (2045, 4096),
            (2048, 4096),
            (4092, 4096),
            (4093, 8192),
            (4096, 8192),
            (8188, 8192),
            (8189, 16384),
            (8192, 16384),
            (16380, 16384),
            (16381, 32768),
            (16384, 32768),
            (32764, 32768),
            (32765, 65536),
            (32768, 65536),
            (65532, 65536),
        ];
        for (msg_len, expected_bucket) in cases {
            let msg = vec![0x41u8; msg_len];
            let padded = pad_message(&msg).unwrap();
            assert_eq!(
                padded.len(),
                expected_bucket,
                "message of length {} should pad to {}, got {}",
                msg_len,
                expected_bucket,
                padded.len()
            );
        }
    }

    #[test]
    fn test_large_message_pads_to_multiple_of_max() {
        sodiumoxide::init().unwrap();
        let msg = vec![0x42u8; 65536];
        let padded = pad_message(&msg).unwrap();
        assert_eq!(padded.len(), 2 * MAX_BUCKET);

        let recovered = unpad_message(&padded).unwrap();
        assert_eq!(recovered, msg);
    }

    #[test]
    fn test_same_bucket_same_padded_length() {
        sodiumoxide::init().unwrap();
        let msg1 = vec![0x41u8; 10];
        let msg2 = vec![0x42u8; 200];
        let padded1 = pad_message(&msg1).unwrap();
        let padded2 = pad_message(&msg2).unwrap();
        assert_eq!(padded1.len(), padded2.len());
        assert_eq!(padded1.len(), 256);
    }

    #[test]
    fn test_corrupted_padding_detected() {
        sodiumoxide::init().unwrap();
        let mut padded = pad_message(b"test data").unwrap();
        // Set the padding length to something larger than the padded message
        let len = padded.len();
        // Encode pad_len = len + 1 (too large) in LE u32
        let bad_len = (len + 1) as u32;
        let bad_bytes = bad_len.to_le_bytes();
        padded[len - 4] = bad_bytes[0];
        padded[len - 3] = bad_bytes[1];
        padded[len - 2] = bad_bytes[2];
        padded[len - 1] = bad_bytes[3];
        let result = unpad_message(&padded);
        assert!(result.is_err());
    }

    #[test]
    fn test_unpad_empty_fails() {
        let result = unpad_message(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_unpad_too_short_fails() {
        let result = unpad_message(&[0x01]);
        assert!(result.is_err());
        let result = unpad_message(&[0x01, 0x02]);
        assert!(result.is_err());
        let result = unpad_message(&[0x01, 0x02, 0x03]);
        assert!(result.is_err());
    }

    #[test]
    fn test_unpad_zero_padding_length_fails() {
        // pad_len = 0 is invalid (minimum is PAD_LEN_BYTES = 4)
        let result = unpad_message(&[0x41, 0x00, 0x00, 0x00, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn test_unpad_small_padding_length_fails() {
        // pad_len < PAD_LEN_BYTES is invalid
        let result = unpad_message(&[0x41, 0x01, 0x00, 0x00, 0x00]); // pad_len = 1
        assert!(result.is_err());
        let result = unpad_message(&[0x41, 0x02, 0x00, 0x00, 0x00]); // pad_len = 2
        assert!(result.is_err());
        let result = unpad_message(&[0x41, 0x03, 0x00, 0x00, 0x00]); // pad_len = 3
        assert!(result.is_err());
    }

    #[test]
    fn test_padding_length_encoded_correctly() {
        sodiumoxide::init().unwrap();
        let msg = vec![0x41u8; 100];
        let padded = pad_message(&msg).unwrap();
        assert_eq!(padded.len(), 256);

        // Last 4 bytes should encode 256 - 100 = 156
        let pad_len = u32::from_le_bytes([padded[252], padded[253], padded[254], padded[255]]);
        assert_eq!(pad_len, 156);
    }

    #[test]
    fn test_max_size_boundary() {
        sodiumoxide::init().unwrap();
        // Message of exactly 252 bytes -> needs 256 bucket (252 + 4 = 256)
        let msg = vec![0x41u8; 252];
        let padded = pad_message(&msg).unwrap();
        assert_eq!(padded.len(), 256);
        // Padding length = 4 (just the length bytes themselves)
        let pad_len = u32::from_le_bytes([padded[252], padded[253], padded[254], padded[255]]);
        assert_eq!(pad_len, 4);
        let recovered = unpad_message(&padded).unwrap();
        assert_eq!(recovered, msg);
    }

    #[test]
    fn test_dummy_message_generation() {
        sodiumoxide::init().unwrap();
        let dummy = generate_dummy_message(512);
        assert_eq!(dummy.len(), 512);
        assert!(is_dummy_message(&dummy));
    }

    #[test]
    fn test_dummy_message_min_size() {
        sodiumoxide::init().unwrap();
        let dummy = generate_dummy_message(10);
        assert_eq!(dummy.len(), MIN_BUCKET);
    }

    #[test]
    fn test_real_message_not_dummy() {
        sodiumoxide::init().unwrap();
        // A padded real message should not be detected as dummy.
        // The last 2 bytes encode the padding length, which for a small message
        // in a 256-byte bucket will be a small number, not 0xFFFF.
        let padded = pad_message(b"real message").unwrap();
        assert!(!is_dummy_message(&padded));
    }

    #[test]
    fn test_pad_unpad_various_sizes() {
        sodiumoxide::init().unwrap();
        for size in [
            0, 1, 10, 127, 128, 251, 252, 253, 256, 500, 1020, 1021, 1024, 4000, 8188, 8189, 8192,
            16383, 32767, 65532, 65535,
        ] {
            let msg = vec![0x61u8; size];
            let padded = pad_message(&msg).unwrap();
            let recovered = unpad_message(&padded).unwrap();
            assert_eq!(recovered, msg, "roundtrip failed for size {}", size);
        }
    }

    #[test]
    fn test_different_messages_same_bucket_same_length() {
        sodiumoxide::init().unwrap();
        // Two different messages that both fall in the 256-byte bucket
        let padded_a = pad_message(b"short").unwrap();
        let padded_b = pad_message(b"a slightly longer message here").unwrap();
        assert_eq!(padded_a.len(), padded_b.len());
    }
}

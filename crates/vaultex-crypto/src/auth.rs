//! Client-side Ed25519 challenge-response authentication.
//!
//! Produces the headers needed to authenticate HTTP requests to the VAULTEX
//! server. The signature covers `METHOD:PATH:TIMESTAMP:BODY_HASH` to prevent
//! request tampering and replay attacks.

use sha2::{Digest, Sha256};

use crate::identity::IdentityKeyPair;

/// Headers produced by [`sign_request`] that the client must attach to every
/// authenticated HTTP request.
pub struct AuthHeader {
    /// The account UUID (as a string).
    pub account_id: String,
    /// Unix timestamp (seconds since epoch).
    pub timestamp: u64,
    /// Hex-encoded Ed25519 signature over the canonical request message.
    pub signature_hex: String,
}

/// Build the canonical message that is signed for authentication.
///
/// Format: `METHOD:PATH:TIMESTAMP:BODY_SHA256_HEX`
///
/// This is public so that tests and the server can reconstruct the same message.
pub fn build_signed_message(method: &str, path: &str, timestamp: u64, body: &[u8]) -> Vec<u8> {
    let body_hash = hex::encode(Sha256::digest(body));
    let message = format!("{}:{}:{}:{}", method, path, timestamp, body_hash);
    message.into_bytes()
}

/// Sign an HTTP request for challenge-response authentication.
///
/// # Arguments
///
/// - `identity` — The client's Ed25519 identity keypair.
/// - `account_id` — The client's account UUID string.
/// - `method` — HTTP method (e.g. `"GET"`, `"POST"`).
/// - `path` — Request path (e.g. `"/api/v1/messages/inbox"`).
/// - `body` — Request body bytes (empty slice for bodyless requests).
///
/// # Returns
///
/// An [`AuthHeader`] containing the account ID, timestamp, and hex-encoded
/// signature that should be sent as `X-Account-Id`, `X-Timestamp`, and
/// `X-Signature` headers respectively.
pub fn sign_request(
    identity: &IdentityKeyPair,
    account_id: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> AuthHeader {
    // SAFETY: SystemTime::now() is always after UNIX_EPOCH on any supported platform.
    // A pre-epoch clock would indicate a severely misconfigured system.
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    sign_request_with_timestamp(identity, account_id, method, path, body, timestamp)
}

/// Sign an HTTP request with an explicit timestamp.
///
/// This variant is useful for testing (to control the timestamp) and for
/// situations where the caller has already captured the current time.
pub fn sign_request_with_timestamp(
    identity: &IdentityKeyPair,
    account_id: &str,
    method: &str,
    path: &str,
    body: &[u8],
    timestamp: u64,
) -> AuthHeader {
    let message = build_signed_message(method, path, timestamp, body);
    let signature = identity.sign(&message);
    let signature_hex = hex::encode(signature.as_ref());

    AuthHeader {
        account_id: account_id.to_string(),
        timestamp,
        signature_hex,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKeyPair;
    use sodiumoxide::crypto::sign;

    #[test]
    fn test_sign_request_produces_valid_headers() {
        let identity = IdentityKeyPair::generate().unwrap();
        let account_id = "550e8400-e29b-41d4-a716-446655440000";

        let header = sign_request(&identity, account_id, "GET", "/api/v1/messages/inbox", b"");

        assert_eq!(header.account_id, account_id);
        assert!(header.timestamp > 0);
        // Signature should be 128 hex chars (64 bytes)
        assert_eq!(header.signature_hex.len(), 128);

        // Verify the signature is actually valid
        let message = build_signed_message("GET", "/api/v1/messages/inbox", header.timestamp, b"");
        let sig_bytes = hex::decode(&header.signature_hex).unwrap();
        let signature = sign::Signature::from_bytes(&sig_bytes).unwrap();
        assert!(IdentityKeyPair::verify(
            &identity.public_key,
            &message,
            &signature
        ));
    }

    #[test]
    fn test_different_bodies_produce_different_signatures() {
        let identity = IdentityKeyPair::generate().unwrap();
        let account_id = "550e8400-e29b-41d4-a716-446655440000";
        let timestamp = 1700000000u64;

        let header1 = sign_request_with_timestamp(
            &identity,
            account_id,
            "POST",
            "/api/v1/messages/send",
            b"body one",
            timestamp,
        );
        let header2 = sign_request_with_timestamp(
            &identity,
            account_id,
            "POST",
            "/api/v1/messages/send",
            b"body two",
            timestamp,
        );

        assert_ne!(header1.signature_hex, header2.signature_hex);
    }

    #[test]
    fn test_different_methods_produce_different_signatures() {
        let identity = IdentityKeyPair::generate().unwrap();
        let account_id = "test-account";
        let timestamp = 1700000000u64;

        let header1 = sign_request_with_timestamp(
            &identity,
            account_id,
            "GET",
            "/api/v1/keys/prekey_count",
            b"",
            timestamp,
        );
        let header2 = sign_request_with_timestamp(
            &identity,
            account_id,
            "POST",
            "/api/v1/keys/prekey_count",
            b"",
            timestamp,
        );

        assert_ne!(header1.signature_hex, header2.signature_hex);
    }

    #[test]
    fn test_different_paths_produce_different_signatures() {
        let identity = IdentityKeyPair::generate().unwrap();
        let account_id = "test-account";
        let timestamp = 1700000000u64;

        let header1 = sign_request_with_timestamp(
            &identity,
            account_id,
            "GET",
            "/api/v1/path/a",
            b"",
            timestamp,
        );
        let header2 = sign_request_with_timestamp(
            &identity,
            account_id,
            "GET",
            "/api/v1/path/b",
            b"",
            timestamp,
        );

        assert_ne!(header1.signature_hex, header2.signature_hex);
    }

    #[test]
    fn test_different_timestamps_produce_different_signatures() {
        let identity = IdentityKeyPair::generate().unwrap();
        let account_id = "test-account";

        let header1 = sign_request_with_timestamp(
            &identity,
            account_id,
            "GET",
            "/api/v1/test",
            b"",
            1700000000,
        );
        let header2 = sign_request_with_timestamp(
            &identity,
            account_id,
            "GET",
            "/api/v1/test",
            b"",
            1700000001,
        );

        assert_ne!(header1.signature_hex, header2.signature_hex);
    }

    #[test]
    fn test_build_signed_message_deterministic() {
        let msg1 = build_signed_message("GET", "/test", 12345, b"hello");
        let msg2 = build_signed_message("GET", "/test", 12345, b"hello");
        assert_eq!(msg1, msg2);
    }

    #[test]
    fn test_build_signed_message_format() {
        let msg = build_signed_message("POST", "/api/v1/test", 1700000000, b"");
        let msg_str = String::from_utf8(msg).unwrap();

        // Should contain method, path, timestamp, and SHA-256 of empty body
        assert!(msg_str.starts_with("POST:/api/v1/test:1700000000:"));
        // SHA-256 of empty string
        let empty_hash = hex::encode(Sha256::digest(b""));
        assert!(msg_str.ends_with(&empty_hash));
    }

    #[test]
    fn test_empty_body_signature_is_valid() {
        let identity = IdentityKeyPair::generate().unwrap();
        let timestamp = 1700000000u64;

        let header = sign_request_with_timestamp(
            &identity,
            "acct",
            "DELETE",
            "/api/v1/accounts/self",
            b"",
            timestamp,
        );

        let message = build_signed_message("DELETE", "/api/v1/accounts/self", timestamp, b"");
        let sig_bytes = hex::decode(&header.signature_hex).unwrap();
        let signature = sign::Signature::from_bytes(&sig_bytes).unwrap();
        assert!(IdentityKeyPair::verify(
            &identity.public_key,
            &message,
            &signature
        ));
    }
}

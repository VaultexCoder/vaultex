// EXTRACTED from crates/vaultex-server/src/middleware/auth.rs in the private VAULTEX monorepo.
// This file is published in isolation so the zero-knowledge
// authentication path can be reviewed. It will not compile
// standalone — see the upstream crate for the full context.

//! Ed25519 challenge-response authentication middleware.
//!
//! Every authenticated request must carry three headers:
//!
//! - `X-Account-Id`: the sender's account UUID.
//! - `X-Timestamp`: Unix timestamp (seconds). Must be within 300 s of server time.
//! - `X-Signature`: hex-encoded Ed25519 signature over `METHOD:PATH:TIMESTAMP:BODY_SHA256`.
//!
//! The middleware reconstructs the signed message, looks up the account's identity
//! public key from the database, and verifies the signature. On success, it
//! inserts an [`AuthenticatedUser`] into request extensions so that downstream
//! handlers can extract the caller's identity without re-parsing headers.
//!
//! The registration endpoint (`POST /api/v1/accounts/register`) and the health
//! check (`GET /api/v1/health`) are unauthenticated.

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::crypto::verify::verify_signature;
use crate::AppState;

/// Authenticated user info, inserted into request extensions after successful
/// signature verification.
#[derive(Clone, Debug)]
pub struct AuthenticatedUser {
    pub account_id: Uuid,
    pub identity_key_hex: String,
}

/// Maximum allowed clock skew between client and server (in seconds).
const MAX_TIMESTAMP_DRIFT_SECS: u64 = 300;

/// Routes that do not require authentication.
fn is_unauthenticated_route(method: &str, path: &str) -> bool {
    // Registration is unauthenticated — the client has no account yet.
    if method == "POST" && path == "/api/v1/accounts/register" {
        return true;
    }
    // Health check is always public.
    if method == "GET" && path == "/api/v1/health" {
        return true;
    }
    // Capability probe (#139) — clients call this BEFORE they have a session,
    // to confirm the URL is a real VAULTEX server. Returns only static service
    // metadata, so it is safe to serve unauthenticated.
    if method == "GET" && path == "/api/v1/ping" {
        return true;
    }
    // WebSocket upgrade is authenticated inside the WS handler.
    if path == "/ws" {
        return true;
    }
    // Account lookup by identity key (used during contact addition).
    if method == "GET" && path.starts_with("/api/v1/accounts/by-key/") {
        return true;
    }
    // Prekey bundle fetch (used during contact addition / X3DH initiation).
    if method == "GET" && path.contains("/prekey_bundle") {
        return true;
    }
    // Message send is unauthenticated in current design (sender identity is
    // inside the encrypted envelope — zero-knowledge model).
    if method == "POST" && path == "/api/v1/messages/send" {
        return true;
    }
    // Sealed sender message endpoint — unauthenticated by design (sender unknown).
    if method == "POST" && path == "/api/v1/messages/sealed" {
        return true;
    }
    false
}

/// Axum middleware that enforces Ed25519 challenge-response authentication.
pub async fn auth_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = request.method().as_str().to_uppercase();
    let path = request.uri().path().to_string();

    // Skip authentication for public endpoints.
    if is_unauthenticated_route(&method, &path) {
        return Ok(next.run(request).await);
    }

    // --- Extract required headers ---
    let headers = request.headers();

    let account_id_str = headers
        .get("X-Account-Id")
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_str()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let account_id = Uuid::parse_str(account_id_str).map_err(|_| StatusCode::BAD_REQUEST)?;

    let timestamp_str = headers
        .get("X-Timestamp")
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_str()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let timestamp: u64 = timestamp_str.parse().map_err(|_| StatusCode::BAD_REQUEST)?;

    let signature_hex = headers
        .get("X-Signature")
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_str()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let signature_bytes = hex::decode(signature_hex).map_err(|_| StatusCode::BAD_REQUEST)?;

    // --- Validate timestamp freshness (replay protection) ---
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let drift = now.abs_diff(timestamp);

    if drift > MAX_TIMESTAMP_DRIFT_SECS {
        tracing::warn!(
            account_id = %account_id,
            drift_secs = drift,
            "auth rejected: timestamp too far from server time"
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    // --- Look up the account's identity public key ---
    let account = state
        .db
        .get_account_by_id(account_id)
        .await
        .map_err(|e| {
            tracing::error!("auth: db lookup failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            tracing::warn!(account_id = %account_id, "auth rejected: unknown account");
            StatusCode::UNAUTHORIZED
        })?;

    let identity_key_bytes = hex::decode(account.identity_key_hex.trim()).map_err(|_| {
        tracing::error!(account_id = %account_id, "auth: corrupt identity key in DB");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // --- Reconstruct the signed message ---
    // We need the body bytes for the hash. Read the body, compute hash, then
    // put the body back so downstream handlers can still read it.
    let (parts, body) = request.into_parts();
    // Allow larger bodies for media upload (100 MiB), standard routes use 1 MiB
    let body_limit = if path.starts_with("/api/v1/media/") {
        100 * 1024 * 1024
    } else {
        1024 * 1024
    };
    let body_bytes = axum::body::to_bytes(body, body_limit)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let body_hash = hex::encode(Sha256::digest(&body_bytes));
    let signed_message = format!("{}:{}:{}:{}", method, path, timestamp, body_hash);

    // --- Verify the Ed25519 signature ---
    verify_signature(
        &identity_key_bytes,
        signed_message.as_bytes(),
        &signature_bytes,
    )
    .map_err(|e| {
        tracing::warn!(
            account_id = %account_id,
            error = %e,
            "auth rejected: signature verification failed"
        );
        StatusCode::UNAUTHORIZED
    })?;

    // --- Insert authenticated user into extensions ---
    let mut request = Request::from_parts(parts, Body::from(body_bytes));
    request.extensions_mut().insert(AuthenticatedUser {
        account_id,
        identity_key_hex: account.identity_key_hex.trim().to_string(),
    });

    Ok(next.run(request).await)
}

/// Legacy helper kept for backward compatibility during migration.
/// Prefer extracting [`AuthenticatedUser`] from request extensions instead.
pub fn extract_account_id(headers: &axum::http::HeaderMap) -> Result<Uuid, StatusCode> {
    let header_value = headers
        .get("X-Account-Id")
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_str()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    Uuid::parse_str(header_value).map_err(|_| StatusCode::BAD_REQUEST)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unauthenticated_routes() {
        assert!(is_unauthenticated_route(
            "POST",
            "/api/v1/accounts/register"
        ));
        assert!(is_unauthenticated_route("GET", "/api/v1/health"));
        assert!(is_unauthenticated_route("GET", "/api/v1/ping"));
        assert!(is_unauthenticated_route("GET", "/ws"));
        assert!(is_unauthenticated_route(
            "GET",
            "/api/v1/accounts/by-key/abcdef1234567890"
        ));
        assert!(is_unauthenticated_route("POST", "/api/v1/messages/send"));
        assert!(is_unauthenticated_route("POST", "/api/v1/messages/sealed"));

        assert!(!is_unauthenticated_route("GET", "/api/v1/messages/inbox"));
        assert!(!is_unauthenticated_route("DELETE", "/api/v1/accounts/self"));
        // Only GET /ping is public; other methods on the path are not.
        assert!(!is_unauthenticated_route("POST", "/api/v1/ping"));
    }

    #[test]
    fn test_timestamp_drift_calculation() {
        // Simulate the drift check logic
        let now = 1700000300u64;
        let timestamp = 1700000000u64;
        let drift = now - timestamp;
        assert_eq!(drift, 300);
        assert!(drift <= MAX_TIMESTAMP_DRIFT_SECS);

        let stale_timestamp = 1699999999u64;
        let stale_drift = now - stale_timestamp;
        assert_eq!(stale_drift, 301);
        assert!(stale_drift > MAX_TIMESTAMP_DRIFT_SECS);
    }

    #[test]
    fn test_future_timestamp_drift() {
        // Client clock is ahead
        let now = 1700000000u64;
        let future_timestamp = 1700000301u64;
        let drift = future_timestamp - now;
        assert_eq!(drift, 301);
        assert!(drift > MAX_TIMESTAMP_DRIFT_SECS);
    }

    #[test]
    fn test_extract_account_id_valid() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "X-Account-Id",
            "550e8400-e29b-41d4-a716-446655440000".parse().unwrap(),
        );
        let result = extract_account_id(&headers);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().to_string(),
            "550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn test_extract_account_id_missing() {
        let headers = axum::http::HeaderMap::new();
        let result = extract_account_id(&headers);
        assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_extract_account_id_invalid_uuid() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-Account-Id", "not-a-uuid".parse().unwrap());
        let result = extract_account_id(&headers);
        assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
    }
}

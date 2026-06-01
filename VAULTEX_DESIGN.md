# VAULTEX — Full-Stack Design Document
**Version:** 1.0  
**Status:** Architecture Draft  
**Target:** Phase 1 — Desktop (Linux/Windows) → Phase 2 — Android/iOS

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Threat Model & Security Philosophy](#2-threat-model--security-philosophy)
3. [System Architecture](#3-system-architecture)
4. [Cryptographic Design](#4-cryptographic-design)
5. [Backend — Server Infrastructure](#5-backend--server-infrastructure)
6. [Backend — API Design](#6-backend--api-design)
7. [Database Schema](#7-database-schema)
8. [Frontend — Desktop (Phase 1)](#8-frontend--desktop-phase-1)
9. [Networking & Transport Layer](#9-networking--transport-layer)
10. [Identity & Key Management](#10-identity--key-management)
11. [Mobile Porting Strategy (Phase 2)](#11-mobile-porting-strategy-phase-2)
12. [Directory Structure](#12-directory-structure)
13. [Tech Stack Summary](#13-tech-stack-summary)
14. [Development Roadmap](#14-development-roadmap)
15. [Deployment Architecture](#15-deployment-architecture)
16. [Security Audit Checklist](#16-security-audit-checklist)

---

## 1. Project Overview

VAULTEX is a zero-knowledge, end-to-end encrypted messaging application designed to address the fundamental weaknesses of existing secure messaging solutions:

| Problem | Existing Apps | VAULTEX Approach |
|---|---|---|
| Server-side metadata | Stored by provider | Never collected |
| Endpoint vulnerability | App-level only | OS-level sandboxing |
| Key management | Provider-assisted | User-sovereign keys |
| Identity linkage | Phone number / email | Cryptographic identity only |
| Forward secrecy | Optional / partial | Mandatory, per-message |
| Mesh capability | None | Built-in relay mesh |

### Core Principles
- **Zero-trust server**: The server never has enough information to reconstruct any message or identify any user
- **Sovereign identity**: Users generate and control all cryptographic keys locally
- **Defense in depth**: Encryption at message, transport, and storage layers
- **Open protocol**: Fully auditable, no proprietary black boxes

---

## 2. Threat Model & Security Philosophy

### Adversaries Considered

```
┌─────────────────────────────────────────────────────┐
│  THREAT LEVEL 1 — Commercial / Data Broker          │
│  Goal: Harvest metadata, contacts, behavior         │
│  Mitigation: No phone numbers, no social graph      │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  THREAT LEVEL 2 — Nation-State Passive              │
│  Goal: Mass surveillance, traffic analysis          │
│  Mitigation: Sealed sender, traffic obfuscation,   │
│              decoy traffic, Tor/I2P transport       │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  THREAT LEVEL 3 — Nation-State Active               │
│  Goal: Targeted intercept, server compromise        │
│  Mitigation: E2E crypto, zero server plaintext,     │
│              reproducible builds, canary tokens     │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  THREAT LEVEL 4 — Endpoint Compromise               │
│  Goal: Access device, extract keys/messages         │
│  Mitigation: Secure enclave storage, memory zeroing,│
│              duress PIN, remote wipe                │
└─────────────────────────────────────────────────────┘
```

### What We Protect
- **Message content** — AES-256-GCM, encrypted client-side before transmission
- **Message metadata** — Who talked to whom, when, how often (sealed sender hides recipient)
- **Identity** — No real-world linkage required (no phone/email verification)
- **Social graph** — Contact lists stored encrypted locally, never sent to server
- **IP addresses** — Onion routing / relay hop obfuscation

### What We Do NOT Protect Against
- Physical device seizure with user cooperation (duress PIN partially mitigates)
- Compromised client binary (mitigated by reproducible builds + code signing)
- Rubber-hose cryptanalysis (out of scope for software)

---

## 3. System Architecture

### High-Level Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                         CLIENT DEVICE                            │
│                                                                  │
│  ┌─────────────────┐    ┌────────────────┐   ┌───────────────┐  │
│  │   UI Layer      │    │  Crypto Engine │   │  Local Store  │  │
│  │  (Tauri/React)  │◄──►│  (Rust/libsodium)│◄►│  (SQLCipher) │  │
│  └────────┬────────┘    └────────────────┘   └───────────────┘  │
│           │                                                       │
│  ┌────────▼────────┐    ┌────────────────┐                       │
│  │  Network Layer  │    │  Key Manager   │                       │
│  │  (Tokio/TLS1.3) │    │  (OS Keychain) │                       │
│  └────────┬────────┘    └────────────────┘                       │
└───────────┼──────────────────────────────────────────────────────┘
            │ WSS / HTTPS (TLS 1.3 only)
            │ Optional: Tor / I2P transport
            ▼
┌───────────────────────────────────────────────────────────────┐
│                      SERVER CLUSTER                           │
│                                                               │
│  ┌─────────────┐  ┌─────────────┐  ┌────────────────────┐   │
│  │  API Gateway│  │  WebSocket  │  │  Message Queue     │   │
│  │  (Nginx)    │  │  Relay      │  │  (Redis Streams)   │   │
│  └──────┬──────┘  └──────┬──────┘  └────────┬───────────┘   │
│         │                │                   │               │
│  ┌──────▼────────────────▼───────────────────▼───────────┐   │
│  │              Application Server (Rust/Axum)           │   │
│  └───────────────────────────┬───────────────────────────┘   │
│                              │                               │
│  ┌───────────────────────────▼───────────────────────────┐   │
│  │        Database (PostgreSQL + Redis)                   │   │
│  │  ONLY stores: encrypted blobs, delivery receipts,     │   │
│  │  public keys, sealed-sender tokens                     │   │
│  └───────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Technology | Responsibility |
|---|---|---|
| UI Shell | Tauri 2.x | Native desktop window, OS integration |
| UI Frontend | React 18 + TypeScript | All user-facing screens |
| Crypto Engine | Rust (libsodium bindings) | All cryptographic operations |
| Local Database | SQLCipher | Encrypted local message store |
| Network Client | Tokio + rustls | WebSocket connections, HTTP |
| Key Store | OS Keychain (libsecret / DPAPI) | Master key storage |
| API Server | Rust / Axum | HTTP endpoints |
| Message Relay | Rust / Tokio WebSockets | Real-time message delivery |
| Queue | Redis Streams | Offline message buffering |
| Database | PostgreSQL 16 | Server-side metadata (minimal) |
| Proxy Layer | Nginx | TLS termination, rate limiting |

---

## 4. Cryptographic Design

### Key Hierarchy

```
┌─────────────────────────────────────────────────────┐
│  MASTER IDENTITY KEY PAIR                           │
│  Algorithm: Ed25519 (signing)                       │
│  Generated: Once, on first launch                   │
│  Storage:   OS Keychain / Secure Enclave            │
│  Never leaves device                                │
└──────────────┬──────────────────────────────────────┘
               │ Derives
               ▼
┌─────────────────────────────────────────────────────┐
│  SIGNED PREKEY PAIR                                 │
│  Algorithm: X25519 (key agreement)                  │
│  Rotation: Every 7 days                             │
│  Published: Public key to server                    │
└──────────────┬──────────────────────────────────────┘
               │ Combined with
               ▼
┌─────────────────────────────────────────────────────┐
│  ONE-TIME PREKEYS (OPK)                             │
│  Algorithm: X25519                                  │
│  Quantity: 100 pre-generated, replenished           │
│  Purpose: Extended Triple Diffie-Hellman (X3DH)    │
└──────────────┬──────────────────────────────────────┘
               │ Produces
               ▼
┌─────────────────────────────────────────────────────┐
│  SESSION ROOT KEY                                   │
│  Algorithm: HKDF-SHA256 from X3DH output            │
│  Feeds into Double Ratchet                          │
└──────────────┬──────────────────────────────────────┘
               │ Drives
               ▼
┌─────────────────────────────────────────────────────┐
│  MESSAGE KEYS (per-message)                         │
│  Algorithm: Double Ratchet (Signal Protocol)        │
│  Encryption: AES-256-GCM                            │
│  Deleted after decryption (forward secrecy)         │
└─────────────────────────────────────────────────────┘
```

### Protocol Stack

```
Layer 1 — Identity:       Ed25519 keypair (signing + verification)
Layer 2 — Key Agreement:  X3DH (Extended Triple Diffie-Hellman)
Layer 3 — Ratchet:        Double Ratchet Algorithm
Layer 4 — Encryption:     AES-256-GCM (AEAD)
Layer 5 — Transport:      TLS 1.3 (minimum) over WebSocket
Layer 6 — Optional:       Tor hidden service OR I2P tunnel
```

### Sealed Sender

To hide who is sending messages (metadata protection):

```
Standard:  Server knows: Sender A → Recipient B
Sealed:    Server knows: Someone → Recipient B
           (sender identity encrypted to recipient's public key)

Implementation:
1. Encrypt sender's certificate under recipient's X25519 public key
2. Append to message envelope
3. Server routes by recipient handle only
4. Recipient decrypts envelope to learn sender identity
```

### Message Envelope Format

```
MESSAGE ENVELOPE (on wire, binary serialized with MessagePack):

{
  version:          u8,           // Protocol version
  recipient_id:     [u8; 32],     // Recipient's public key hash
  sealed_sender:    Vec<u8>,      // Encrypted sender cert
  message_body:     Vec<u8>,      // AES-256-GCM ciphertext
  ratchet_key:      [u8; 32],     // Current DH ratchet public key
  prev_chain_len:   u32,          // Previous chain message count
  message_number:   u32,          // Position in current chain
  nonce:            [u8; 12],     // AES-GCM nonce (random)
  auth_tag:         [u8; 16],     // GCM authentication tag
  timestamp_range:  [u64; 2],     // Fuzzy timestamp (obfuscated)
}
```

### Self-Destructing Messages

```
Self-destruct implemented client-side:
1. Message carries TTL field (seconds) in encrypted body
2. Recipient client sets a local timer on decrypt
3. On timer fire: zero-wipe from SQLCipher DB + UI removal
4. Sender also deletes on same TTL if desired
5. Server NEVER stores plaintext — automatic after delivery
```

---

## 5. Backend — Server Infrastructure

### Server Stack

```
Language:   Rust (Axum framework)
Runtime:    Tokio async runtime
Database:   PostgreSQL 16 (primary) + Redis 7 (cache/queue)
Proxy:      Nginx (TLS termination + rate limiting)
Containers: Docker + Docker Compose (Phase 1)
Orchestration: Kubernetes (Phase 2+)
```

### What the Server Stores (and Does NOT Store)

```
STORED ON SERVER:
✓ User public keys (Ed25519 identity, X25519 prekeys)
✓ Encrypted message blobs (can't decrypt — no keys)
✓ Delivery status tokens (opaque, no content info)
✓ Rate limiting counters (IP-keyed, not identity-keyed)
✓ Account handle → public key mapping

NEVER STORED ON SERVER:
✗ Private keys (never transmitted)
✗ Message plaintext
✗ Contact lists
✗ IP addresses (stripped by nginx before hitting app)
✗ Device fingerprints
✗ Read receipts (optional, user-controlled)
✗ Real names, phone numbers, emails
```

### Server Modules

```
src/
├── main.rs                  # Entry point, server bootstrap
├── api/
│   ├── accounts.rs          # Account registration / prekey upload
│   ├── messages.rs          # Message send / receive endpoints
│   ├── keys.rs              # Prekey bundle retrieval
│   ├── delivery.rs          # Delivery receipt endpoints
│   └── admin.rs             # Admin endpoints (rate limits, bans)
├── websocket/
│   ├── handler.rs           # WebSocket upgrade + session mgmt
│   ├── relay.rs             # Message routing logic
│   └── presence.rs          # Online/offline status (anonymized)
├── crypto/
│   ├── verify.rs            # Signature verification
│   └── sealed_sender.rs     # Sealed sender validation
├── db/
│   ├── postgres.rs          # PostgreSQL connection pool
│   ├── redis.rs             # Redis connection pool
│   ├── accounts.rs          # Account queries
│   ├── messages.rs          # Message queue queries
│   └── keys.rs              # Prekey bundle queries
├── middleware/
│   ├── auth.rs              # Request authentication
│   ├── rate_limit.rs        # Rate limiting
│   └── strip_ip.rs          # IP stripping middleware
└── models/
    ├── account.rs
    ├── message.rs
    └── prekey.rs
```

---

## 6. Backend — API Design

### REST Endpoints

```
BASE URL: https://relay.vaultex.local/api/v1

ACCOUNTS
────────
POST   /accounts/register
  Body: { identity_key: hex, signed_prekey: bundle, one_time_prekeys: [bundle] }
  Returns: { account_id: uuid }
  Note: No email/phone. account_id is a random UUID, not linked to identity.

POST   /accounts/prekeys
  Body: { signed_prekey: bundle, one_time_prekeys: [bundle] }
  Auth: Signature over request body using identity key
  Returns: 204 No Content

GET    /accounts/{recipient_id}/prekey_bundle
  Returns: { identity_key, signed_prekey, one_time_prekey }
  Note: Fetching a prekey is anonymous, no auth required

DELETE /accounts/self
  Auth: Signature proof of key ownership
  Purges all stored data

MESSAGES
────────
POST   /messages/send
  Body: { envelope: MessageEnvelope (binary/base64) }
  Auth: Sealed sender (server cannot identify sender)
  Returns: { delivery_token: uuid }

GET    /messages/inbox
  Auth: Challenge-response, proves key ownership
  Returns: [ { delivery_token, envelope } ] — encrypted blobs only
  Note: Server marks as delivered; client ACKs deletion

DELETE /messages/inbox/{delivery_token}
  Auth: Key ownership proof
  Returns: 204 No Content

KEYS
────
GET    /keys/prekey_count
  Auth: Key ownership proof
  Returns: { one_time_prekey_count: u32 }

DISCOVERY (opt-in, default off)
───────────────────────────────
POST   /users/me/discoverable
  Body: { enabled: bool, display_name?: string }
  Auth: Key ownership proof
  Returns: 204 No Content
  Note: Enabling stores the optional display name + timestamp; disabling clears
        them. Relaxes only metadata privacy (display name) for opted-in users;
        E2E encryption is unaffected. Default is off.

GET    /users/me/discoverable
  Auth: Key ownership proof
  Returns: { enabled: bool, display_name?: string }
  Note: Read-back so the client reflects the true server state.

GET    /users?q=<substring>
  Auth: Key ownership proof
  Returns: { users: [ { account_id, identity_key_hex, display_name? } ] }
  Note: Only opted-in, non-suspended users. Rate-limited per account, capped,
        caller excluded. The query is matched literally (LIKE wildcards escaped).
        Clients MUST show the fingerprint before adding (trust-on-first-use).

HEALTH
──────
GET    /health
  Returns: { status: "ok", version: "1.0.0" }
  Note: For ops monitoring.

GET    /ping
  Unauthenticated.
  Returns: { service: "vaultex", version, min_client_version, capabilities: [string] }
  Note: Client pre-flight — confirm a URL is a real VAULTEX server and
        feature-detect before the authenticated WebSocket handshake.
```

### WebSocket Protocol

```
WS URL: wss://relay.vaultex.local/ws

AUTHENTICATION:
  Client sends: { type: "auth", challenge_response: hex, public_key: hex }
  Server sends: { type: "auth_ok" } or { type: "auth_fail" }

MESSAGE EVENTS:
  Server → Client: { type: "message", envelope: base64 }
  Client → Server: { type: "ack", delivery_token: uuid }
  Client → Server: { type: "typing_enc", recipient_id: hex }  // encrypted blob
  Server → Client: { type: "typing_enc", blob: base64 }

PRESENCE (anonymized):
  Client → Server: { type: "ping" }      // keepalive, proves online
  Server → Client: { type: "pong" }

DISCONNECT:
  Client → Server: { type: "goodbye" }   // server clears session
```

---

## 7. Database Schema

### PostgreSQL Tables

```sql
-- Accounts: minimal, no PII
CREATE TABLE accounts (
    account_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_key_hex    CHAR(64) UNIQUE NOT NULL,   -- Ed25519 public key
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    last_active_bucket  SMALLINT,                   -- hour-of-week bucket (0-167), not exact time
    suspended           BOOLEAN DEFAULT FALSE
);

-- Signed Prekeys (one per account, rotated weekly)
CREATE TABLE signed_prekeys (
    account_id          UUID REFERENCES accounts(account_id) ON DELETE CASCADE,
    prekey_id           INTEGER NOT NULL,
    public_key_hex      CHAR(64) NOT NULL,
    signature_hex       CHAR(128) NOT NULL,         -- Signed by identity key
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (account_id, prekey_id)
);

-- One-Time Prekeys (100 per account, consumed on use)
CREATE TABLE one_time_prekeys (
    id                  BIGSERIAL PRIMARY KEY,
    account_id          UUID REFERENCES accounts(account_id) ON DELETE CASCADE,
    prekey_id           INTEGER NOT NULL,
    public_key_hex      CHAR(64) NOT NULL,
    consumed            BOOLEAN DEFAULT FALSE,
    UNIQUE (account_id, prekey_id)
);

-- Message Queue (encrypted blobs waiting for offline recipients)
CREATE TABLE message_queue (
    delivery_token      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    recipient_id        UUID REFERENCES accounts(account_id) ON DELETE CASCADE,
    envelope_data       BYTEA NOT NULL,             -- Fully encrypted blob
    received_at         TIMESTAMPTZ DEFAULT NOW(),
    expires_at          TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '30 days'),
    delivered           BOOLEAN DEFAULT FALSE
);
CREATE INDEX idx_queue_recipient ON message_queue(recipient_id, delivered);
CREATE INDEX idx_queue_expires ON message_queue(expires_at);

-- Rate Limiting (no identity linkage — IP hash only)
CREATE TABLE rate_limits (
    ip_hash             CHAR(64) PRIMARY KEY,       -- SHA-256 of IP, salted
    request_count       INTEGER DEFAULT 0,
    window_start        TIMESTAMPTZ DEFAULT NOW()
);
```

### Redis Data Structures

```
# Active WebSocket Sessions
HSET session:{account_id}  socket_id  connection_id
EXPIRE session:{account_id} 86400

# Online Presence (anonymized bucket — not exact)
SADD online_users  {account_id}
# TTL set by keepalive pings

# Pending Delivery Notifications
LIST pending:{account_id}   → delivery_token UUIDs
# WebSocket relay reads from this list

# Rate Limiting (sliding window)
ZADD ratelimit:{ip_hash}  {timestamp}  {request_id}
EXPIRE ratelimit:{ip_hash} 3600
```

---

## 8. Frontend — Desktop (Phase 1)

### Technology

```
Shell:         Tauri 2.x (Rust backend + WebView2/WebKitGTK)
UI Framework:  React 18 + TypeScript
Styling:       Tailwind CSS + custom CSS variables
State:         Zustand (lightweight, no Redux overhead)
Routing:       React Router v6 (in-app navigation)
Build:         Vite
Local DB:      better-sqlite3-sqlcipher (Node bindings)
Crypto:        @tauri-apps/api + Rust sidecar process
```

### Why Tauri (not Electron)

| Factor | Electron | Tauri |
|---|---|---|
| Binary size | ~150MB | ~10MB |
| Memory usage | ~300MB | ~30MB |
| Security | Chromium sandbox | OS WebView (more isolated) |
| Rust integration | Via N-API | Native |
| Code signing | External | Built-in |

### Screen Map

```
VAULTEX Desktop App — Screen Flow

┌──────────────────────────────────────────────┐
│  ONBOARDING FLOW (First launch only)         │
│                                              │
│  WelcomeScreen                               │
│    → KeygenScreen     (generate Ed25519 pair)│
│    → BackupScreen     (seed phrase export)   │
│    → PinSetupScreen   (app lock PIN)         │
│    → DuressSetupScreen (optional duress PIN) │
│    → MainApp                                 │
└──────────────────────────────────────────────┘

┌──────────────────────────────────────────────┐
│  MAIN APP LAYOUT                             │
│                                              │
│  ┌──────────┬──────────────────┬──────────┐  │
│  │ Sidebar  │  Chat Window     │ InfoPanel│  │
│  │          │                  │ (toggle) │  │
│  │ Contact  │  MessageList     │          │  │
│  │ List     │                  │ Key Info │  │
│  │          │  InputArea       │ Session  │  │
│  │ NavIcons │                  │ Stats    │  │
│  └──────────┴──────────────────┴──────────┘  │
└──────────────────────────────────────────────┘

┌──────────────────────────────────────────────┐
│  SETTINGS SCREENS                            │
│                                              │
│  Settings/
│    ├── ProfileScreen      (identity key info)│
│    ├── SecurityScreen     (PIN, duress, wipe)│
│    ├── PrivacyScreen      (read receipts,    │
│    │                       typing indicators)│
│    ├── NetworkScreen      (Tor, proxy, relay)│
│    ├── NotificationsScreen                   │
│    └── BackupScreen       (key export)       │
└──────────────────────────────────────────────┘
```

### Frontend Directory Structure

```
src/
├── main.tsx                    # React entry point
├── App.tsx                     # Root + routing
├── store/
│   ├── authStore.ts            # Authentication state
│   ├── contactsStore.ts        # Contact list (encrypted local)
│   ├── messagesStore.ts        # Active conversation messages
│   ├── uiStore.ts              # UI state (panels, theme)
│   └── networkStore.ts         # Connection status
├── screens/
│   ├── onboarding/
│   │   ├── Welcome.tsx
│   │   ├── KeyGen.tsx
│   │   ├── Backup.tsx
│   │   └── PinSetup.tsx
│   ├── main/
│   │   ├── MainLayout.tsx
│   │   ├── Sidebar.tsx
│   │   ├── ChatWindow.tsx
│   │   ├── MessageList.tsx
│   │   ├── MessageBubble.tsx
│   │   ├── InputArea.tsx
│   │   └── InfoPanel.tsx
│   └── settings/
│       ├── ProfileSettings.tsx
│       ├── SecuritySettings.tsx
│       ├── NetworkSettings.tsx
│       └── PrivacySettings.tsx
├── components/
│   ├── Avatar.tsx
│   ├── ContactItem.tsx
│   ├── EncryptionBadge.tsx
│   ├── KeyFingerprint.tsx
│   ├── SelfDestructTimer.tsx
│   └── VerificationModal.tsx
├── crypto/                     # Calls into Tauri Rust commands
│   ├── keyManager.ts
│   ├── messageEncrypt.ts
│   ├── messageDecrypt.ts
│   ├── x3dh.ts
│   └── doubleRatchet.ts
├── db/
│   ├── localDb.ts              # SQLCipher wrapper
│   ├── migrations/
│   └── queries/
├── network/
│   ├── websocketClient.ts
│   ├── apiClient.ts
│   └── torTransport.ts         # Optional Tor integration
├── types/
│   ├── message.ts
│   ├── contact.ts
│   ├── session.ts
│   └── keys.ts
└── utils/
    ├── fingerprint.ts          # Key fingerprint display
    ├── timestamp.ts            # Fuzzy timestamp utils
    └── memoryZero.ts           # Secure memory wiping
```

### Local SQLCipher Schema

```sql
-- Encrypted with user's PIN-derived key

CREATE TABLE contacts (
    id                  TEXT PRIMARY KEY,          -- Hex identity key
    nickname            TEXT NOT NULL,
    fingerprint         TEXT NOT NULL,
    verified            BOOLEAN DEFAULT FALSE,
    added_at            INTEGER,                   -- Unix timestamp
    last_message_at     INTEGER,
    archived            BOOLEAN DEFAULT FALSE,
    blocked             BOOLEAN DEFAULT FALSE
);

CREATE TABLE sessions (
    contact_id          TEXT PRIMARY KEY REFERENCES contacts(id),
    root_key_enc        BLOB NOT NULL,             -- Encrypted ratchet state
    send_chain_key_enc  BLOB NOT NULL,
    recv_chain_key_enc  BLOB NOT NULL,
    send_message_number INTEGER DEFAULT 0,
    recv_message_number INTEGER DEFAULT 0,
    ratchet_key_pub     BLOB NOT NULL,
    updated_at          INTEGER
);

CREATE TABLE messages (
    id                  TEXT PRIMARY KEY,          -- UUID
    contact_id          TEXT REFERENCES contacts(id),
    direction           TEXT CHECK(direction IN ('sent', 'received')),
    body_enc            BLOB NOT NULL,             -- Encrypted even locally
    media_type          TEXT DEFAULT 'text',
    sent_at             INTEGER,
    delivered_at        INTEGER,
    read_at             INTEGER,
    self_destruct_at    INTEGER,                   -- NULL = no self-destruct
    deleted             BOOLEAN DEFAULT FALSE
);
CREATE INDEX idx_messages_contact ON messages(contact_id, sent_at);

CREATE TABLE prekeys (
    prekey_id           INTEGER PRIMARY KEY,
    public_key          BLOB NOT NULL,
    private_key_enc     BLOB NOT NULL,             -- Encrypted with master key
    consumed            BOOLEAN DEFAULT FALSE
);

CREATE TABLE settings (
    key                 TEXT PRIMARY KEY,
    value               TEXT NOT NULL
);
```

---

## 9. Networking & Transport Layer

### Connection Flow

```
1. Client resolves relay server (DNS over HTTPS to avoid DNS leakage)
2. TCP connect to nginx (port 443)
3. TLS 1.3 handshake (minimum version enforced, TLS 1.2 rejected)
   - Cert pinning: client pins server's public key hash on first connection
   - Subsequent connections reject cert changes (TOFU model)
4. HTTP Upgrade → WebSocket
5. WebSocket auth challenge-response (proves key ownership)
6. Encrypted message stream begins

Optional Tor path:
1. Connect to local Tor SOCKS5 proxy (127.0.0.1:9050)
2. Route all traffic through Tor hidden service (.onion address)
3. Server's .onion address distributed separately from clearnet address
```

### Traffic Obfuscation

```
Problem: Even encrypted traffic reveals that you're using a secure
         messenger (traffic shape, timing, connection patterns)

Mitigations:
1. Random padding: All messages padded to one of 5 fixed sizes
   (256, 512, 1024, 2048, 4096 bytes) to prevent size analysis

2. Decoy traffic: Client sends encrypted noise packets when idle
   (configurable, off by default to save bandwidth)

3. Coalesced sends: Messages batched with random 0-500ms delay
   to prevent exact timing correlation

4. Multiplexed sessions: Multiple virtual conversations over
   single WebSocket connection (indistinguishable externally)
```

### Offline Message Delivery

```
Sender is online, Recipient is offline:
1. Sender encrypts message normally
2. Sends encrypted envelope to server via REST POST /messages/send
3. Server stores encrypted blob in message_queue table
4. When recipient comes online:
   a. Authenticates to WebSocket
   b. Server sends queued envelopes via WebSocket
   c. Recipient client decrypts
   d. Client sends DELETE /messages/inbox/{token} for each
5. Queued messages expire after 30 days (configurable)
```

---

## 10. Identity & Key Management

### User Identity

```
There are NO usernames, email addresses, or phone numbers.
A user is identified ONLY by their Ed25519 public key.

User ID = SHA-256(Ed25519_public_key)[0..16] displayed as hex
Example:  7F3A·C291·08BE·4D12

Contact Discovery:
  Out-of-band only (QR code, manual key exchange, link share)
  No central directory (no way to search for users)
  No address book access
```

### Key Exchange Flow (New Conversation)

```
ALICE wants to message BOB for first time:

1. Alice fetches Bob's prekey bundle from server:
   { identity_key_B, signed_prekey_B, one_time_prekey_B }

2. Alice performs X3DH:
   DH1 = ECDH(Alice_identity, Bob_signed_prekey)
   DH2 = ECDH(Alice_ephemeral, Bob_identity)
   DH3 = ECDH(Alice_ephemeral, Bob_signed_prekey)
   DH4 = ECDH(Alice_ephemeral, Bob_one_time_prekey)
   master_secret = HKDF(DH1 || DH2 || DH3 || DH4)

3. Alice initializes Double Ratchet with master_secret

4. First message includes Alice's ephemeral key (so Bob can
   reconstruct the same master_secret)

5. Bob, on receiving first message:
   - Looks up the one-time prekey used (identified by prekey_id)
   - Reconstructs master_secret via same X3DH
   - Initializes Double Ratchet
   - All subsequent messages use the ratchet state
```

### Safety Numbers / Verification

```
To prevent MITM attacks, users verify each other's identity out-of-band:

Safety Number = display_format(
    SHA-512(Alice_identity || Bob_identity)[0..30]
)

Displayed as 12 groups of 5 digits:
Example: 05413 33475 29277 71229 00962 13481
         41039 01413 78534 55288 21219 33741

Verification methods:
1. In-person: Both users read the number aloud and compare
2. QR code: Scan each other's QR (encodes identity key)
3. Secure channel: Share via another verified secure channel
```

### Key Backup & Recovery

```
Seed phrase (BIP-39 compatible, 24 words) derived from master key:
- Generated on first launch
- User must write down and store securely
- Allows re-derivation of identity key on new device
- WITHOUT seed phrase: identity is lost (no recovery service)

Key rotation:
- Signed prekeys: Auto-rotated every 7 days
- One-time prekeys: Replenished when count drops below 20
- Identity key: Never rotated (would break all existing verifications)
  - Compromise scenario: notify contacts manually + create new identity
```

---

## 11. Mobile Porting Strategy (Phase 2)

### Platform Strategy

```
Shared Code (Rust):          ~60% of codebase reused
  - All cryptographic logic
  - Protocol implementation (X3DH, Double Ratchet)
  - Message serialization
  - Database layer (SQLCipher)
  - Network client

Platform-Specific:           ~40% rewritten
  - UI (React Native for shared, or native per platform)
  - Key storage (Android Keystore / iOS Secure Enclave)
  - Push notifications
  - Background processing
  - OS-level sandboxing
```

### Android Port

```
Framework:    React Native (reuses most UI logic from desktop)
  OR:         Kotlin + Jetpack Compose (for deeper OS integration)

Crypto Layer: Rust compiled to ARM64/x86_64 via cargo-ndk
              Called via JNI (Java Native Interface)

Key Storage:  Android Keystore System
              - Keys never leave secure hardware (if TEE available)
              - Biometric authentication integration
              - Strongbox for Pixel/certified devices

Push:         Firebase Cloud Messaging (FCM)
              - Push payload contains ONLY a wakeup signal
              - No message content in push payload
              - App fetches encrypted messages on wakeup
              - FCM can be replaced with self-hosted ntfy.sh

Local DB:     SQLCipher for Android (same schema)

Background:   WorkManager for periodic key replenishment
              Foreground Service for persistent WebSocket

Build:        Gradle + Android Studio
              Signed with hardware-backed key if available
```

### iOS Port

```
Framework:    React Native (share with Android UI)
  OR:         Swift + SwiftUI (for deeper OS integration)

Crypto Layer: Rust compiled to ARM64 via cargo-lipo
              Called via C FFI + Swift bridging header

Key Storage:  iOS Secure Enclave
              - P-256 keys hardware-bound to device
              - Face ID / Touch ID gate on key access
              - Note: Secure Enclave uses P-256, so identity key
                derivation layer needed to bridge to Ed25519

Push:         Apple Push Notification Service (APNs)
              - Same approach: wakeup only, no payload content
              - Background refresh mode for key replenishment

Local DB:     SQLCipher for iOS (same schema)

Build:        Xcode + Swift Package Manager
              Notarization + App Store or TestFlight distribution

Special:      App Clip for quick key exchange without full install
              Widgets for unread count (no message preview)
```

### Desktop → Mobile Migration Path

```
Phase 2 Steps:
1. Extract Rust crypto core into shared crate (no UI deps)
2. Create C FFI interface for mobile consumption
3. Android: Build AAR with JNI bindings
4. iOS: Build xcframework with Swift bridging
5. React Native: Reuse existing React components (with mobile adaptations)
6. Test on Android 10+ / iOS 15+
7. Self-sign APK for sideloading (Android)
8. TestFlight beta → App Store review (iOS)

Feature parity target: 90% of desktop features in mobile v1.0
Mobile-exclusive features:
  - Biometric unlock
  - Ephemeral "vanish mode" (screen recording detection)
  - Nearby key exchange (Bluetooth/NFC)
```

---

## 12. Directory Structure

### Full Repository Layout

```
vaultex/
├── README.md
├── DESIGN.md                        # This file
├── Cargo.toml                       # Rust workspace
├── package.json                     # Node workspace root
│
├── crates/
│   ├── vaultex-crypto/              # Core crypto library
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── identity.rs          # Ed25519 key management
│   │   │   ├── x3dh.rs             # X3DH implementation
│   │   │   ├── double_ratchet.rs    # Double Ratchet impl
│   │   │   ├── sealed_sender.rs     # Sealed sender
│   │   │   ├── aes_gcm.rs          # AES-256-GCM wrapper
│   │   │   └── prekeys.rs          # Prekey management
│   │   └── Cargo.toml
│   │
│   ├── vaultex-server/              # Backend server
│   │   ├── src/
│   │   │   ├── main.rs
│   │   │   ├── api/
│   │   │   ├── websocket/
│   │   │   ├── db/
│   │   │   ├── middleware/
│   │   │   └── models/
│   │   ├── migrations/              # SQL migrations (sqlx)
│   │   └── Cargo.toml
│   │
│   └── vaultex-ffi/                 # C FFI for mobile
│       ├── src/
│       │   ├── lib.rs
│       │   └── bindings.rs
│       └── Cargo.toml
│
├── apps/
│   ├── desktop/                     # Tauri desktop app
│   │   ├── src-tauri/
│   │   │   ├── src/
│   │   │   │   ├── main.rs
│   │   │   │   ├── commands/        # Tauri IPC commands
│   │   │   │   └── db/
│   │   │   ├── Cargo.toml
│   │   │   └── tauri.conf.json
│   │   ├── src/                     # React frontend
│   │   │   ├── (see Frontend structure above)
│   │   ├── package.json
│   │   └── vite.config.ts
│   │
│   ├── android/                     # Android app (Phase 2)
│   │   ├── app/
│   │   ├── rust-bridge/
│   │   └── build.gradle
│   │
│   └── ios/                         # iOS app (Phase 2)
│       ├── VaultexApp/
│       ├── rust-bridge/
│       └── Podfile
│
├── infrastructure/
│   ├── docker-compose.yml           # Local dev stack
│   ├── docker-compose.prod.yml      # Production stack
│   ├── nginx/
│   │   └── vaultex.conf
│   ├── postgres/
│   │   └── init.sql
│   └── scripts/
│       ├── setup-dev.sh
│       ├── gen-certs.sh             # Self-signed certs for dev
│       └── db-migrate.sh
│
└── docs/
    ├── PROTOCOL.md                  # Crypto protocol spec
    ├── API.md                       # API reference
    ├── SECURITY.md                  # Security considerations
    └── BUILD.md                     # Build instructions
```

---

## 13. Tech Stack Summary

### Phase 1 — Desktop

| Layer | Technology | Version | Reason |
|---|---|---|---|
| Desktop Shell | Tauri | 2.x | Tiny binary, Rust native, secure |
| UI Framework | React + TypeScript | 18.x | Reusable for mobile, large ecosystem |
| Styling | Tailwind CSS | 3.x | Utility-first, no runtime |
| State Management | Zustand | 4.x | Lightweight, TypeScript-first |
| Build Tool | Vite | 5.x | Fast HMR, Tauri-optimized |
| Crypto Core | Rust + libsodium | latest | Audited, production-grade |
| Local Database | SQLCipher | 4.x | AES-256 encrypted SQLite |
| Server Language | Rust + Axum | 0.7 | Memory-safe, high performance |
| Async Runtime | Tokio | 1.x | De facto Rust async standard |
| Primary DB | PostgreSQL | 16 | ACID, solid JSON support |
| Cache / Queue | Redis | 7.x | Fast pub/sub, message buffering |
| Proxy | Nginx | 1.25 | Battle-tested TLS termination |
| Containerization | Docker Compose | 2.x | Dev and prod parity |
| Migration Tool | sqlx-cli | 0.7 | Compile-time checked SQL |

### Phase 2 — Mobile (Additional)

| Layer | Technology | Reason |
|---|---|---|
| Mobile UI | React Native | Shares desktop React components |
| Android Crypto | Rust → JNI → Kotlin | Full crypto reuse |
| iOS Crypto | Rust → C FFI → Swift | Full crypto reuse |
| Android KeyStore | Android Keystore API | Hardware key protection |
| iOS Key Store | Secure Enclave | Hardware key protection |
| Push (Android) | FCM (content-free) | Wakeup only, no payload |
| Push (iOS) | APNs (content-free) | Wakeup only, no payload |

---

## 14. Development Roadmap

### Phase 1a — Foundation (Weeks 1–4)

```
[ ] Server setup
    [ ] PostgreSQL + Redis + Nginx Docker Compose stack
    [ ] Rust/Axum server skeleton with health endpoint
    [ ] Database migrations (accounts, prekeys, message_queue)
    [ ] Basic REST API: register, prekey upload/fetch
    [ ] WebSocket server: connect, auth, relay

[ ] Crypto core (Rust crate)
    [ ] Ed25519 key generation and signing
    [ ] X25519 Diffie-Hellman
    [ ] X3DH implementation (unit tested against test vectors)
    [ ] Double Ratchet implementation (unit tested)
    [ ] AES-256-GCM encrypt/decrypt
    [ ] Sealed sender construction/parsing

[ ] Desktop app skeleton
    [ ] Tauri project with React + TypeScript
    [ ] SQLCipher local database setup
    [ ] Tauri IPC commands to crypto crate
    [ ] Basic screen routing
```

### Phase 1b — Core Features (Weeks 5–8)

```
[ ] Onboarding flow
    [ ] Key generation screen
    [ ] Seed phrase display + confirmation
    [ ] PIN setup + SQLCipher key derivation
    [ ] Server registration

[ ] Core messaging
    [ ] Contact add (manual key input + QR scan)
    [ ] Session establishment (X3DH + Double Ratchet init)
    [ ] Send encrypted message
    [ ] Receive encrypted message (WebSocket)
    [ ] Offline message delivery

[ ] UI polish
    [ ] Full chat UI (matches VAULTEX design mockup)
    [ ] Contact list with status
    [ ] Message status (sent/delivered/read)
    [ ] Key fingerprint + safety number display
```

### Phase 1c — Security Features (Weeks 9–12)

```
[ ] Self-destructing messages (client-side timer)
[ ] Sealed sender implementation
[ ] Duress PIN (opens decoy app/wipes real data)
[ ] Traffic padding (fixed-size message padding)
[ ] Optional Tor transport integration
[ ] App lock (timeout + PIN re-entry)
[ ] Key rotation (prekeys, signed prekeys)
[ ] Safety number verification flow
[ ] Reproducible build setup
[ ] Security audit prep (code review, fuzzing)
```

### Phase 1d — Polish & Release (Weeks 13–16)

```
[ ] Media support (images, files — encrypted)
[ ] Group messaging (sender key protocol)
[ ] Search (local SQLCipher FTS5)
[ ] Notification system (OS integration)
[ ] Settings screens
[ ] Export/import (key backup/restore)
[ ] Installer packages (Linux AppImage/deb, Windows MSI)
[ ] Documentation
[ ] Internal security audit
```

### Phase 2 — Mobile (Weeks 17–28)

```
[ ] Rust FFI interface finalization
[ ] Android: JNI bindings + Kotlin app
[ ] iOS: Swift bridging + SwiftUI app
[ ] React Native shared UI layer
[ ] Biometric authentication
[ ] Push notification integration
[ ] Beta testing (TestFlight + sideload APK)
[ ] App Store submission prep
```

---

## 15. Deployment Architecture

### Development Environment

```bash
# Quick start:
git clone https://github.com/your-org/vaultex
cd vaultex/infrastructure
docker-compose up -d         # Starts postgres, redis, nginx
cd ../crates/vaultex-server
cargo run                    # Starts dev server on :8080
cd ../../apps/desktop
npm install && npm run tauri dev   # Starts desktop app
```

### Production Server (Single Node, Phase 1)

```
Minimum spec:
  CPU: 2 cores
  RAM: 4GB
  Storage: 40GB SSD
  OS: Ubuntu 22.04 LTS
  Network: 100Mbps, 1TB/mo transfer

Stack:
  Nginx (443/80) → Axum server (:8080) → PostgreSQL (:5432) + Redis (:6379)

TLS:
  Let's Encrypt (certbot) for clearnet domain
  Self-hosted CA option for high-security deployments

Tor Hidden Service:
  tor daemon with HiddenServicePort 443 → localhost:443
  .onion address distributed to users directly

Hardening:
  UFW firewall: only 22, 80, 443 inbound
  fail2ban on SSH and nginx
  Automatic security updates (unattended-upgrades)
  PostgreSQL not exposed to network (localhost only)
  Redis bound to 127.0.0.1 only
  AppArmor profiles for server process
```

### Server docker-compose.yml

```yaml
version: '3.9'

services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: vaultex
      POSTGRES_USER: vaultex
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./postgres/init.sql:/docker-entrypoint-initdb.d/init.sql
    restart: unless-stopped
    networks: [internal]

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD} --save 60 1
    volumes:
      - redisdata:/data
    restart: unless-stopped
    networks: [internal]

  server:
    build: ../crates/vaultex-server
    environment:
      DATABASE_URL: postgresql://vaultex:${POSTGRES_PASSWORD}@postgres:5432/vaultex
      REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379
      SERVER_PORT: 8080
      LOG_LEVEL: info
    depends_on: [postgres, redis]
    restart: unless-stopped
    networks: [internal, external]

  nginx:
    image: nginx:1.25-alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/vaultex.conf:/etc/nginx/conf.d/default.conf
      - /etc/letsencrypt:/etc/letsencrypt:ro
    depends_on: [server]
    restart: unless-stopped
    networks: [external]

volumes:
  pgdata:
  redisdata:

networks:
  internal:
    internal: true
  external:
```

---

## 16. Security Audit Checklist

### Cryptography

- [ ] X3DH implementation matches Signal's published spec
- [ ] Double Ratchet passes all test vectors from Signal spec
- [ ] No homebrew crypto — all primitives from libsodium
- [ ] AES-GCM nonces are random (never reused)
- [ ] HKDF info strings are unique per use
- [ ] Memory containing key material is zeroed after use
- [ ] No private keys ever leave device in plaintext
- [ ] Sealed sender correctly hides sender identity from server

### Server

- [ ] Server cannot decrypt any stored message
- [ ] SQL injection: all queries use parameterized statements
- [ ] Rate limiting prevents enumeration / DoS
- [ ] No IP addresses stored in database
- [ ] All endpoints reject requests over TLS < 1.3
- [ ] Certificate pinning enforced client-side
- [ ] Redis not accessible from external network
- [ ] PostgreSQL not accessible from external network
- [ ] No user metadata logged (no access logs with identity)

### Client

- [ ] SQLCipher key derived from PIN with Argon2id (not SHA)
- [ ] Duress PIN wipes database before showing decoy
- [ ] App does not cache plaintext messages in OS swap
- [ ] Screen recording / screenshot prevention (mobile)
- [ ] Clipboard cleared after copying sensitive data
- [ ] No crash reports containing message content
- [ ] Reproducible builds (deterministic compiler output)
- [ ] Code signing with hardware-backed key

### Operational

- [ ] Warrant canary published and updated regularly
- [ ] Server accepts Tor connections (.onion address)
- [ ] No third-party SDKs (analytics, crash reporting) in production build
- [ ] Open source (enables community audit)
- [ ] Binary transparency log (users can verify distributed binary matches source)

---

*Document generated for Claude Code. Begin with Phase 1a foundation tasks. Run `cargo test` in vaultex-crypto crate first to validate X3DH and Double Ratchet implementations before building any UI.*

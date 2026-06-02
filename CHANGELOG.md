# Changelog

All notable changes to the VAULTEX project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.6] - 2026-06-02

### Fixed
- **Android: messages from server contacts were never delivered, even after registration was fixed.** The v0.10.5 release fixed Android's server-registration flow but the WebSocket connection that delivers messages was never opened — `NavGraph` materialized a `NetworkManager` ViewModel but never called `setCredentials` or `connect`, and `MessagingManager.networkManager` stayed `null`. The desktop-side "Contact added in local-only mode" symptom looked unfixed because the Android client never came online on the server. `NavGraph` now wires both managers and triggers `networkManager.connect(Config.DEFAULT_SERVER_URL)` on `isAuthenticated`. Verified end-to-end: desktop registered (account `39c9922e-…`), Android registered (account `6024dd19-…`), desktop adds Android via `/accounts/by-key` without falling back to local-only, desktop sends a Double Ratchet + sealed-sender message, server queues + delivers, Android logcat shows `MessagingManager onMessage senderId=39c9922e-… payloadLen=1098`.
- **Android: contact-add resolved a local UUID instead of the server's account_id** (also in v0.10.5 but worth restating). The fix in commit `68fee24` is now actually exercised on the wire by the WS fix above.

### Added
- **Website: GitHub Releases-backed download buttons with self-hosted fallback.** `useLatestRelease` fetches `/repos/VaultexCoder/vaultex/releases/latest` at runtime and the platform cards swap their URLs in once the API answers (8s budget; static `/downloads` URLs are used otherwise). Result: shipping a new binary version no longer requires rebuilding and redeploying the Astro site — just upload assets to a GitHub release and the marketing site picks them up automatically.

### Internal
- Diagnostic `Log.i` instrumentation added to `NavGraph`, `NetworkManager`, `WebSocketClient`, and `MessagingManager` covering connect lifecycle + server message arrival. Future WS regressions surface from logcat alone, no emulator/Maestro needed.

Android only — desktop builds (Linux .deb, Windows .exe) remain at 0.10.3.

## [0.10.5] - 2026-06-02

### Fixed
- **Android: default server URL was still `http://localhost:8080`.** The v0.10.3 release notes claimed the localhost default was switched to the production demo server, but that fix only touched `apps/desktop/src-tauri/src/state.rs` and `apps/desktop/src/stores/networkStore.ts`. Three independent hardcoded defaults in `NetworkState`, `ApiClient`, and `SettingsState` on Android were missed. A fresh APK install therefore tried to reach `localhost:8080` on registration and silently failed with no UI hint. Centralized as `Config.DEFAULT_SERVER_URL = "https://api.vaultexchat.org"` so all three sites stay in sync going forward.

### Added
- **Android Settings → Test Connection button.** Pings `/api/v1/health` on the current server URL and shows a 4-second success / failure card. Removes the "is the server reachable?" guesswork that previously could only be answered by attempting registration.

Android only — desktop builds (Linux .deb, Windows .exe) remain at 0.10.3.

## [0.10.4] - 2026-06-01

### Fixed
- **Android: tapping "Generate Identity Key" crashed the app immediately.** `VaultexLib.INSTANCE`'s lazy `Native.load("vaultex_ffi", ...)` throws `UnsatisfiedLinkError` (a `java.lang.Error` subclass — not an `Exception`) when `libvaultex_ffi.so` is missing from the APK, and `AuthViewModel.register()`'s `catch (Exception)` blocks did not intercept Errors, so the LinkageError escaped the coroutine and tore down the process. Broadened the three relevant catches to `Throwable`, and now cross-compile + bundle `libvaultex_ffi.so` for `arm64-v8a` and `x86_64` so the FFI path actually works rather than just degrading gracefully.

Android only — desktop builds (Linux .deb, Windows .exe) remain at 0.10.3.

## [0.10.3] - 2026-06-01

### Fixed
- **Default server URL switched from localhost to the production demo server.** A fresh install on a new machine — without any environment variables set, without running `launch-alice.ps1` / `launch-bob.ps1` to override — no longer defaults to `http://localhost:8080` and gets stuck on the login screen with no way to reach Settings. Default is now `https://api.vaultexchat.org`. `VAULTEX_SERVER_URL` still overrides as before.

  Applies to both the Rust backend (`AppState::new` in `apps/desktop/src-tauri/src/state.rs`) and the React frontend (`networkStore` initial state in `apps/desktop/src/stores/networkStore.ts`). The two stayed in sync per the v0.10.2 `get_default_server_url` wiring.

  Long-term UX fix (allow editing the server URL from the login screen, before registration) is tracked in the project issue tracker — this release is the immediate unblock.

## [0.10.2] - 2026-05-31

### Fixed
- **Frontend silently overrode env-derived server URL on first connect**: `networkStore` hardcoded `serverUrl: 'http://localhost:8080'` as its initial value, and `App.tsx` auto-connect passed that hardcoded value into `connect_to_server`, which OVERWRITES `AppState::server_url` (the value derived from `VAULTEX_SERVER_URL` at startup). The backend then made all session-establish HTTP calls against `localhost:8080`, so adding a contact returned `sessionStatus = "server_unreachable"` and no encrypted messages flowed. Same regression class as the three v0.10.1 fixes (silent local-mode fallback via a different code path).

  Fix: new `get_default_server_url` Tauri command that returns whatever the backend was configured with; `networkStore.initServerUrl()` reads it and adopts that value; `App.tsx` awaits `initServerUrl` before issuing `connect`. Surfaced by the new distributed E2E spec (`wdio.distributed.conf.ts`).

### Added
- **`get_default_server_url` Tauri command** so the frontend can stay in sync with the backend's resolved server URL without re-reading env vars (which a WebView can't see).

## [0.10.1] - 2026-05-30

### Fixed
- **Multi-client vault collision on a single OS user**: `default_data_dir()` now honors `VAULTEX_DATA_DIR` before the platform default, so two desktop instances launched on the same Windows (or any) OS user can hold distinct vaults instead of fighting over `%APPDATA%\vaultex`. The E2E orchestrator sets `VAULTEX_DATA_DIR` per client (kept `XDG_DATA_HOME` alongside for backward compat).
- **Silent registration fallback**: `register` previously fabricated a local UUID when the server rejected the request or was unreachable, leaving the UI showing "registered" against an account the server didn't know. Every later request (WS auth, by-key lookup, discoverability) then quietly 401'd. The command now returns an actionable error and persists nothing, so the user can fix the server URL and retry on a clean vault.
- **Default server URL ignored env**: `AppState::new` now reads `VAULTEX_SERVER_URL` first (falling back to `http://localhost:8080`), so a launcher / CI can point a client at the right server before any UI interaction.
- **Server Dockerfile build break** (#143): bumped builder image from `rust:1.77-bookworm` to `rust:1-bookworm`. The pinned 1.77 Cargo could not parse the workspace `Cargo.lock` (lock format v4, introduced in Cargo 1.78), so `docker compose build server` failed immediately.
- **Desktop Tauri version mismatch** (#144): bumped `@tauri-apps/api` from `^2.0.0` to `^2.11.0` so it tracks the Rust `tauri` crate (resolved to 2.11.x). The Tauri CLI rejects mismatched major/minor versions between the npm package and Rust crate, which broke `cargo tauri build` immediately with a version-mismatch error.

### Added
- **`scripts/launch-alice.ps1` / `launch-bob.ps1`**: Windows launcher scripts that pre-set `VAULTEX_DATA_DIR` and `VAULTEX_SERVER_URL` so two desktop clients can run side-by-side against a remote server without UI configuration. Accept `-Fresh` (wipe vault), `-Server <url>`, and `-Exe <path>` flags.

## [0.10.0] - 2026-05-29

### Added

#### Tester UX & Honest Connectivity (#136–#141)
- **Persistent dev-server scripts** (#136): `scripts/dev-server-up.{sh,ps1}` bring up the persistent Postgres + Redis stack and run the server natively; `dev-server-down.{sh,ps1}` tears it down (`--wipe` clears volumes). Persistent mode is now the documented default; demo mode prints a loud startup warning and is scoped to unit tests.
- **Reset Local Data** (#137): Settings → Danger Zone control that securely wipes the local SQLCipher database and zeroizes in-memory key material, then restarts on a fresh-account screen. Gated behind a typed `RESET` confirmation plus a backend confirm token.
- **Session-establish status surfacing** (#138): adding a contact now reports a typed `sessionStatus` and shows an actionable banner (account-not-found / server-unreachable / prekey-bundle-unavailable) instead of silently falling back to local-only mode. Re-adding a known contact is idempotent (dedupe on identity key); adding your own key is rejected.
- **`GET /api/v1/ping`** (#139): unauthenticated capability probe returning `{ service, version, min_client_version, capabilities }` so clients can confirm a URL is a real VAULTEX server before the WebSocket handshake.
- **Test Connection** (#140): a Settings → Server Connection diagnostic that probes ping + account registration and reports an honest verdict (unreachable / not-a-VAULTEX-server / reachable / account-registered / account-not-registered) with actionable copy, replacing the optimistic "connected".
- **Opt-in user discovery** (#141): default-off Settings → Privacy toggle to be findable by display name on a server, and a Browse Server dialog to find and add discoverable peers after confirming their safety-number fingerprint. Server adds authenticated set/read-back/list endpoints (rate-limited, suspended-filtered, self-excluded, LIKE-escaped) across both storage backends. End-to-end encryption is unchanged; opting out purges the stored metadata.

### Changed
- The server now applies SQLx migrations on startup (Postgres backend); discovery columns ship in both the migration and `infrastructure/postgres/init.sql`.
- `http_client::auth_get` signs over the request path without the query string, matching the server's auth middleware (enables authenticated GETs with query parameters).

### Fixed
- **Secure local-data wipe** (#137): `wipe_all_data` now scrubs the database file (`secure_delete`, `VACUUM`, WAL truncate) rather than only deleting rows — wiped identity keys and messages are no longer recoverable from the freelist/WAL given the non-secret bootstrap DB key. Also hardens the duress-PIN wipe and zeroes the retained rotation-grace prekey.

## [0.9.0] - 2026-05-24

### Added

#### Android P2P Transport (#94–#98)
- Full P2P transport manager with Bluetooth LE, WiFi Direct, and LAN/Bonjour backends, offline message queue, and a manual peer-connect path. Brings Android to parity with the desktop transport stack.
- Maestro UI automation framework (#93) for cross-device acceptance testing.
- QR code contact exchange (#91): generate and scan invite codes; QR scanner accepts `vaultex://` invite links and pre-fills the add-contact dialog.

#### Desktop UI
- QR code display and invite-link generation on the desktop client (matches Android UX).

#### Server / Infrastructure
- **Server containerization** (`infrastructure/docker-compose.prod.yml`): production-grade compose stack with Caddy TLS termination, Watchtower image auto-rollout, Postgres + Redis volumes.
- **Cloud deploy scaffolding** (`.gitlab-ci.yml`): `build-server-docker` pushes to GitLab Container Registry; manual `deploy-server` job SSH-deploys to a Hetzner-class host.
- **Linux bundle build script** (`scripts/build-linux-bundles.sh`, #131): one-command `.deb` + `.AppImage` production from `apps/desktop/src-tauri`, with prereq checks and artifact verification.

#### Documentation
- `docs/distribution/linux-tester-setup.md`: install/run instructions for non-dev Linux testers (`.deb` and `.AppImage` paths, data locations, troubleshooting).
- `docs/windows-build.md`: native Windows x64 build recipe (MSVC, libsodium, SQLCipher) producing the NSIS installer.
- `infrastructure/DEPLOYMENT.md`: prod deploy how-to (host setup, secrets, Watchtower, manual deploy, rollback, backups).
- `docs/operations/cloud-hosting-and-deploy-plan.md`: planning doc covering host selection (Hetzner CX22 recommended), co-hosting the marketing site, release-driven deployment automation, and the GitHub-vs-GitLab path for public security review.
- `docs/testing/peer-review-report.md`, `docs/testing/peer-review-report-p2p-transport.md`, `docs/testing/mobile-acceptance-test-report.md`: multi-expert peer-review reports for the iOS, P2P transport, and Android-acceptance sweeps.

### Fixed

#### iOS Peer Review (`bugfix/ios-peer-review`, !43)
- **FFI pointer ABI (iOS + Android)**: `ffi_identity_sign` / `ffi_identity_verify` now take `*const u8` / `*mut u8` instead of `*const [u8; 32]` / `*const [u8; 64]`. cbindgen previously lowered the array-pointer form into opaque Swift tuple types, forcing callers into unsafe `assumingMemoryBound` gymnastics; the Android JNA bindings were already using `ByteArray` and were silently mismatched.
- **iOS `VaultexCrypto.sign` / `verify`**: rewritten to pass arrays directly, removing ~20 lines of tuple-binding scaffolding per call site.
- **iOS `PersistenceController`**: Core Data load failure now `fatalError`s instead of silently `print`ing.
- **iOS `TransportType` enum**: `.wifi` → `.wifiDirect` (rawValue `"WIFI_DIRECT"`) to match Rust/Android wire format.
- **iOS `project.yml`**: removed stale `LIBRARY_SEARCH_PATHS` / `OTHER_LDFLAGS -lvaultex_ffi`; replaced deprecated `UILaunchStoryboardName` with `UILaunchScreen`.

#### Android
- **Passphrase verification**: store + verify Argon2id hash on login (matches desktop semantics).
- **P2P transport stability**: LAN server race condition, WiFi Direct discovery port + receiver issues, LAN data-port exchange + permissions, QR scanner accepting invite links.
- **Version-string source**: read from BuildConfig instead of hardcoded string (#92).

#### Website
- **CSP unblocked Google Fonts + inline hydration scripts** in `apps/website/nginx.conf` — interactive widgets (demo chat, comparison chart) now hydrate when served from the container.
- Added `apps/website/docker-compose.yml` for one-command local serving.

#### CI / Lint
- Unblock CI gates that were red on develop (rust-lint + frontend-lint).
- Prettier write across UI to unblock frontend-lint.

### Changed
- Tauri desktop crate: `cargo fmt` whitespace pass across `src-tauri` (no behavior change).

## [0.8.0] - 2026-03-23

#### Fixed

- **FFI pointer ABI (iOS + Android)**: `ffi_identity_sign` / `ffi_identity_verify` now take `*const u8` / `*mut u8` instead of `*const [u8; 32]` / `*const [u8; 64]`. cbindgen lowered the array-pointer form into opaque Swift tuple types (`(UInt8, UInt8, ... ×32)`), forcing callers into unsafe `assumingMemoryBound` gymnastics that were unidiomatic and fragile. The Android JNA bindings were already using `ByteArray` (which marshals to `*const u8`), so the old signature was actively mismatched there. The new signature is the same ABI both callers naturally produce.
- **iOS `VaultexCrypto.sign` / `verify`**: rewritten to pass arrays directly (Swift auto-converts `[UInt8]` to `UnsafePointer<UInt8>`), removing ~20 lines of tuple-binding scaffolding per call site.
- **iOS `PersistenceController`**: Core Data load failure now calls `fatalError` instead of silently `print`ing. A broken persistence stack cannot be recovered from mid-run — swallowing the error left the app in an undefined state. Will become user-visible recovery when SQLCipher lands (tracked for follow-up).
- **iOS `TransportType` enum**: `.wifi` (rawValue `"WIFI"`) renamed to `.wifiDirect` (rawValue `"WIFI_DIRECT"`) to match the Rust `TransportType::WifiDirect` and Android `TransportType.WIFI_DIRECT` wire format. Previously an iOS peer serializing a `PeerInfo` would emit `"WIFI"` which no other client recognized.
- **iOS `PeerDiscoveryView`**: updated `switch` to use the renamed `.wifiDirect` case (was a compile error after the rename).
- **iOS `project.yml`**: dropped stale `LIBRARY_SEARCH_PATHS` / `OTHER_LDFLAGS -lvaultex_ffi` (the FFI is now shipped as `VaultexFFI.xcframework` and linked via `dependencies:`, so the flat-file search path was dead config). Replaced deprecated `UILaunchStoryboardName: LaunchScreen` with modern `UILaunchScreen: {}` (required for iOS 14+ apps built with Xcode 12+).

#### Regenerated

- `apps/ios/VaultexApp/Crypto/include/vaultex_ffi.h` re-ran through cbindgen (`apps/ios/scripts/build-ffi.sh`) after the Rust signature change; now byte-identical to `cbindgen --config cbindgen.toml --crate vaultex-ffi`.

## [0.8.0] - 2026-03-23

### Security

#### Auth Bug Fix (#90)
- **Passphrase verification**: Login now verifies passphrase against Argon2id hash stored during registration. Previously any passphrase >= 8 chars could access the app.
- **Media encryption**: Replaced XOR placeholder cipher with AES-256-GCM in Android MediaManager

#### Security Hardening (#39)
- **Screenshot prevention**: FLAG_SECURE on Android prevents screenshots and screen recording
- **Clipboard auto-clear**: Copied sensitive data auto-clears after 30 seconds
- **Root detection**: Warns user of rooted device, debugger, or emulator (non-blocking)
- **Secure storage**: Android Keystore wrapper for encrypted preferences

### Added

#### Phase 7: Android Mobile App (#75-#89)
- **Android scaffold (#75)**: Gradle project with Jetpack Compose, Material3 dark theme
- **FFI bindings (#76)**: JNA wrappers for all 20 Rust FFI functions — identity, X3DH, Double Ratchet, sealed sender, file encryption, safety numbers
- **SQLCipher database (#77)**: Room + SQLCipher encrypted storage with 14 entities
- **Auth screens (#78)**: Login, register, PIN setup, seed phrase display
- **Contact management (#79)**: Add, search, verify, archive, block contacts
- **Messaging (#80)**: Send/receive with status tracking, read receipts, typing indicators, reactions, editing, search
- **Chat UI (#81)**: Message bubbles with status icons, TTL indicators, typing dots, input bar
- **Network layer (#82)**: WebSocket + HTTP fallback, Ed25519 auth, exponential backoff reconnect
- **Group messaging (#83)**: Group entities, create/list groups, fan-out encryption
- **Media transfer (#84)**: Encrypted upload/download with AES-256-GCM, image thumbnails
- **Voice/video calls (#85)**: Call history, active call UI with timer/mute, signaling
- **Export/import (#86)**: Encrypted conversation backup with PBKDF2 + AES-256-GCM
- **Settings (#87)**: PIN, duress PIN, server URL, identity display, biometric toggle
- **CI/CD (#88)**: Android lint, test, debug build, release build pipeline
- **E2E tests (#89)**: Compose testing framework for auth and navigation flows
- **Biometric auth (#37)**: AndroidX Biometric fingerprint/face unlock
- **Push notifications (#38)**: Content-free, sender-only, and preview notification modes
- **Beta distribution (#40)**: Release signing config via environment variables

#### FFI Completion (#33)
- All 20 Rust FFI functions now have JNA bindings and Kotlin wrappers
- JNA Structure mappings for complex return types (FfiByteBuffer, FfiEncryptResult, etc.)
- computeSafetyNumber() fully wired (no longer placeholder)

#### Tech Debt (#63, #64)
- WebSocket rate limiting (100 msg/10s per connection)
- Message ID collision fix (crypto.randomUUID vs Date.now)
- Export chunked processing (1000 messages at a time)
- Timestamp format standardized to ISO 8601
- Call history click confirmation
- Tor TLS policy documentation

#### Acceptance Tests
- 31 automated server-level acceptance tests covering 7 phases
- 130+ Android acceptance tests (auth, contacts, messaging, network, crypto)

### Changed
- Desktop app version bumped to 0.8.0
- Android app versionCode 8, versionName 0.8.0
- All Cargo workspace crates version 0.8.0

### Test Coverage
- **694 total tests** (337 Rust + 79 frontend + 278 Android), 0 failures
- **All 90 GitLab issues closed**

#### Peer Review Fixes (`bugfix/peer-review-fixes`)
- **Targeted relay:** Read receipt and typing indicator WebSocket relay now sends only to the intended recipient, not broadcast
- **Payload size limits:** Enforced maximum payload sizes on incoming WebSocket and REST messages to prevent abuse
- **FTS5 query sanitization:** Full-text search queries are sanitized to prevent FTS5 syntax injection
- **Export key zeroing:** Chat export encryption key material is zeroized after use via `zeroize` crate
- **Duress wipe completion:** Duress PIN wipe now clears all in-memory state (stores, sessions, keys) in addition to database
- **PIN timing equalization:** PIN verification uses constant-time Argon2id comparison to prevent timing side-channels
- **Lock state enforcement:** App lock state is enforced on all Tauri commands, not just the frontend gate
- **Tor transport hardening:** SOCKS5 feature-gated, Tor client reuse to avoid circuit churn, connection timeouts, strict .onion address validation

### Added

#### Phase 1c: Tor Transport (#12)
- `TorTransport` in `vaultex-transport` — routes messages through Tor SOCKS5 proxy for IP-level anonymity
- `.onion` hidden service address support with `onion_only` mode
- `TransportType::Tor` variant with Tor priority in `TransportManager` (LocalNet > WifiDirect > Bluetooth > Tor > Server)
- HTTP polling through Tor for message retrieval
- 10 unit tests for Tor transport configuration and connectivity

#### Phase 4: Enhancements (#45-#52)
- **Message Search (#45)**: FTS5 full-text search on decrypted messages via SQLCipher, `search_messages` Tauri command, `SearchBar` and `SearchResults` React components, `searchStore` Zustand store
- **Read Receipts & Typing (#46)**: `ReadReceipt`, `TypingStart/Stop` WebSocket protocol extensions, `ReadReceipt` and `TypingIndicator` UI components, ephemeral typing relay on server
- **Reactions & Editing (#47)**: Emoji reactions on messages (`message_reactions` table), message editing with 5-minute window (`message_edits` table), `add_reaction`, `remove_reaction`, `edit_message` Tauri commands
- **Chat Export/Import (#48)**: Encrypted `.vaultex-export` archives (AES-256-GCM + Argon2id KDF), `export_conversation` and `import_conversation` Tauri commands
- **App Lock (#49)**: Configurable inactivity timeout (1min–1hr), PIN re-entry on lock, `set_lock_timeout`, `lock_app`, `unlock_app` commands
- **Archive & Block (#50)**: Archive/unarchive conversations (local-only), block contacts (silently drop messages), `blocked_contacts` table
- **Notifications (#51)**: `NotificationSettings` component with content-free/sender/preview modes, DND schedule, per-conversation mute, `notificationStore`
- **Unread Badges (#52)**: `UnreadBadge` component, unread count tracking in `messagesStore`, auto mark-as-read on conversation open

#### Phase 5: Voice Chat (#53-#57)
- **Call Signaling (#53)**: `CallOffer`, `CallAnswer`, `IceCandidate`, `CallHangup`, `CallReject`, `CallBusy` WebSocket protocol types with E2E encrypted SDP/ICE payloads. Server relays without storing.
- **WebRTC Types (#54)**: SRTP key derivation design from Double Ratchet via HKDF-SHA256
- **Call State Machine (#55)**: `callStore` with Idle→Offering→Ringing→Connecting→Connected→Ended states, ring/ICE timeouts
- **Voice Call UI (#56)**: `IncomingCallOverlay`, `ActiveCallView` with mute/hangup controls, duration timer, quality indicator
- **Call History (#57)**: `call_history` SQLCipher table, `CallHistoryList` component with direction/status/duration, missed call tracking

#### Phase 6: Video Chat (#58-#62)
- **Video Call UI (#59)**: `VideoCallView` with remote video + self-view PiP, auto-hiding controls, full-screen mode
- **Group Video (#62)**: `GroupCallGrid` with CSS grid for 2-4 participants, active speaker detection, speaker/grid view toggle
- **Screen Sharing (#60)**: `ScreenShareControls` with source picker and stop-sharing overlay
- **Quality Panel (#61)**: `CallQualityPanel` with RTT/loss/jitter/codec stats, expandable panel with signal bars

#### CI/CD
- Build stage in GitLab CI: produces `.deb` artifact for desktop app (downloadable from pipeline)
- Server Docker image build stage (main/tags only)

#### Desktop App (`apps/desktop/`)
- **PIN security**: Unlock PIN with Argon2id hashing (32 MiB, 3 iterations, 4 lanes), set during registration or in settings
- **Duress PIN**: Secondary PIN that silently wipes all data (database + in-memory state) while returning success to the attacker
- PIN gate on login screen — if PIN is set, prompts after passphrase authentication
- PIN and Duress PIN management in Settings screen with set/change/confirmation flows
- Settings screen with configurable server URL, connection status, identity info, key management, and logout
- Message delivery status indicators — server sends `Delivered` receipt with `recipient_id`, client updates message status in real-time
- `message-delivered` Tauri event for frontend delivery receipt handling

#### Tauri Backend (`apps/desktop/src-tauri/`)
- `app_settings` table for PIN/duress PIN storage (hash + salt)
- `db::pin` module — hash, verify (constant-time), store, load, wipe functions
- Tauri commands: `get_pin_status`, `set_pin`, `verify_pin`, `set_duress_pin`
- 12 Rust PIN unit tests + 5 command-level tests
- **State persistence**: Identity, contacts, sessions, messages, and prekeys now persisted to SQLCipher database across app restarts
- `login()` restores full state from database: identity keypair, contacts, Double Ratchet sessions, messages, signed/one-time prekeys
- `register()` persists identity and prekeys to database immediately after generation
- `add_contact()`, `remove_contact()`, `verify_contact()` persist to database
- `send_message()` and `receive_message()` persist messages and updated ratchet session state to database
- `mark_message_read()` persists read status to database
- WebSocket handler persists received messages and session state via DB connection

#### Crypto (`crates/vaultex-crypto/`)
- `RatchetState::to_bytes()` / `from_bytes()` for session serialization and database persistence
- `SignedPreKey::from_bytes()` and `OneTimePreKey::from_bytes()` for restoring prekeys from database
- `IdentityKeyPair::secret_key_bytes()` for secure persistence to SQLCipher
- `CryptoError::SerializationError` variant for serialization failures

#### Server (`crates/vaultex-server/`)
- `recipient_id` field added to `Delivered` WebSocket protocol message for client-side delivery tracking

### Changed

#### Desktop App (`apps/desktop/`)
- Replaced all hardcoded `http://localhost:8080` URLs with configurable `networkStore.serverUrl`
- Settings gear button in sidebar now navigates to full settings view (replaced inline dropdown)

### Previously Added

#### Crypto (`crates/vaultex-crypto/`)
- Ed25519 identity keypair generation and signing (`identity.rs`)
- X3DH key exchange — initiator and acceptor sides (`x3dh.rs`)
- Double Ratchet with AES-GCM (actually XChaCha20-Poly1305 via libsodium) (`double_ratchet.rs`, `aes_gcm.rs`)
- Sealed sender envelope — hides sender identity from server (`sealed_sender.rs`)
- Client-side auth module — Ed25519 challenge-response over method:path:timestamp:body_hash (`auth.rs`)
- MessagePayload with optional TTL for self-destructing messages (`message_payload.rs`)
- Safety number generation — SHA-256 of sorted identity keys, 12 groups of 5 digits (`safety_number.rs`)
- Key rotation helpers — `needs_rotation()`, rotation intervals, grace periods (`prekeys.rs`)
- Power-of-2 bucket padding (256–65536 bytes) with dummy traffic generation (`padding.rs`)
- Group messaging primitives — GroupId, GroupInfo, member management (`group.rs`)
- XChaCha20-Poly1305 per-file media encryption with random key (`media.rs`)
- Security utilities — `constant_time_eq`, `secure_random_bytes`, `wipe_memory` (`security.rs`)
- `#[must_use]` annotations on all Result-returning crypto functions
- `debug_assert!` for non-zero key generation in identity and prekeys
- `sodiumoxide::utils::memzero` in Drop impls to prevent compiler elision
- Skipped message key caching per Signal Double Ratchet spec with replay protection and MAX_SKIP bound
- 6 end-to-end integration tests covering full message flow, sealed sender, out-of-order delivery, multi-party isolation, forward secrecy, and auth signing
- 262+ unit tests across all Rust crates (crypto, server, transport, Tauri backend)

#### Server (`crates/vaultex-server/`)
- Axum REST API with PostgreSQL 16 and Redis 7 backends
- In-memory Storage backend for demo mode (no external deps required) — activate with `VAULTEX_DEMO=1`
- Account registration: `POST /api/v1/accounts/register`
- Account lookup by identity key: `GET /api/v1/accounts/by-key/:hex`
- Prekey bundle fetch: `GET /api/v1/accounts/:id/prekey_bundle`
- Signed prekey upload and rotation
- One-time prekey storage and consumption
- Message send: `POST /api/v1/messages/send`
- Sealed sender send: `POST /api/v1/messages/sealed` (no auth required)
- Media upload/download with 100 MiB limit
- Group CRUD API (6 endpoints)
- Ed25519 challenge-response auth middleware with timestamp freshness validation
- Rate limiting middleware
- WebSocket handler with Ed25519 auth, message routing (online=immediate, offline=queued), ack-based queue cleanup, ping/pong keepalive, and JSON wire protocol
- Crypto verification module for Ed25519 signature and signed prekey validation
- Multi-stage production Dockerfile with non-root user and healthcheck
- 55+ unit tests across API, middleware, WebSocket, and crypto modules

#### Desktop App (`apps/desktop/`)
- Tauri 2.x + React 18 + TypeScript desktop shell
- Vite build with strict TypeScript and Vitest test framework
- Tailwind dark theme with custom `vx-*` color tokens
- 10 React components: LoginScreen, RegisterScreen, Sidebar, MainPanel, ContactList, ContactItem, ChatHeader, MessageBubble, MessageInput, SafetyNumberDialog, KeyStatusIndicator
- 5 Zustand state stores: authStore, contactsStore, messagesStore, uiStore, networkStore, keyStatusStore, groupsStore
- Register command generates real Ed25519 identity + prekeys and uploads to server
- Login command restores identity from passphrase
- AppState with Mutex-wrapped identity, sessions, contacts, messages; key material zeroized on logout
- SQLCipher local database with Argon2id key derivation (accounts, contacts, messages, sessions, prekeys tables)
- HTTP client with Ed25519-signed requests for authenticated API calls
- WebSocket client with auto-reconnect (exponential backoff) and Tauri event emission
- `add_contact` fetches prekey bundle from server and initiates X3DH automatically
- `send_message` encrypts via Double Ratchet, wraps in sealed sender, sends via WebSocket or HTTP fallback
- `receive_message` decrypts incoming messages and auto-creates receiver X3DH sessions from init data
- `initiate_session` performs full X3DH key exchange from prekey bundle
- Key rotation commands: check, rotate signed prekey, replenish one-time prekeys, cleanup expired
- Safety number and contact verification commands
- Self-destruct message support: TTL selector, countdown timer, mark-as-read triggers, periodic cleanup
- Media commands for encrypted file upload and download
- Group messaging commands
- Auto-connect WebSocket and set up event listeners after authentication
- Sidebar: identity key display with copy button, server connect button, add-contact form, search
- Bundle config for deb/appimage/msi/dmg with icon generation

#### Infrastructure (`infrastructure/`)
- Docker Compose for PostgreSQL, Redis, Nginx
- Nginx reverse proxy configuration
- PostgreSQL init scripts
- Dev scripts: `dev-setup.sh`, `db-reset.sh`, `test-runner.sh`, `demo.sh`

#### Documentation
- `VAULTEX_DESIGN.md` — Full design document (architecture, crypto protocol, API, schemas, roadmap)
- `README.md` — Project overview with architecture, security model, and quick start
- `CONTRIBUTING.md` — Developer onboarding and contribution guide
- `docs/team/roles.md` — Team role definitions
- `docs/team/processes.md` — Sprint ceremonies, Git workflow, code review, release process, DoD
- `docs/team/automated-review.md` — CI/CD and GitLab automation setup
- `docs/adr/ADR-0001` — Initial technology choices
- `docs/adr/ADR-0002` — P2P off-grid messaging transport abstraction (Phase 3)
- `docs/security/` — Threat model, crypto inventory, audit checklist, dependency audit
- `docs/preview/app-mockup.html` — Customer-facing UI mockup
- GitLab issue templates (bug report, feature request, security vulnerability)
- MR template with security checklist
- CODEOWNERS for security-critical paths

#### CI/CD
- GitLab CI pipeline with lint, test, audit, coverage stages
- System deps (libsodium, libssl, libpq) in CI images
- Strict clippy for lib, standard for tests
- ESLint and Prettier configs for frontend

### Fixed
- Double Ratchet skipped message keys now cached per Signal spec instead of discarded
- `ON CONFLICT` clause in `store_signed_prekey` corrected to match composite PK `(account_id, prekey_id)`
- `queued_messages` renamed to `message_queue` in `delete_account`
- `Signature::as_ref()` used for sodiumoxide compatibility
- Tauri config: removed duplicate `identifier` in bundle, removed invalid `title` prop, fixed icon refs
- Bidirectional X3DH sessions: receiver auto-creates session from X3DH init data in first message
- Associated data mismatch in `receive_message` — now uses own account_id to match sender's encryption
- "Rotate Now" button forces rotation instead of skipping when keys are fresh
- Contact selection uses proper Zustand primitive selectors (prevents re-render loops)
- Server URL default corrected to 8080 (matching server default)
- WebSocket event listeners wired up in App.tsx so incoming messages are received and decrypted
- Auto-connect WebSocket after authentication
- Tauri compile errors: private field access on IdentityKeyPair, missing `use tauri::Manager`, borrow lifetime issues, non-exhaustive match on SealedMessage variant
- All clippy warnings resolved (abs_diff, unused mut, fmt, assertions_on_constants)
- **Conflicting X3DH sessions**: Both parties independently initiating X3DH in `add_contact` created incompatible sender sessions. Fixed with lazy session creation — X3DH shared secret is computed in `add_contact` but the ratchet session is only created in `send_message` when the first message is sent. The receiver creates the matching session from X3DH init data in the received message. This ensures both parties share the same session.
- **Outgoing WebSocket channel dropped**: `let (tx, _rx)` immediately dropped the receiver half, silently losing all outgoing messages. Fixed by passing `rx` into the relay loop.
- **Duplicate WebSocket connections**: Multiple `connect()` calls spawned competing tasks causing rapid connect/disconnect storms. Fixed with a guard that returns early if already connected.
- **Tauri event system bypass**: Frontend `listen("message-received")` via dynamic import never fired even though `app.emit()` returned `Ok(())`. Fixed by decrypting messages directly in the Rust WebSocket handler (`handle_server_message` calls `receive_message_inner`) and emitting a `message-decrypted` event with plaintext. Added 3-second polling fallback via `pollAllMessages` for guaranteed delivery.
- **X3DH init data ignored on existing sessions**: `receive_message_inner` skipped processing X3DH init data if any session existed, preventing the receiver from creating the correct receiver session. Now always processes incoming X3DH init data, replacing any incompatible sender session.
- **Missing tracing subscriber**: All `tracing::info!` calls silently dropped. Added `tracing_subscriber::fmt().init()` in `lib.rs` and `println!` diagnostics at critical points.
- **Pending X3DH not cleared on logout**: Shared secrets in `pending_x3dh_init` were not zeroized during logout. Now cleared alongside other key material.
- Extracted `receive_message_inner` as a public function callable from both the Tauri command and the WebSocket handler

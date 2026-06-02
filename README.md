# VAULTEX — Public Open-Core Mirror

This is the **public open-core mirror** of [VAULTEX](https://vaultexchat.org/),
a zero-knowledge, end-to-end encrypted messaging application.

> **This repo is a curated snapshot, not the full project.** Per the project's
> auditable-open-core model, only the security-relevant components are
> published here so independent researchers can verify the zero-knowledge
> claim. The desktop / mobile applications, transport layer, server
> orchestration, marketing site, and operational tooling stay closed-source.

## What's in this mirror

- **`crates/vaultex-crypto/`** — Ed25519 / X25519 / X3DH / Double Ratchet /
  AES-256-GCM / sealed-sender primitives. Built on libsodium. Independent of
  any UI or networking layer. This is the part of VAULTEX that must be
  auditable for the zero-knowledge claim to mean anything.
- **`extracted/server-middleware/auth.rs`** — The server's challenge-response
  authentication middleware. Lifted out of the private server crate because
  the auth handshake is part of the zero-knowledge trust boundary. Will not
  compile standalone; published for review.
- **`docs/protocol-spec.md`** — The VAULTEX protocol design document
  (crypto sections, API shape, threat model).
- **`CONTRIBUTING.md`**, **`CHANGELOG.md`** — Public-facing contribution
  guide and version history.

## What's NOT in this mirror

The following stay private on the upstream GitLab repo:

- Desktop application (`apps/desktop/`)
- Android / iOS applications (`apps/android/`, future `apps/ios/`)
- Marketing website (`apps/website/`)
- Rest of the server crate beyond the auth middleware
- P2P / Tor transport layer (`crates/vaultex-transport/`)
- C FFI / mobile bindings (`crates/vaultex-ffi/`)
- Business strategy, security audit notes, internal team processes
- Deployment automation, CI/CD configuration, infrastructure

## Provenance

This snapshot was generated from upstream commit `9dc309a` on branch
`develop` by `scripts/mirror-to-github.sh`. The sync is one-way
(GitLab to GitHub) and is not automated — it runs manually at the
maintainer's discretion. As a result, this mirror may lag the private
repo by hours to days.

## Building `vaultex-crypto`

```
cd crates/vaultex-crypto
cargo build
cargo test
```

System libsodium development headers are required (`libsodium-dev` on
Debian / Ubuntu; `libsodium` via Homebrew on macOS).

## License

Dual-licensed under MIT OR Apache-2.0 — pick whichever fits your
project. See `LICENSE-MIT` and `LICENSE-APACHE`.

## Reporting Security Issues

Please use GitHub's private vulnerability reporting on this repository, or
contact the team via the channels listed at <https://vaultexchat.org/>.
Do not file public issues for security vulnerabilities.

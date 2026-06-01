# VAULTEX — Public Open-Source Repository

**Zero-Knowledge End-to-End Encrypted Messaging**

Live demo: [vaultexchat.org](https://vaultexchat.org)

[![License: Apache 2.0 OR MIT](https://img.shields.io/badge/License-Apache--2.0_OR_MIT-blue.svg)](#license)
[![Rust](https://img.shields.io/badge/Rust-stable-orange.svg)](https://www.rust-lang.org/)

---

## What is this repository

This is the **public** repository for VAULTEX. It contains exactly the parts of the codebase that must be readable for third-party security reviewers to verify the system's cryptographic and protocol design. The rest of the project (applications, server business logic, transport layer, mobile clients, deployment automation) is developed in a private monorepo and is not the appropriate subject for open-source publication at this stage.

**This repository contains:**

| Path | Contents | License |
|---|---|---|
| `crates/vaultex-crypto/` | The cryptographic core. X3DH key agreement, Double Ratchet message encryption, sealed sender, safety numbers, group messaging, per-file media encryption, message padding. Built on libsodium. **The audit target.** | Apache-2.0 OR MIT |
| `VAULTEX_DESIGN.md` | Full architecture and protocol specification — threat model, X3DH and Double Ratchet implementation notes, API surface, database schema, roadmap. | CC-BY-SA 4.0 |
| `CONTRIBUTING.md` | Developer setup, Git workflow, code review process, definition of done. | CC-BY-SA 4.0 |
| `CHANGELOG.md` | Release history in Keep a Changelog format. | CC-BY-SA 4.0 |

**This repository does NOT contain** — and intentionally so — the desktop application, the mobile clients (Android/iOS), the bulk of the server, the off-grid transport layer, the discovery service, the marketing site source, or the operational/deployment automation. Those live in the private monorepo and are subject to a different licensing strategy.

## Why an "auditable open core"

Trust in a secure-messaging product depends on the cryptographic implementation being verifiable. Users will not (and should not) trust closed-source crypto, no matter how well marketed.

At the same time, fully open-sourcing every line of a commercial product is rarely the right business choice for a small team. So we publish exactly the parts that *must* be auditable to be trustworthy, under permissive licenses that allow re-use without restriction. The rest of the product remains proprietary.

This is the same pattern used by Signal Foundation (Signal app fully open + server closed initially), Tutanota (crypto open + service closed), Threema (protocol spec + audit reports public + application closed), and many other privacy-product vendors that need to balance security transparency with commercial sustainability.

## Status

The cryptographic implementation is **pre-audit**. A third-party security audit by an independent firm is planned before public production deployment; funding is being sought through the Open Tech Fund's Red Team Lab and equivalent programs. **Until the audit is complete and the report is published in this repository, this code should not be deployed in a security-critical environment without independent review.**

If you are a cryptographer or security researcher and would like to review the code before the formal audit, that is welcomed — please open an issue or contact the maintainers privately if your finding is sensitive.

## Building and testing

```bash
git clone https://github.com/VaultexCoder/vaultex.git
cd vaultex/crates/vaultex-crypto

# Run the unit tests
cargo test

# Run the integration tests against the published Signal protocol test vectors
cargo test --test e2e_message_flow

# Run the security-property tests
cargo test --test security_audit_tests

# Lint
cargo clippy --all-targets -- -D warnings

# Memory safety check
grep -r 'unsafe' src/    # should return zero matches
```

Prerequisites: a recent stable Rust toolchain (1.78+), and the libsodium development package (`libsodium-dev` on Debian/Ubuntu; bundled on Windows via `vcpkg`).

## Cryptographic primitives

| Function | Primitive | Source / spec |
|---|---|---|
| Identity keys | Ed25519 | libsodium |
| Key agreement | X25519 | libsodium |
| Session establishment | X3DH (Extended Triple Diffie-Hellman) | Signal specification |
| Message encryption | Double Ratchet | Signal specification |
| Symmetric encryption | XChaCha20-Poly1305 | libsodium |
| Key derivation | HKDF-SHA256 | libsodium |
| Sender unlinkability | Sealed sender | Signal construction |

The implementation explicitly avoids novel primitives. Every algorithm in use has independent academic analysis. The audit's job is to verify (a) faithful implementation of the published Signal specifications against their test vectors, (b) correct use of libsodium, (c) absence of memory-safety or nonce-reuse issues, and (d) correctness of the derived/session key handling.

## Verifying against Signal protocol test vectors

The integration tests in `crates/vaultex-crypto/tests/e2e_message_flow.rs` and `crates/vaultex-crypto/tests/security_audit_tests.rs` exercise the X3DH and Double Ratchet implementations against the published Signal test vectors. To run them locally:

```bash
cargo test --release --test e2e_message_flow
cargo test --release --test security_audit_tests
```

If any assertion fails, the implementation has diverged from the spec and should not be deployed.

## License

The Rust code in `crates/` is **dual-licensed** under the Apache License 2.0 OR the MIT License at your option. This matches the Rust ecosystem's strong convention and ensures the code can be incorporated into projects with either license preference.

- See [`LICENSE-APACHE`](./LICENSE-APACHE) for the Apache 2.0 text.
- See [`LICENSE-MIT`](./LICENSE-MIT) for the MIT text.

Documentation files (`VAULTEX_DESIGN.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, this README) are released under the [Creative Commons Attribution-ShareAlike 4.0 International License (CC-BY-SA 4.0)](https://creativecommons.org/licenses/by-sa/4.0/).

## Responsible disclosure

If you discover a security vulnerability:

- **Please do not open a public issue.**
- Report privately to the maintainers (open an issue marked `security` and mark it private, or email the address listed in [security.txt on the live site](https://vaultexchat.org/.well-known/security.txt) once it is published).
- Allow a reasonable window for remediation before public disclosure.

Once a third-party audit report is published, that report and the project's remediation response will live in the [`audit/`](audit/) directory of this repository.

## Relationship to the private monorepo

This repository is a curated subset of the full VAULTEX monorepo at `gitlab.com/secureapps/vaultex` (private). Code in this repository is **authoritative for the crypto core only** — any changes to the cryptographic implementation must land in both repositories. The private monorepo is updated first; this repository is synced from it on each release.

If you contribute a patch here, the maintainers will manually port it into the monorepo with proper attribution.

## Contact

- Website: [vaultexchat.org](https://vaultexchat.org)
- Documentation: [vaultexchat.org/docs/](https://vaultexchat.org/docs/)
- Demo server (development only, do not store real data): `api.vaultexchat.org`

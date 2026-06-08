# Contributing to VAULTEX

## Development Environment Setup

### Prerequisites

- **Rust** (stable toolchain): `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **Node.js** >= 20 LTS
- **Docker** and **Docker Compose**
- **Tauri prerequisites**: [platform-specific instructions](https://v2.tauri.app/start/prerequisites/)
  - Linux: `sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file libssl-dev libayatana-appindicator3-dev librsvg2-dev`
  - Windows: WebView2 (usually pre-installed on Windows 10/11)

### Setup

```bash
# Clone the repository
git clone git@gitlab.com:secureapps/vaultex.git
cd vaultex

# Install Rust components
rustup component add clippy rustfmt
cargo install cargo-audit cargo-tarpaulin sqlx-cli tauri-cli

# Start infrastructure
cd infrastructure
docker-compose up -d
cd ..

# Build and test Rust workspace
cargo build --workspace
cargo test --workspace

# Set up frontend
cd apps/desktop
npm install
npm test
cd ../..

# Launch desktop app in development mode
cd apps/desktop
cargo tauri dev

# Install pre-commit hooks
pip install pre-commit
pre-commit install
pre-commit install --hook-type pre-push
```

## Git Workflow

We follow **GitFlow**. See `docs/team/processes.md` for full details.

### Branch Naming

| Type | Pattern | Example |
|---|---|---|
| Feature | `feature/<issue-id>-short-description` | `feature/12-x3dh-implementation` |
| Bug Fix | `bugfix/<issue-id>-short-description` | `bugfix/45-fix-nonce-generation` |
| Hotfix | `hotfix/<version>-short-description` | `hotfix/0.1.1-fix-key-derivation` |

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`, `revert`

Scopes: `crypto`, `server`, `ffi`, `ui`, `tauri`, `store`, `db`, `network`, `infra`, `deps`

## Submitting a Merge Request

1. Create a branch from `develop` following the naming convention.
2. Implement your changes with tests.
3. Ensure CI passes locally: `cargo test --workspace && cd apps/desktop && npm test`
4. Push and open an MR targeting `develop`.
5. Fill out the MR template completely, including the security checklist if applicable.
6. Wait for CI and at least one reviewer approval.
7. MRs touching `crates/vaultex-crypto/`, server middleware, or crypto integration require **Security Engineer review**.

## Code Review

- Reviewers respond within 24 hours.
- Authors respond to feedback within 48 hours.
- Use feedback prefixes: `nit:`, `suggestion:`, `question:`, `required:`, `blocker:`, `security:`

## Definition of Done

A story is done when:

- Code implemented with all acceptance criteria satisfied
- Unit tests written and passing
- All CI stages green
- Security review approved (if tagged `security-review-required`)
- Documentation and CHANGELOG updated
- Code reviewed and approved
- QA sign-off received
- MR merged and branch deleted

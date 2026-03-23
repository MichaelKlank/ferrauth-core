# ferrauth-core

> Pluggable authentication for Rust services — Password, TOTP and Passkey in one unified trait.

[![CI](https://img.shields.io/github/actions/workflow/status/MichaelKlank/ferrauth-core/ci.yml?branch=main&logo=github)](https://github.com/MichaelKlank/ferrauth-core/actions/workflows/ci.yml)
[![codecov](https://img.shields.io/codecov/c/github/MichaelKlank/ferrauth-core?branch=main&logo=codecov)](https://codecov.io/gh/MichaelKlank/ferrauth-core)
[![crates.io](https://img.shields.io/crates/v/ferrauth-core.svg)](https://crates.io/crates/ferrauth-core)
[![docs.rs](https://docs.rs/ferrauth-core/badge.svg)](https://docs.rs/ferrauth-core)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

---

## What is ferrauth-core?

`ferrauth-core` is a shared authentication library for the [Ferrum](https://github.com/MichaelKlank/ferrum) ecosystem. It provides a single `AuthProvider` trait that unifies **Password**, **TOTP** and **Passkey (WebAuthn)** authentication behind one interface — so your login handler never needs to change when you add a new auth method.

**Key design decisions:**

- **Zero-Knowledge friendly** — sensitive types like `PlaintextPassword` and `TotpSecret` implement `Zeroize` and are cleared from memory after use. No `Debug` or `Clone` on credentials to prevent accidental logging.
- **Async-first** — all verification runs async. CPU-heavy operations (Argon2) are automatically moved to `spawn_blocking` so they never block the Tokio executor.
- **Feature-flag based** — only compile what you need. No WebAuthn code in your binary if you only use passwords.
- **Opinionated error types** — `AuthError::InvalidCredentials` reveals nothing about whether the email or password was wrong. Security by design, not by accident.

---

## Feature Flags

| Flag | What it enables | Extra dependencies |
|---|---|---|
| *(none)* | `AuthProvider` trait, `SessionState`, `PasswordAuth` | `argon2`, `async-trait` |
| `totp` | `TotpAuth` — TOTP verification and secret generation | `totp-rs` |
| `passkey` | `PasskeyAuth` — WebAuthn registration and authentication | `webauthn-rs` |
| `full` | All of the above | All of the above |

---

## Installation

```toml
# Cargo.toml

# Password auth only (default)
ferrauth-core = "0.1"

# With TOTP support
ferrauth-core = { version = "0.1", features = ["totp"] }

# With Passkey (WebAuthn) support
ferrauth-core = { version = "0.1", features = ["passkey"] }

# Everything
ferrauth-core = { version = "0.1", features = ["full"] }
```

During development alongside Ferrikey or Ferrum Chat, use a path dependency:

```toml
ferrauth-core = { path = "../ferrauth-core", features = ["full"] }
```

---

## Quick Start

### Password Authentication

```rust
use ferrauth_core::{
    AuthProvider, AuthResult, Credentials,
    PasswordAuth, PlaintextPassword, PasswordHash,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Hash a password at registration time
    let password = PlaintextPassword::new("correct-horse-battery-staple");
    let hash: PasswordHash = PasswordAuth::hash_password(&password)?;

    // Store `hash.as_str()` in your database, then verify at login:
    let credentials = Credentials::Password {
        user_id: uuid::Uuid::new_v4(),
        password: PlaintextPassword::new("correct-horse-battery-staple"),
        hash,
    };

    let auth = PasswordAuth;
    match auth.verify(credentials).await {
        Ok(AuthResult { user_id, method }) => {
            println!("Authenticated: {user_id} via {method:?}");
        }
        Err(e) => eprintln!("Auth failed: {e}"),
    }

    Ok(())
}
```

### TOTP (Two-Factor Authentication)

```rust
use ferrauth_core::{TotpAuth, Credentials, AuthProvider};

// At setup: generate a secret and show the QR code to the user
let secret = TotpAuth::generate_secret();
let qr_url = TotpAuth::qr_code_url(&secret, "user@example.com", "Ferrikey");
// → "otpauth://totp/Ferrikey:user%40example.com?secret=BASE32..."

// Store the secret encrypted in your database.

// At login (after password verification):
let credentials = Credentials::Totp {
    user_id,
    code: "123456".to_string(),  // from Google Authenticator
    secret,                       // from your database
};

let auth = TotpAuth;
let result = auth.verify(credentials).await?;
```

### Passkeys (WebAuthn)

```rust
use ferrauth_core::{PasskeyAuth, StoredPasskey};

let auth = PasskeyAuth::new("ferrikey.example.com", "Ferrikey")?;

// Registration (step 1 — send to browser)
let (challenge, state) = auth.begin_registration(user_id, "user@example.com")?;

// Registration (step 2 — after browser responds)
let stored_passkey: StoredPasskey = auth.finish_registration(state, browser_response)?;
// Persist `stored_passkey` in your database.

// Authentication (step 1 — send to browser)
let (challenge, state) = auth.begin_authentication(&[stored_passkey])?;

// Authentication (step 2 — after browser responds)
let (result, updated_passkey) = auth.finish_authentication(state, browser_response, &stored_passkey)?;
// Update `sign_count` in your database with `updated_passkey`.
```

### Using the AuthProvider trait in your login handler

The power of `ferrauth-core` is that your login handler works with any provider via the trait:

```rust
use ferrauth_core::{AuthProvider, AuthError, SessionState};
use chrono::{Utc, Duration};
use std::sync::Arc;

async fn login_handler(
    provider: Arc<dyn AuthProvider>,
    credentials: Credentials,
    user_has_mfa: bool,
) -> Result<SessionState, AuthError> {
    let result = provider.verify(credentials).await?;

    let session = if user_has_mfa {
        SessionState::PendingMfa {
            user_id: result.user_id,
            expires_at: Utc::now() + Duration::minutes(5),
        }
    } else {
        SessionState::Authenticated {
            user_id: result.user_id,
            auth_methods: vec![result.method],
            expires_at: Utc::now() + Duration::hours(24),
        }
    };

    Ok(session)
}
```

When you add Passkeys later, this handler needs **zero changes**. Just pass a different `Arc<dyn AuthProvider>`.

---

## SessionState

`SessionState` is designed to make it impossible to accidentally treat a partially-authenticated session as fully authenticated:

```rust
use ferrauth_core::SessionState;

// After first factor only (MFA still required)
let session = SessionState::PendingMfa { user_id, expires_at };
assert!(!session.is_authenticated());

// After all factors
let session = SessionState::Authenticated { user_id, auth_methods, expires_at };
assert!(session.is_authenticated());

// Check expiry
if session.is_expired() {
    return Err(AuthError::SessionExpired);
}

// Serialize to JSON for storage in Redis
let json = serde_json::to_string(&session)?;
let restored: SessionState = serde_json::from_str(&json)?;
```

---

## Security Design

| Concern | Approach |
|---|---|
| Timing attacks on password comparison | Argon2 constant-time comparison |
| Sensitive data in logs | `Credentials` has no `Debug` impl |
| Key material in memory | `PlaintextPassword`, `TotpSecret` implement `Zeroize` + `ZeroizeOnDrop` |
| Vague error messages | `AuthError::InvalidCredentials` — never hints at which field was wrong |
| Replay attacks (Passkey) | `sign_count` is checked and must increment on every authentication |
| TOTP clock drift | ±1 time window (30s) tolerated |
| CPU blocking in async | Argon2 runs in `tokio::task::spawn_blocking` |

---

## OpenTelemetry Tracing

`ferrauth-core` instruments all `verify()` calls with `tracing` spans. If your service registers an OpenTelemetry subscriber, auth operations show up as spans automatically:

```
auth.verify
  auth.method = "Password"
  user.id = "550e8400-e29b-41d4-a716-446655440000"
  otel.status_code = "OK"
```

No sensitive data (passwords, secrets, tokens) is ever included in span attributes.

To use it, just register your own subscriber in your service — `ferrauth-core` uses the `tracing` facade and never forces a specific subscriber on you:

```rust
// In your service's main.rs
tracing_subscriber::fmt()
    .with_env_filter(EnvFilter::from_default_env())
    .json()
    .init();
```

---

## Examples

Run the examples with:

```bash
# Password auth roundtrip
cargo run --example password_auth

# TOTP setup + verification
cargo run --example totp_auth --features totp

# Session state machine
cargo run --example session_state
```

---

## Development

### Prerequisites

- Rust (stable) via [rustup](https://rustup.rs/)

### Git hooks (pre-commit)

This repo uses [`cargo-husky`](https://github.com/rhysd/cargo-husky) as a **dev-dependency**. On the first `cargo test` (or any build that compiles dev-dependencies, e.g. `cargo clippy --all-targets`), its build script copies **`.cargo-husky/hooks/pre-commit`** into **`.git/hooks/pre-commit`** (if that hook is not already present from the same cargo-husky version).

The **pre-commit** hook runs:

1. `cargo fmt --all -- --check` — fails if the tree is not rustfmt-clean  
2. `cargo clippy --all-features -- -D warnings` — same bar as CI  

To **skip** hook installation (e.g. in automation), set:

```bash
export CARGO_HUSKY_DONT_INSTALL_HOOKS=true
```

To **refresh** hooks after upgrading `cargo-husky`, remove `.git/hooks/pre-commit` (if it was generated by cargo-husky) and run `cargo test` again. On Unix, ensure `.cargo-husky/hooks/pre-commit` stays **executable** (`chmod +x`).

### Build and test

```bash
# Build with all features
cargo build --all-features

# Run all tests (also installs pre-commit hook locally via cargo-husky, unless disabled above)
cargo test --all-features

# Run linting
cargo clippy --all-features -- -D warnings

# Check formatting
cargo fmt --check

# Check for known vulnerabilities
cargo audit

# Build documentation
cargo doc --all-features --no-deps --open
```

### Run a single example

```bash
cargo run --example password_auth
cargo run --example totp_auth --features totp
cargo run --example session_state
```

---

## Project Structure

```
ferrauth-core/
├── src/
│   ├── lib.rs              # Public API and re-exports
│   ├── provider.rs         # AuthProvider trait, AuthMethod, AuthResult
│   ├── credentials.rs      # Credentials enum, Newtypes (PlaintextPassword etc.)
│   ├── session.rs          # SessionState machine
│   ├── error.rs            # AuthError types
│   ├── password.rs         # PasswordAuth implementation
│   ├── totp.rs             # TotpAuth (feature: totp)
│   └── passkey.rs          # PasskeyAuth (feature: passkey)
├── examples/
│   ├── password_auth.rs
│   ├── totp_auth.rs
│   └── session_state.rs
├── tests/
│   └── integration_tests.rs
├── CHANGELOG.md
├── CONTRIBUTING.md
└── LICENSE
```

---

## Used by

- [ferrikey](https://github.com/MichaelKlank/ferrikey) — Self-hosted password manager (Bitwarden-compatible)
- [ferrum](https://github.com/MichaelKlank/ferrum) — Self-hosted team chat (Mattermost-compatible)

---

## Versioning

This crate follows [Semantic Versioning](https://semver.org/). The public API is defined by everything under `pub use` in `lib.rs`.

**Breaking changes** (require a major version bump):
- Changing the signature of any `AuthProvider` method
- Removing or renaming public types
- Changing the serialization format of `SessionState`

**Non-breaking additions** (minor version):
- New `AuthMethod` variants (marked `#[non_exhaustive]`)
- New optional methods on `AuthProvider` with default implementations
- New feature flags

See [CHANGELOG.md](./CHANGELOG.md) for the full history.

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](./CONTRIBUTING.md) for the development workflow, SemVer policy and breaking change process.

---

## License

MIT — see [LICENSE](./LICENSE).
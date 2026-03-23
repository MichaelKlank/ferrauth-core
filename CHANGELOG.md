# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `AuthProvider` trait with `verify()` and `method()` — unified interface for all auth methods
- `AuthMethod` enum: `Password`, `Totp`, `Passkey` (marked `#[non_exhaustive]`)
- `AuthResult` struct containing `user_id: Uuid` and `method: AuthMethod`
- `Credentials` enum with variants for `Password`, `Totp` and `Passkey`
- `PlaintextPassword` and `TotpSecret` newtypes implementing `Zeroize` + `ZeroizeOnDrop`
- `PasswordHash` newtype — no `Clone` or `Debug` to prevent accidental logging
- `AuthError` enum via `thiserror`: `InvalidCredentials`, `MfaRequired`, `InvalidMfaCode`, `SessionExpired`, `PasskeyVerificationFailed`, `Internal`
- `SessionState` enum: `PendingMfa` and `Authenticated` with `is_authenticated()`, `is_expired()`, `user_id()` helpers
- `SessionState` implements `serde::Serialize` + `serde::Deserialize` for Redis storage
- `PasswordAuth` — Argon2-based password verification running in `tokio::task::spawn_blocking`
- `PasswordAuth::hash_password()` helper for hashing at registration time
- `TotpAuth` behind feature flag `totp` — TOTP verification via `totp-rs` with ±1 window drift tolerance
- `TotpAuth::generate_secret()` — generates 20 bytes of cryptographically random Base32 secret
- `TotpAuth::qr_code_url()` — returns a valid `otpauth://totp/...` URL for QR code generation
- `PasskeyAuth` behind feature flag `passkey` — WebAuthn registration and authentication via `webauthn-rs`
- `PasskeyAuth::begin_registration()` / `finish_registration()` — full WebAuthn registration flow
- `PasskeyAuth::begin_authentication()` / `finish_authentication()` — full WebAuthn authentication flow with sign counter validation
- `StoredPasskey` struct — serializable credential for database persistence
- `tracing` instrumentation on all `verify()` calls — spans include `auth.method` and `user.id`, no sensitive data
- Feature flags: `totp`, `passkey`, `full` (enables both)
- Examples: `password_auth`, `totp_auth`, `session_state`
- Rustdoc with doctests for all public types

[unreleased]: https://github.com/MichaelKlank/ferrauth-core/commits/main

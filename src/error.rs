//! Authentication errors — safe [`Display`](std::fmt::Display) output only (no secrets).

use thiserror::Error;

/// Errors returned by [`crate::AuthProvider::verify`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuthError {
    /// First-factor or combined credentials were rejected (no hint which part failed).
    #[error("invalid credentials")]
    InvalidCredentials,
    /// Second factor is required before the session is fully authenticated.
    #[error("mfa required")]
    MfaRequired,
    /// TOTP or similar MFA code was wrong or out of window.
    #[error("invalid mfa code")]
    InvalidMfaCode,
    /// Session is no longer valid.
    #[error("session expired")]
    SessionExpired,
    /// WebAuthn / passkey verification failed.
    #[error("passkey verification failed")]
    PasskeyVerificationFailed,
    /// Unexpected failure (logged server-side; not shown to clients as distinct variants).
    #[error("internal error")]
    Internal,
}

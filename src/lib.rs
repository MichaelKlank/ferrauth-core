//! Pluggable authentication: password (always), optional TOTP and passkey providers.
//!
//! ## Tracing
//!
//! [`AuthProvider::verify`] implementations emit `tracing` spans and events. Sensitive values are
//! never passed into [`tracing::instrument`] fields — use [`telemetry`](crate::telemetry) attribute
//! names only with coarse labels and ids.

pub mod telemetry;

mod auth_method;
mod auth_tracing;
mod credentials;
mod error;
mod password;
mod provider;
mod result;

#[cfg(feature = "passkey")]
mod passkey;
#[cfg(feature = "totp")]
mod totp;

pub use auth_method::AuthMethod;
#[cfg(feature = "totp")]
pub use credentials::TotpSecret;
pub use credentials::{Credentials, PasswordHash, PlaintextPassword};
pub use error::AuthError;
#[cfg(feature = "passkey")]
pub use passkey::PasskeyAuth;
pub use password::PasswordAuth;
pub use provider::AuthProvider;
pub use result::AuthResult;
#[cfg(feature = "totp")]
pub use totp::TotpAuth;

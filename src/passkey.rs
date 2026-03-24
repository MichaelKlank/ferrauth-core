//! Passkey / WebAuthn provider shell (feature `passkey`).
//!
//! Full WebAuthn ceremonies use `webauthn-rs` begin/finish APIs. [`AuthProvider::verify`] is kept
//! for a uniform trait surface; direct passkey login should use those flows.

use async_trait::async_trait;

use crate::auth_method::AuthMethod;
use crate::auth_tracing;
use crate::credentials::Credentials;
use crate::error::AuthError;
use crate::provider::AuthProvider;
use crate::result::AuthResult;
use crate::telemetry::{ATTR_AUTH_METHOD, ATTR_USER_ID};

/// Passkey authentication provider (placeholder `verify` — use WebAuthn ceremony APIs in production).
#[derive(Debug, Clone)]
pub struct PasskeyAuth {
    rp_id: String,
    rp_name: String,
}

impl PasskeyAuth {
    /// Configure relying party id and display name for future WebAuthn operations.
    pub fn new(rp_id: &str, rp_name: &str) -> Result<Self, AuthError> {
        if rp_id.is_empty() || rp_name.is_empty() {
            return Err(AuthError::Internal);
        }
        Ok(Self { rp_id: rp_id.to_string(), rp_name: rp_name.to_string() })
    }

    /// Relying party id (e.g. registrable domain suffix) configured at construction.
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// Human-readable RP name shown in WebAuthn UI.
    pub fn rp_name(&self) -> &str {
        &self.rp_name
    }
}

/// Sync core so line coverage maps to this file (`async_trait` bodies are often invisible to llvm-cov).
pub(crate) fn verify_passkey_credentials(
    credentials: Credentials,
) -> Result<AuthResult, AuthError> {
    let Credentials::Passkey { user_id } = credentials else {
        let err = AuthError::InvalidCredentials;
        auth_tracing::log_verify_failed(&err);
        return Err(err);
    };

    auth_tracing::record_verify_user_id(&user_id);

    let err = AuthError::PasskeyVerificationFailed;
    auth_tracing::log_verify_failed(&err);
    Err(err)
}

#[async_trait]
impl AuthProvider for PasskeyAuth {
    #[tracing::instrument(
        name = "PasskeyAuth::verify",
        skip_all,
        fields(
            { ATTR_AUTH_METHOD } = %"passkey",
            { ATTR_USER_ID } = tracing::field::Empty,
        ),
    )]
    async fn verify(&self, credentials: Credentials) -> Result<AuthResult, AuthError> {
        verify_passkey_credentials(credentials)
    }

    fn method(&self) -> AuthMethod {
        AuthMethod::Passkey
    }
}

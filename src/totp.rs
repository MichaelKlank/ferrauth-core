//! TOTP verification (feature `totp`).

use async_trait::async_trait;
use totp_rs::{Algorithm, TOTP};

use crate::auth_method::AuthMethod;
use crate::auth_tracing;
use crate::credentials::Credentials;
use crate::error::AuthError;
use crate::provider::AuthProvider;
use crate::result::AuthResult;
use crate::telemetry::{ATTR_AUTH_METHOD, ATTR_USER_ID};

/// Time-based one-time password provider (RFC 6238).
#[derive(Debug, Default, Clone, Copy)]
pub struct TotpAuth;

/// Sync core so line coverage maps to this file (`async_trait` bodies are often invisible to llvm-cov).
pub(crate) fn verify_totp_credentials(credentials: Credentials) -> Result<AuthResult, AuthError> {
    let Credentials::Totp { user_id, code, secret } = credentials else {
        let err = AuthError::InvalidCredentials;
        auth_tracing::log_verify_failed(&err);
        return Err(err);
    };

    auth_tracing::record_verify_user_id(&user_id);

    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret.as_slice().to_vec())
        .map_err(|_| AuthError::Internal)?;

    let ok = totp.check_current(code.trim()).map_err(|_| AuthError::Internal)?;

    if !ok {
        let err = AuthError::InvalidMfaCode;
        auth_tracing::log_verify_failed(&err);
        return Err(err);
    }

    auth_tracing::log_verify_succeeded(&user_id, AuthMethod::Totp.as_label());
    Ok(AuthResult { user_id, method: AuthMethod::Totp })
}

#[async_trait]
impl AuthProvider for TotpAuth {
    #[tracing::instrument(
        name = "TotpAuth::verify",
        skip_all,
        fields(
            { ATTR_AUTH_METHOD } = %"totp",
            { ATTR_USER_ID } = tracing::field::Empty,
        ),
    )]
    async fn verify(&self, credentials: Credentials) -> Result<AuthResult, AuthError> {
        verify_totp_credentials(credentials)
    }

    fn method(&self) -> AuthMethod {
        AuthMethod::Totp
    }
}

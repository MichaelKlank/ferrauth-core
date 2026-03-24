//! Password authentication via Argon2 (CPU work on a blocking thread).

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{
    PasswordHash as PhcHash, PasswordHasher, PasswordVerifier, SaltString,
};
use async_trait::async_trait;

use crate::auth_method::AuthMethod;
use crate::auth_tracing;
use crate::credentials::{Credentials, PasswordHash, PlaintextPassword};
use crate::error::AuthError;
use crate::provider::AuthProvider;
use crate::result::AuthResult;
use crate::telemetry::{ATTR_AUTH_METHOD, ATTR_USER_ID};

/// Argon2 password provider.
#[derive(Debug, Default, Clone, Copy)]
pub struct PasswordAuth;

impl PasswordAuth {
    /// Hash a password for storage (e.g. at registration). Runs on the calling thread.
    pub fn hash_password(password: &PlaintextPassword) -> Result<PasswordHash, AuthError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_slice(), &salt)
            .map_err(|_| AuthError::Internal)?
            .to_string();
        Ok(PasswordHash::new(hash))
    }
}

fn verify_password_blocking(password: PlaintextPassword, hash: String) -> Result<(), AuthError> {
    let parsed = PhcHash::new(&hash).map_err(|_| AuthError::Internal)?;
    Argon2::default()
        .verify_password(password.as_slice(), &parsed)
        .map_err(|_| AuthError::InvalidCredentials)?;
    Ok(())
}

#[async_trait]
impl AuthProvider for PasswordAuth {
    #[tracing::instrument(
        name = "PasswordAuth::verify",
        skip_all,
        fields(
            { ATTR_AUTH_METHOD } = %"password",
            { ATTR_USER_ID } = tracing::field::Empty,
        ),
    )]
    async fn verify(&self, credentials: Credentials) -> Result<AuthResult, AuthError> {
        let (user_id, password, hash) = match credentials {
            Credentials::Password { user_id, password, hash } => (user_id, password, hash),
            #[cfg(any(feature = "totp", feature = "passkey"))]
            _ => {
                let err = AuthError::InvalidCredentials;
                auth_tracing::log_verify_failed(&err);
                return Err(err);
            }
        };

        auth_tracing::record_verify_user_id(&user_id);
        let hash_str = hash.as_str().to_string();

        let verify =
            tokio::task::spawn_blocking(move || verify_password_blocking(password, hash_str))
                .await
                .map_err(|_| AuthError::Internal);

        match verify {
            Ok(Ok(())) => {
                let result = AuthResult { user_id, method: AuthMethod::Password };
                auth_tracing::log_verify_succeeded(&user_id, AuthMethod::Password.as_label());
                Ok(result)
            }
            Ok(Err(err)) => {
                auth_tracing::log_verify_failed(&err);
                Err(err)
            }
            Err(_) => {
                let err = AuthError::Internal;
                auth_tracing::log_verify_failed(&err);
                Err(err)
            }
        }
    }

    fn method(&self) -> AuthMethod {
        AuthMethod::Password
    }
}

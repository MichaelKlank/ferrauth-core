//! [`AuthProvider`] trait.

use async_trait::async_trait;

use crate::auth_method::AuthMethod;
use crate::credentials::Credentials;
use crate::error::AuthError;
use crate::result::AuthResult;

/// Pluggable authentication (password, TOTP, passkey, …).
#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// Verify credentials and return the authenticated subject.
    async fn verify(&self, credentials: Credentials) -> Result<AuthResult, AuthError>;

    /// Which [`AuthMethod`] this provider represents.
    fn method(&self) -> AuthMethod;
}

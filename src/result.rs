//! Successful authentication outcome.

use uuid::Uuid;

use crate::auth_method::AuthMethod;

/// Returned when [`crate::AuthProvider::verify`] succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResult {
    pub user_id: Uuid,
    pub method: AuthMethod,
}

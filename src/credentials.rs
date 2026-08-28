//! Credential payloads for [`crate::AuthProvider::verify`].
//!
//! These types intentionally avoid [`Debug`] where they may hold secrets.

use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// UTF-8 password as owned bytes; cleared on drop. Not [`Debug`] or [`Clone`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PlaintextPassword(Vec<u8>);

impl PlaintextPassword {
    /// Stores a copy of `password` in cleared-on-drop memory.
    pub fn new(password: impl AsRef<[u8]>) -> Self {
        Self(password.as_ref().to_vec())
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

/// Argon2 password hash string (e.g. PHC). No [`Debug`] or [`Clone`] to reduce accidental leakage.
pub struct PasswordHash(String);

impl PasswordHash {
    pub(crate) fn new(phc: String) -> Self {
        Self(phc)
    }

    /// Wrap a PHC string loaded from storage (e.g. a database row).
    pub fn from_phc(phc: impl Into<String>) -> Self {
        Self(phc.into())
    }

    /// Borrow the PHC string for verification or persistence.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Raw TOTP secret (≥ 128 bits). Cleared on drop. Not [`Debug`] or [`Clone`].
#[cfg(feature = "totp")]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TotpSecret(Vec<u8>);

#[cfg(feature = "totp")]
impl TotpSecret {
    /// Takes ownership of secret bytes; must meet minimum length for RFC 6238.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, crate::AuthError> {
        if bytes.len() < 16 {
            return Err(crate::AuthError::Internal);
        }
        Ok(Self(bytes))
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

/// Input bundle for [`crate::AuthProvider::verify`]. Not [`Debug`] — may contain secrets.
pub enum Credentials {
    Password {
        user_id: Uuid,
        password: PlaintextPassword,
        hash: PasswordHash,
    },
    #[cfg(feature = "totp")]
    Totp {
        user_id: Uuid,
        code: String,
        secret: TotpSecret,
    },
    #[cfg(feature = "passkey")]
    Passkey {
        user_id: Uuid,
    },
}

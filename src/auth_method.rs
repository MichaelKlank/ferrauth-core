//! Coarse auth method labels for results and telemetry.

/// Method used to authenticate (for [`crate::AuthResult`] and tracing).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthMethod {
    Password,
    #[cfg(feature = "totp")]
    Totp,
    #[cfg(feature = "passkey")]
    Passkey,
}

impl AuthMethod {
    /// Stable label for tracing / logs (not a secret).
    pub const fn as_label(self) -> &'static str {
        match self {
            AuthMethod::Password => "password",
            #[cfg(feature = "totp")]
            AuthMethod::Totp => "totp",
            #[cfg(feature = "passkey")]
            AuthMethod::Passkey => "passkey",
        }
    }
}

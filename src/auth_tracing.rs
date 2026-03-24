//! Internal tracing helpers for auth verification (no credentials).

use uuid::Uuid;

use crate::AuthError;
use crate::telemetry::{ATTR_AUTH_METHOD, ATTR_USER_ID};

pub(crate) fn record_verify_user_id(user_id: &Uuid) {
    tracing::Span::current().record(ATTR_USER_ID, tracing::field::display(user_id));
}

/// Successful verify: [`tracing::info!`] with standard field names (see [`crate::telemetry`]).
pub(crate) fn log_verify_succeeded(user_id: &Uuid, auth_method_label: &'static str) {
    tracing::info!(
        { ATTR_USER_ID } = %user_id,
        { ATTR_AUTH_METHOD } = %auth_method_label,
        "authentication succeeded",
    );
}

/// Failed verify: [`tracing::error!`] with error kind only ([`AuthError`]'s [`Display`](std::fmt::Display)).
pub(crate) fn log_verify_failed(err: &AuthError) {
    tracing::error!(
        auth.error = %err,
        "authentication failed",
    );
}

//! Tracing helpers for authentication flows.
//!
//! This crate does **not** re-export [`tracing`]. Applications must register their own subscriber
//! (e.g. `tracing-subscriber`). If no subscriber is installed, tracing is a no-op.
//!
//! Use only **non-sensitive** inputs: an auth method label (e.g. `"password"`, `"totp"`) and an
//! optional user id. Never pass passwords, TOTP secrets, tokens, or session secrets into these APIs.

use std::borrow::Cow;

use tracing::Span;
use uuid::Uuid;

/// Stable span name for auth-related work.
pub const SPAN_AUTH: &str = "ferrauth.auth";

/// Standard attribute: authentication method label (not a secret).
pub const ATTR_AUTH_METHOD: &str = "auth.method";

/// Standard attribute: authenticated subject identifier (e.g. user id).
pub const ATTR_USER_ID: &str = "user.id";

/// Maximum UTF-8 byte length of the sanitized auth method label written to the span.
///
/// If the trimmed first line is longer than this, it is truncated and a single ellipsis
/// character (`…`) is appended. The prefix is shortened so **prefix + `…`** never exceeds
/// this byte length.
pub const MAX_AUTH_METHOD_LABEL_UTF8_BYTES: usize = 64;

const AUTH_METHOD_TRUNCATION_SUFFIX: char = '…';

/// Longest prefix of `s` that ends on a UTF-8 boundary and has byte length ≤ `max_bytes`.
fn utf8_prefix_at_most_bytes(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = 0usize;
    for (i, ch) in s.char_indices() {
        let next = i + ch.len_utf8();
        if next > max_bytes {
            break;
        }
        end = next;
    }
    &s[..end]
}

fn sanitize_auth_method_label(s: &str) -> Cow<'_, str> {
    let s = s.trim();
    let s = s.lines().next().unwrap_or("").trim();
    if s.is_empty() {
        return Cow::Borrowed("unknown");
    }
    if s.len() > MAX_AUTH_METHOD_LABEL_UTF8_BYTES {
        let max_prefix = MAX_AUTH_METHOD_LABEL_UTF8_BYTES
            .saturating_sub(AUTH_METHOD_TRUNCATION_SUFFIX.len_utf8());
        let truncated = utf8_prefix_at_most_bytes(s, max_prefix);
        Cow::Owned(format!("{truncated}{AUTH_METHOD_TRUNCATION_SUFFIX}"))
    } else {
        Cow::Borrowed(s)
    }
}

/// Returns a span with the standard auth attributes [`ATTR_AUTH_METHOD`] and [`ATTR_USER_ID`].
///
/// `auth_method` should be a coarse label (e.g. `"passkey"`), not a credential.
/// `user_id` is optional (field omitted from export when empty on some backends).
pub fn auth_span(auth_method: &str, user_id: Option<&Uuid>) -> Span {
    let method = sanitize_auth_method_label(auth_method);
    match user_id {
        Some(id) => tracing::info_span!(
            SPAN_AUTH,
            { ATTR_AUTH_METHOD } = %method,
            { ATTR_USER_ID } = %id,
        ),
        None => tracing::info_span!(
            SPAN_AUTH,
            { ATTR_AUTH_METHOD } = %method,
            { ATTR_USER_ID } = tracing::field::Empty,
        ),
    }
}

/// Same spans as [`auth_span`], for call sites that prefer a macro.
///
/// Bind the span to a local before [`.enter()`](tracing::Span::enter); do not chain
/// `auth_operation_span!(…).enter()` (temporary span).
#[macro_export]
macro_rules! auth_operation_span {
    ($method:expr) => {
        $crate::telemetry::auth_span($method, ::core::option::Option::None)
    };
    ($method:expr, user_id = $uid:expr) => {
        $crate::telemetry::auth_span($method, ::core::option::Option::Some($uid))
    };
}

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

const MAX_AUTH_METHOD_LEN: usize = 64;

fn sanitize_auth_method_label(s: &str) -> Cow<'_, str> {
    let s = s.trim();
    let s = s.lines().next().unwrap_or("").trim();
    if s.is_empty() {
        return Cow::Borrowed("unknown");
    }
    if s.len() > MAX_AUTH_METHOD_LEN {
        Cow::Owned(format!("{}…", &s[..MAX_AUTH_METHOD_LEN]))
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
            "auth.method" = %method,
            "user.id" = %id,
        ),
        None => tracing::info_span!(
            SPAN_AUTH,
            "auth.method" = %method,
            "user.id" = tracing::field::Empty,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use tracing::field::{Field, Visit};
    use tracing::span::Attributes;
    use tracing::subscriber::NoSubscriber;
    use tracing_subscriber::Registry;
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

    #[derive(Default, Clone)]
    struct Captured(Arc<Mutex<Vec<(String, String)>>>);

    #[derive(Default)]
    struct RecordVisitor {
        pairs: Vec<(String, String)>,
    }

    impl Visit for RecordVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.pairs.push((field.name().to_string(), format!("{value:?}")));
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.pairs.push((field.name().to_string(), value.to_string()));
        }

        fn record_bool(&mut self, field: &Field, value: bool) {
            self.pairs.push((field.name().to_string(), format!("{value}")));
        }

        fn record_i64(&mut self, field: &Field, value: i64) {
            self.pairs.push((field.name().to_string(), format!("{value}")));
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            self.pairs.push((field.name().to_string(), format!("{value}")));
        }

        fn record_i128(&mut self, field: &Field, value: i128) {
            self.pairs.push((field.name().to_string(), format!("{value}")));
        }

        fn record_u128(&mut self, field: &Field, value: u128) {
            self.pairs.push((field.name().to_string(), format!("{value}")));
        }

        fn record_f64(&mut self, field: &Field, value: f64) {
            self.pairs.push((field.name().to_string(), format!("{value}")));
        }
    }

    struct CaptureLayer(Captured);

    impl<S> Layer<S> for CaptureLayer
    where
        S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        fn on_new_span(
            &self,
            attrs: &Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: Context<'_, S>,
        ) {
            let mut visitor = RecordVisitor::default();
            attrs.record(&mut visitor);
            self.0.0.lock().expect("lock poisoned").extend(visitor.pairs);
        }
    }

    const FORBIDDEN_NAME_FRAGMENTS: &[&str] = &["password", "secret", "token"];

    fn assert_no_sensitive_field_names(pairs: &[(String, String)]) {
        for (name, _) in pairs {
            let lower = name.to_ascii_lowercase();
            for frag in FORBIDDEN_NAME_FRAGMENTS {
                assert!(!lower.contains(frag), "field name must not suggest secrets: {name:?}");
            }
        }
    }

    fn assert_only_standard_auth_fields(pairs: &[(String, String)]) {
        for (name, _) in pairs {
            assert!(
                name == ATTR_AUTH_METHOD || name == ATTR_USER_ID,
                "unexpected field {name:?}; only {ATTR_AUTH_METHOD} and {ATTR_USER_ID} are allowed"
            );
        }
    }

    #[test]
    fn auth_span_records_only_standard_fields_without_sensitive_names() {
        let captured = Captured::default();
        let subscriber = Registry::default().with(CaptureLayer(captured.clone()));
        let _guard = tracing::subscriber::set_default(subscriber);

        let uid = Uuid::nil();
        let span = auth_span("totp", Some(&uid));
        let _entered = span.enter();

        let pairs = captured.0.lock().expect("lock poisoned").clone();
        assert_only_standard_auth_fields(&pairs);
        assert_no_sensitive_field_names(&pairs);
        assert!(pairs.iter().any(|(k, _)| k == ATTR_AUTH_METHOD), "missing {}", ATTR_AUTH_METHOD);
        assert!(pairs.iter().any(|(k, _)| k == ATTR_USER_ID), "missing {}", ATTR_USER_ID);
    }

    #[test]
    fn no_subscriber_does_not_panic() {
        let _guard = tracing::subscriber::set_default(NoSubscriber::default());
        let span = auth_span("password", None);
        let _e = span.enter();
        let span2 = crate::auth_operation_span!("totp", user_id = &Uuid::nil());
        let _e2 = span2.enter();
    }

    #[test]
    fn macro_matches_function_span() {
        let captured = Captured::default();
        let subscriber = Registry::default().with(CaptureLayer(captured.clone()));
        let _guard = tracing::subscriber::set_default(subscriber);

        let uid = Uuid::nil();
        let span = crate::auth_operation_span!("passkey", user_id = &uid);
        let _e = span.enter();

        let pairs = captured.0.lock().expect("lock poisoned").clone();
        assert_only_standard_auth_fields(&pairs);
        assert_no_sensitive_field_names(&pairs);
    }
}

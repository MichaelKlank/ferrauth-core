//! Integration tests for [`ferrauth_core::telemetry`]. Kept here so `cargo llvm-cov` does not count
//! large test-only helpers toward `src/telemetry.rs` line coverage (80% gate).

use std::sync::{Arc, Mutex};

use ferrauth_core::auth_operation_span;
use ferrauth_core::telemetry::{ATTR_AUTH_METHOD, ATTR_USER_ID, SPAN_AUTH, auth_span};
use tracing::field::{Field, Visit};
use tracing::span::Attributes;
use tracing::subscriber::NoSubscriber;
use tracing_subscriber::Registry;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use uuid::Uuid;

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
    fn on_new_span(&self, attrs: &Attributes<'_>, _id: &tracing::span::Id, _ctx: Context<'_, S>) {
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

fn method_value(pairs: &[(String, String)]) -> String {
    pairs.iter().find(|(k, _)| k == ATTR_AUTH_METHOD).map(|(_, v)| v.clone()).expect("auth.method")
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
    assert!(pairs.iter().any(|(k, _)| k == ATTR_AUTH_METHOD));
    assert!(pairs.iter().any(|(k, _)| k == ATTR_USER_ID));
}

#[test]
fn no_subscriber_does_not_panic() {
    let _guard = tracing::subscriber::set_default(NoSubscriber::default());
    let span = auth_span("password", None);
    let _e = span.enter();
    let span2 = auth_operation_span!("totp", user_id = &Uuid::nil());
    let _e2 = span2.enter();
}

#[test]
fn macro_matches_function_span() {
    let captured = Captured::default();
    let subscriber = Registry::default().with(CaptureLayer(captured.clone()));
    let _guard = tracing::subscriber::set_default(subscriber);

    let uid = Uuid::nil();
    let span = auth_operation_span!("passkey", user_id = &uid);
    let _e = span.enter();

    let pairs = captured.0.lock().expect("lock poisoned").clone();
    assert_only_standard_auth_fields(&pairs);
    assert_no_sensitive_field_names(&pairs);
}

#[test]
fn macro_one_arg_form() {
    let captured = Captured::default();
    let subscriber = Registry::default().with(CaptureLayer(captured.clone()));
    let _guard = tracing::subscriber::set_default(subscriber);

    let span = auth_operation_span!("oauth");
    let _e = span.enter();

    let pairs = captured.0.lock().expect("lock poisoned").clone();
    assert_only_standard_auth_fields(&pairs);
    assert_no_sensitive_field_names(&pairs);
    assert!(pairs.iter().any(|(k, _)| k == ATTR_AUTH_METHOD));
}

#[test]
fn sanitize_empty_auth_method_becomes_unknown() {
    let captured = Captured::default();
    let subscriber = Registry::default().with(CaptureLayer(captured.clone()));
    let _guard = tracing::subscriber::set_default(subscriber);

    for input in ["", "   ", "\n\t  "] {
        let span = auth_span(input, None);
        let _e = span.enter();
        let pairs = captured.0.lock().expect("lock poisoned").clone();
        let v = method_value(&pairs);
        assert!(v.contains("unknown"), "expected unknown for {input:?}, got {v:?}");
        captured.0.lock().expect("lock poisoned").clear();
    }
}

#[test]
fn sanitize_truncates_long_method_label() {
    let captured = Captured::default();
    let subscriber = Registry::default().with(CaptureLayer(captured.clone()));
    let _guard = tracing::subscriber::set_default(subscriber);

    let long = "a".repeat(70);
    let span = auth_span(&long, None);
    let _e = span.enter();

    let pairs = captured.0.lock().expect("lock poisoned").clone();
    let v = method_value(&pairs);
    assert!(v.contains('…') || v.len() <= 70, "value should truncate: {v:?}");
}

#[test]
fn sanitize_uses_first_line_only() {
    let captured = Captured::default();
    let subscriber = Registry::default().with(CaptureLayer(captured.clone()));
    let _guard = tracing::subscriber::set_default(subscriber);

    let span = auth_span("first-line\nsecond-line", None);
    let _e = span.enter();

    let pairs = captured.0.lock().expect("lock poisoned").clone();
    let v = method_value(&pairs);
    assert!(v.contains("first-line") && !v.contains("second-line"), "{v:?}");
}

#[test]
fn span_name_is_stable() {
    assert_eq!(SPAN_AUTH, "ferrauth.auth");
}

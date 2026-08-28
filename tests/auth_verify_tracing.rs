//! Ensures [`AuthProvider::verify`] tracing does not record passwords, TOTP secrets, or codes.

use std::sync::{Arc, Mutex};

use ferrauth_core::telemetry::{ATTR_AUTH_METHOD, ATTR_USER_ID};
use ferrauth_core::{
    AuthError, AuthMethod, AuthProvider, AuthResult, Credentials, PasswordAuth, PasswordHash,
    PlaintextPassword,
};
use tracing::Subscriber;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Record};
use tracing_subscriber::Registry;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use uuid::Uuid;

#[cfg(feature = "passkey")]
use ferrauth_core::PasskeyAuth;
#[cfg(feature = "totp")]
use ferrauth_core::{TotpAuth, TotpSecret};
#[cfg(feature = "totp")]
use totp_rs::{Algorithm, TOTP};

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

struct AllFieldsLayer(Captured);

impl<S> Layer<S> for AllFieldsLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, _id: &tracing::span::Id, _ctx: Context<'_, S>) {
        let mut visitor = RecordVisitor::default();
        attrs.record(&mut visitor);
        self.0.0.lock().expect("lock poisoned").extend(visitor.pairs);
    }

    fn on_record(&self, _span: &tracing::span::Id, values: &Record<'_>, _ctx: Context<'_, S>) {
        let mut visitor = RecordVisitor::default();
        values.record(&mut visitor);
        self.0.0.lock().expect("lock poisoned").extend(visitor.pairs);
    }

    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = RecordVisitor::default();
        event.record(&mut visitor);
        let mut lock = self.0.0.lock().expect("lock poisoned");
        lock.extend(visitor.pairs);
        lock.push(("event.name".to_string(), event.metadata().name().to_string()));
    }
}

fn captured_dump(c: &Captured) -> String {
    let lock = c.0.lock().expect("lock poisoned");
    lock.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("\n")
}

fn clear(c: &Captured) {
    c.0.lock().expect("lock poisoned").clear();
}

/// Known password — must never appear in tracing field values or event metadata we collect.
const PLAINTEXT_PASSWORD: &str = "CorrectHorseBatteryStaple-TracingTest-99!";

#[tokio::test]
async fn password_verify_never_records_plaintext_in_tracing() {
    let captured = Captured::default();
    let subscriber = Registry::default().with(AllFieldsLayer(captured.clone()));
    let _guard = tracing::subscriber::set_default(subscriber);

    let user_id = Uuid::new_v4();
    let hash =
        PasswordAuth::hash_password(&PlaintextPassword::new(PLAINTEXT_PASSWORD)).expect("hash");

    let wrong = PlaintextPassword::new("wrong-password-not-the-secret");
    let creds = Credentials::Password {
        user_id,
        password: wrong,
        hash: PasswordHash::from_phc(hash.as_str()),
    };
    let err = PasswordAuth.verify(creds).await.expect_err("wrong password");
    assert_eq!(err, AuthError::InvalidCredentials);
    let dump = captured_dump(&captured);
    assert!(
        !dump.contains(PLAINTEXT_PASSWORD),
        "tracing must not contain plaintext password (failure path): {dump}"
    );
    clear(&captured);

    let creds_ok = Credentials::Password {
        user_id,
        password: PlaintextPassword::new(PLAINTEXT_PASSWORD),
        hash: PasswordHash::from_phc(hash.as_str()),
    };
    let result = PasswordAuth.verify(creds_ok).await.expect("verify");
    assert_eq!(result, AuthResult { user_id, method: AuthMethod::Password });
    let dump = captured_dump(&captured);
    assert!(
        !dump.contains(PLAINTEXT_PASSWORD),
        "tracing must not contain plaintext password (success path): {dump}"
    );
    assert!(
        dump.contains(ATTR_AUTH_METHOD) && dump.contains("password"),
        "expected auth.method label in trace: {dump}"
    );
    assert!(
        dump.contains(ATTR_USER_ID) && dump.contains(&user_id.to_string()),
        "expected user.id in trace: {dump}"
    );
}

#[cfg(feature = "totp")]
#[test]
fn totp_method_is_totp() {
    assert_eq!(TotpAuth.method(), AuthMethod::Totp);
}

#[cfg(feature = "totp")]
#[tokio::test]
async fn totp_rejects_password_credentials() {
    let user_id = Uuid::new_v4();
    let hash =
        PasswordAuth::hash_password(&PlaintextPassword::new("totp-cross-test")).expect("hash");
    let creds = Credentials::Password {
        user_id,
        password: PlaintextPassword::new("totp-cross-test"),
        hash,
    };
    assert_eq!(
        TotpAuth.verify(creds).await.expect_err("wrong variant"),
        AuthError::InvalidCredentials
    );
}

#[cfg(feature = "totp")]
#[tokio::test]
async fn totp_rejects_wrong_code() {
    let user_id = Uuid::new_v4();
    let raw = [0x3Cu8; 20];
    let secret = TotpSecret::from_bytes(raw.to_vec()).expect("secret");
    let creds = Credentials::Totp { user_id, code: "000000".to_string(), secret };
    assert_eq!(TotpAuth.verify(creds).await.expect_err("bad code"), AuthError::InvalidMfaCode);
}

#[cfg(all(feature = "totp", feature = "passkey"))]
#[tokio::test]
async fn totp_rejects_passkey_credentials() {
    let creds = Credentials::Passkey { user_id: Uuid::nil() };
    assert_eq!(
        TotpAuth.verify(creds).await.expect_err("wrong variant"),
        AuthError::InvalidCredentials
    );
}

#[cfg(feature = "totp")]
#[tokio::test]
async fn totp_verify_never_records_secret_or_code_in_tracing() {
    let captured = Captured::default();
    let subscriber = Registry::default().with(AllFieldsLayer(captured.clone()));
    let _guard = tracing::subscriber::set_default(subscriber);

    let user_id = Uuid::new_v4();
    let raw = [0x5Au8; 20];
    let secret = TotpSecret::from_bytes(raw.to_vec()).expect("secret length");
    let device = TOTP::new(Algorithm::SHA1, 6, 1, 30, raw.to_vec()).expect("totp");
    let code = device.generate_current().expect("code");

    assert!(!code.is_empty(), "generated TOTP code must be non-empty for this test");

    let creds = Credentials::Totp { user_id, code: code.clone(), secret };
    TotpAuth.verify(creds).await.expect("totp ok");

    let dump = captured_dump(&captured);
    assert!(!dump.contains(&code), "TOTP code must not appear in tracing output: {dump}");
    let secret_b32 = device.get_secret_base32();
    assert!(!dump.contains(&secret_b32), "TOTP secret (base32) must not appear in tracing: {dump}");
}

#[cfg(feature = "passkey")]
#[test]
fn passkey_auth_method_label_is_stable() {
    assert_eq!(AuthMethod::Passkey.as_label(), "passkey");
}

#[cfg(feature = "passkey")]
#[test]
fn passkey_method_and_rp_accessors() {
    let auth = PasskeyAuth::new("login.example.com", "Example App").expect("new");
    assert_eq!(auth.method(), AuthMethod::Passkey);
    assert_eq!(auth.rp_id(), "login.example.com");
    assert_eq!(auth.rp_name(), "Example App");
}

#[cfg(feature = "passkey")]
#[test]
fn passkey_new_rejects_empty_rp_id_or_name() {
    assert_eq!(PasskeyAuth::new("", "Name").expect_err("empty rp_id"), AuthError::Internal);
    assert_eq!(PasskeyAuth::new("id.example", "").expect_err("empty rp_name"), AuthError::Internal);
}

#[cfg(feature = "passkey")]
#[tokio::test]
async fn passkey_rejects_password_credentials() {
    let auth = PasskeyAuth::new("a.example", "A").expect("new");
    let user_id = Uuid::new_v4();
    let hash = PasswordAuth::hash_password(&PlaintextPassword::new("pk-cross")).expect("hash");
    let creds =
        Credentials::Password { user_id, password: PlaintextPassword::new("pk-cross"), hash };
    assert_eq!(auth.verify(creds).await.expect_err("wrong variant"), AuthError::InvalidCredentials);
}

#[cfg(all(feature = "totp", feature = "passkey"))]
#[tokio::test]
async fn passkey_rejects_totp_credentials() {
    let auth = PasskeyAuth::new("a.example", "A").expect("new");
    let raw = [7u8; 20];
    let secret = TotpSecret::from_bytes(raw.to_vec()).expect("secret");
    let creds = Credentials::Totp { user_id: Uuid::nil(), code: "123456".to_string(), secret };
    assert_eq!(auth.verify(creds).await.expect_err("wrong variant"), AuthError::InvalidCredentials);
}

#[cfg(feature = "passkey")]
#[tokio::test]
async fn passkey_verify_is_instrumented_without_extra_panic() {
    let captured = Captured::default();
    let subscriber = Registry::default().with(AllFieldsLayer(captured.clone()));
    let _guard = tracing::subscriber::set_default(subscriber);

    let auth = PasskeyAuth::new("example.com", "Example").expect("passkey new");
    let user_id = Uuid::new_v4();
    let creds = Credentials::Passkey { user_id };
    let err = auth.verify(creds).await.expect_err("stub verify fails");
    assert_eq!(err, AuthError::PasskeyVerificationFailed);
    let dump = captured_dump(&captured);
    assert!(
        dump.contains("passkey") || dump.contains("PasskeyAuth"),
        "expected passkey-related trace: {dump}"
    );
}

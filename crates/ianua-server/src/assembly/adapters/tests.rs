use std::time::Duration;

use ianua_app::ports::authentication::TextAvailability;
use ianua_boot::env::Env;
use ianua_boot::shutdown::Shutdown;
use ianua_domain::domains::identity::account::address::MailReach;
use ianua_infra::test_support::{
    APP_ROLE, APP_ROLE_PASSWORD, AUDIT_PURGE_ROLE, AUDIT_PURGE_ROLE_PASSWORD, TestDb,
};

use super::*;
use crate::command::Command;

const HEX_1: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const HEX_2: &str = "0000000000000000000000000000000000000000000000000000000000000002";
const HEX_3: &str = "0000000000000000000000000000000000000000000000000000000000000003";

/// A single node running everything over `db`, with `extra` settings.
fn config(db: &TestDb, files: &std::path::Path, extra: &[(&str, &str)]) -> Config {
    let app = db.address(APP_ROLE, APP_ROLE_PASSWORD);
    let owner = db.address("postgres", "postgres");
    let purge = db.address(AUDIT_PURGE_ROLE, AUDIT_PURGE_ROLE_PASSWORD);
    let files = files.display().to_string();
    let mut pairs = vec![
        ("APP_ENV", "development"),
        ("AUDIT_REQUIRE_SEALED", "false"),
        ("APP_BASE_URL", "https://app.example.com"),
        ("PROXY_BASE_DOMAIN", "apps.example.com"),
        ("DATABASE_URL", app.as_str()),
        ("MIGRATION_DATABASE_URL", owner.as_str()),
        ("AUDIT_PURGE_DATABASE_URL", purge.as_str()),
        ("HMAC_SECRET", HEX_1),
        ("EVENT_SIGNING_SECRET", HEX_2),
        ("ENCRYPTION_KEY", HEX_3),
        ("EMAIL_FROM", "noreply@example.com"),
        ("SMTP_HOST", "smtp.example.com"),
        ("WEBAUTHN_RP_ID", "example.com"),
        ("WEBAUTHN_RP_ORIGIN", "https://app.example.com"),
        ("FILES_DIR", files.as_str()),
    ];
    pairs.extend_from_slice(extra);
    Config::read(&Env::of(pairs), &Command::Serve).unwrap()
}

/// The platform `config` describes, over its database.
async fn platform(config: &Config) -> Platform {
    let shutdown = Shutdown::new(Duration::from_secs(1));
    Platform::build(config, &shutdown).await.unwrap()
}

/// A single node's API is built over the real database: every port has
/// its adapter, the settings read, and with nothing optional set up, the
/// platform's own puzzle as the challenge and texted codes refused. The
/// SMTP server it names lets mail reach people.
#[tokio::test]
async fn single_node_adapters_use_safe_defaults() {
    let db = TestDb::fresh().await;
    let files = tempfile::tempdir().unwrap();
    let config = config(&db, files.path(), &[]);
    let platform = platform(&config).await;

    let deps = crate::assembly::assembly(&platform, &config).unwrap();

    assert!(deps.adapters.challenge_verifier.is_some());
    assert!(deps.adapters.challenge_issuer.is_some());
    assert_eq!(
        deps.adapters.text_messaging.availability(),
        TextAvailability::NotSetUp
    );
    assert_eq!(deps.adapters.mail_setup.reach(), MailReach::Available);
}

/// With Turnstile and Twilio set up, a flooded sign-in asks for Turnstile
/// and the platform sets no puzzle of its own, and texted codes are
/// offered.
#[tokio::test]
async fn builds_configured_optional_providers() {
    let db = TestDb::fresh().await;
    let files = tempfile::tempdir().unwrap();
    let config = config(
        &db,
        files.path(),
        &[
            ("TURNSTILE_SECRET_KEY", "turnstile-secret"),
            ("TURNSTILE_HOSTNAMES", "app.example.com"),
            ("TWILIO_ACCOUNT_SID", "AC0123456789abcdef0123456789abcdef"),
            ("TWILIO_AUTH_TOKEN", "tw-token"),
            ("TWILIO_FROM", "+15005550006"),
            ("STRIPE_SECRET_KEY", "sk_test_1"),
            ("STRIPE_WEBHOOK_SECRET", "whsec_1"),
        ],
    );
    let platform = platform(&config).await;

    let deps = crate::assembly::assembly(&platform, &config).unwrap();

    assert!(deps.adapters.challenge_verifier.is_some());
    assert!(deps.adapters.challenge_issuer.is_none());
    assert_eq!(
        deps.adapters.text_messaging.availability(),
        TextAvailability::Available
    );
}

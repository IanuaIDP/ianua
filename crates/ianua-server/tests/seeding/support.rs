//! A whole platform over a test database of its own, built as the one-off
//! commands build it: the configuration read from settings, the platform
//! brought up on it, and the adapters the API and the seeders share.
//!
//! The breach check asks a local stand-in of the Pwned Passwords range
//! service, named through `PASSWORD_BREACH_URL`, so no test needs the
//! internet, and none fails or slows when the real service does.

use std::path::Path;

use ianua_api::state::Deps;
use ianua_boot::env::Env;
use ianua_boot::shutdown::Shutdown;
use ianua_infra::test_support::{
    APP_ROLE, APP_ROLE_PASSWORD, AUDIT_PURGE_ROLE, AUDIT_PURGE_ROLE_PASSWORD, TestDb,
};
use ianua_server::api;
use ianua_server::command::Command;
use ianua_server::config::Config;
use ianua_server::platform::Platform;
use sqlx::PgPool;
use tempfile::TempDir;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// What the stand-in answers for every hash prefix: one padding line, as
/// the real service pads, so every password reads as in no breach.
const NO_BREACH: &str = "0000000000000000000000000000000000A:0\r\n";

/// The settings every test platform runs with, beside its database's.
const SETTINGS: [(&str, &str); 13] = [
    ("APP_ENV", "development"),
    ("APP_BASE_URL", "https://app.example.com"),
    ("PROXY_BASE_DOMAIN", "apps.example.com"),
    (
        "HMAC_SECRET",
        "0000000000000000000000000000000000000000000000000000000000000001",
    ),
    (
        "EVENT_SIGNING_SECRET",
        "0000000000000000000000000000000000000000000000000000000000000002",
    ),
    (
        "ENCRYPTION_KEY",
        "0000000000000000000000000000000000000000000000000000000000000003",
    ),
    ("ARGON2_MEMORY_KIB", "8192"),
    ("ARGON2_ITERATIONS", "1"),
    ("ARGON2_LANES", "1"),
    ("EMAIL_FROM", "noreply@example.com"),
    ("SMTP_HOST", "smtp.example.com"),
    ("WEBAUTHN_RP_ID", "example.com"),
    ("WEBAUTHN_RP_ORIGIN", "https://app.example.com"),
];

/// A platform built for one command over a database of its own.
pub(crate) struct Server {
    /// The adapters the API and the seeders share.
    pub(crate) deps: Deps,
    /// The settings it was built with.
    pub(crate) config: Config,
    owner: PgPool,
    _platform: Platform,
    _shutdown: Shutdown,
    _files: TempDir,
    _breaches: MockServer,
    _db: TestDb,
}

impl Server {
    /// The platform `command` runs on, with `extra` settings beside the
    /// ones every test platform has.
    pub(crate) async fn start(command: &Command, extra: &[(&str, &str)]) -> Self {
        let db = TestDb::fresh().await;
        let files = TempDir::new().expect("a directory for the files");
        let breaches = breach_stand_in().await;
        let vars = environment(
            &Places {
                db: &db,
                files: files.path(),
                breaches: &breaches.uri(),
            },
            extra,
        );
        let config = Config::read(&vars, command).expect("the test settings are accepted");
        let shutdown = Shutdown::new(config.http.shutdown_grace);
        let platform = Platform::build(&config, &shutdown)
            .await
            .expect("the platform is built on the test database");
        let deps = api::deps(&platform, &config).expect("the adapters are built");
        let owner = owner_connection(&db).await;
        Self {
            deps,
            config,
            owner,
            _platform: platform,
            _shutdown: shutdown,
            _files: files,
            _breaches: breaches,
            _db: db,
        }
    }

    /// How many rows `table` holds, past row-level security.
    pub(crate) async fn rows(&self, table: &str) -> i64 {
        sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(&self.owner)
            .await
            .expect("the table is counted")
    }

    /// How many audit records of `event_type` the trail holds, the
    /// tenants' and the platform's together.
    pub(crate) async fn recorded(&self, event_type: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM audit_records WHERE event_type = $1) \
                  + (SELECT count(*) FROM platform_audit_records WHERE event_type = $1)",
        )
        .bind(event_type)
        .fetch_one(&self.owner)
        .await
        .expect("the trail is counted")
    }

    /// How many audit records the trail holds in all.
    pub(crate) async fn trail(&self) -> i64 {
        sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM audit_records) \
                  + (SELECT count(*) FROM platform_audit_records)",
        )
        .fetch_one(&self.owner)
        .await
        .expect("the trail is counted")
    }
}

/// Opens an owner connection so assertions count records across row-level security scopes.
async fn owner_connection(db: &TestDb) -> PgPool {
    PgPool::connect_with(db.owner_options())
        .await
        .expect("the test database answers its owner")
}

/// Where a test platform keeps what is its own.
struct Places<'a> {
    /// Its database.
    db: &'a TestDb,
    /// The directory its files go in.
    files: &'a Path,
    /// The address of its breach service stand-in.
    breaches: &'a str,
}

/// A stand-in for the Pwned Passwords range service that knows no breach.
async fn breach_stand_in() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/range/[0-9A-F]{5}$"))
        .respond_with(ResponseTemplate::new(200).set_body_string(NO_BREACH))
        .mount(&server)
        .await;
    server
}

/// The settings of a platform kept in `places`.
fn environment(places: &Places<'_>, extra: &[(&str, &str)]) -> Env {
    let db = places.db;
    let logins = [
        ("DATABASE_URL", db.address(APP_ROLE, APP_ROLE_PASSWORD)),
        ("MIGRATION_DATABASE_URL", db.address("postgres", "postgres")),
        (
            "AUDIT_PURGE_DATABASE_URL",
            db.address(AUDIT_PURGE_ROLE, AUDIT_PURGE_ROLE_PASSWORD),
        ),
        ("FILES_DIR", places.files.display().to_string()),
        ("PASSWORD_BREACH_URL", places.breaches.to_owned()),
    ];
    let pairs = SETTINGS
        .iter()
        .copied()
        .chain(logins.iter().map(|(name, value)| (*name, value.as_str())))
        .chain(extra.iter().copied());
    Env::of(pairs)
}

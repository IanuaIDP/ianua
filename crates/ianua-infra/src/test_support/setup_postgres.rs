//! Nextest setup script: one shared Postgres for the whole test run.
//!
//! Nextest runs each test in its own process, so a container per process
//! would boot a Postgres and replay every migration per test. This keeps one
//! container, with a migrated template database and the roles of the app,
//! the audit purge, the gateway and the nameservers, and writes
//! `IANUA_TEST_PG_PORT` to the file
//! `$NEXTEST_ENV` names. Each test clones its own database from the
//! template (`TestDb`).
//!
//! The container is kept between runs while the migrations and the roles'
//! grants stay as they are: the template carries a fingerprint of every
//! migration file and of the roles' file, written
//! once it is complete, and a run whose migrations give another fingerprint,
//! or that finds no complete template, starts the container afresh. So a
//! test never runs against an old schema, and an unchanged schema is never
//! migrated twice. The databases a run's tests leave behind are dropped by
//! the next run once they have no connections. Cleanup holds the same
//! lock as cloning and never forces another run's connections closed.
//!
//! The container is named after the CI runner when there is one: runners
//! share one container daemon, and a fixed name would let one job remove
//! another's database mid-run. It is started with `--rm`, and one replaced
//! is removed with its volumes, or every run leaves gigabytes behind.

// This nextest setup binary must fail the run if its migrated database or environment file is unavailable.
#![allow(clippy::expect_used)]

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;

use ianua_infra::postgres::{
    Databases, LoginRole, PlatformRoles, PoolLimits, ensure_roles, migrate_platform,
};
use ianua_infra::test_support::cleanup::discard_unused_databases;
use ianua_infra::test_support::{
    APP_ROLE, APP_ROLE_PASSWORD, AUDIT_PURGE_ROLE, AUDIT_PURGE_ROLE_PASSWORD, GATEWAY_ROLE,
    GATEWAY_ROLE_PASSWORD, NAMESERVER_ROLE, NAMESERVER_ROLE_PASSWORD, TEMPLATE_DATABASE,
};
use sqlx::PgPool;
use sqlx::postgres::PgConnectOptions;

const CONTAINER_BASE: &str = "ianua-test-postgres";

/// Reuses or creates the shared server, reclaims abandoned databases and
/// publishes its port without disturbing databases another run still uses.
#[tokio::main]
async fn main() {
    let name = container_name();
    let fingerprint = migrations_fingerprint();
    let port = match reusable_port(&name, &fingerprint).await {
        Some(port) => {
            discard_unused_databases(&port.to_string()).await;
            port
        }
        None => {
            let port = start_container(&name);
            wait_until_ready(port).await;
            build_template(port, &fingerprint).await;
            port
        }
    };
    publish_port(port);
}

/// The container's name, with the CI runner's name when there is one.
fn container_name() -> String {
    match std::env::var("RUNNER_NAME") {
        Ok(runner) if !runner.trim().is_empty() => format!("{CONTAINER_BASE}-{}", runner.trim()),
        _ => CONTAINER_BASE.to_owned(),
    }
}

/// A fingerprint of every migration file, its name and its text, in order,
/// and of the file that makes the roles and their grants, which the
/// template carries too.
fn migrations_fingerprint() -> String {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files: Vec<_> = std::fs::read_dir(crate_dir.join("migrations"))
        .expect("the migrations folder is readable")
        .flatten()
        .map(|entry| entry.path())
        .collect();
    files.sort();
    files.push(crate_dir.join("src/postgres/foundation/roles.rs"));
    let mut hasher = DefaultHasher::new();
    for file in files {
        file.file_name().hash(&mut hasher);
        std::fs::read(&file)
            .expect("a migration is readable")
            .hash(&mut hasher);
    }
    format!("{:016x}", hasher.finish())
}

/// The port of the running container `name`, when its template is complete
/// for the migrations `fingerprint` describes.
async fn reusable_port(name: &str, fingerprint: &str) -> Option<u16> {
    let running = Command::new("docker")
        .args(["inspect", "-f", "{{.State.Running}}", name])
        .output()
        .ok()?;
    if String::from_utf8_lossy(&running.stdout).trim() != "true" {
        return None;
    }
    let port = mapped_port(name);
    let admin = PgPool::connect(&admin_url(port, "postgres")).await.ok()?;
    let stamped: Option<String> = sqlx::query_scalar(
        "SELECT shobj_description(oid, 'pg_database') FROM pg_database WHERE datname = $1",
    )
    .bind(TEMPLATE_DATABASE)
    .fetch_optional(&admin)
    .await
    .ok()
    .flatten();
    admin.close().await;
    (stamped.as_deref() == Some(fingerprint)).then_some(port)
}

/// Starts a clean shared server when no compatible template can be reused.
fn start_container(name: &str) -> u16 {
    let _left_over = Command::new("docker")
        .args(["rm", "-f", "-v", name])
        .output();
    let status = container_command(name)
        .status()
        .expect("`docker run` starts");
    assert!(status.success(), "`docker run` failed for {name}");
    mapped_port(name)
}

/// Configures the shared PostgreSQL process for concurrent, disposable test databases.
fn container_command(name: &str) -> Command {
    let mut command = Command::new("docker");
    command.args([
        "run",
        "-d",
        "--rm",
        "--name",
        name,
        "--label",
        "ianua-test=1",
        "-p",
        "127.0.0.1::5432",
        "-e",
        "POSTGRES_USER=postgres",
        "-e",
        "POSTGRES_PASSWORD=postgres",
        "pgvector/pgvector:pg16",
        "postgres",
        "-c",
        "max_connections=2000",
        "-c",
        "fsync=off",
        "-c",
        "synchronous_commit=off",
        "-c",
        "full_page_writes=off",
    ]);
    command
}

/// Reads the host port Docker assigned to the shared PostgreSQL listener.
fn mapped_port(name: &str) -> u16 {
    let output = Command::new("docker")
        .args(["port", name, "5432/tcp"])
        .output()
        .expect("`docker port` runs");
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .next()
        .and_then(|line| line.rsplit(':').next())
        .and_then(|port| port.trim().parse().ok())
        .unwrap_or_else(|| panic!("no host port for {name} in {text:?}"))
}

/// Bounds startup polling until PostgreSQL accepts an administrator connection.
async fn wait_until_ready(port: u16) {
    for _ in 0..60 {
        if PgPool::connect(&admin_url(port, "postgres")).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("postgres did not become ready on port {port}");
}

/// Makes the template: migrated, with the roles of the app, the audit
/// purge and the gateway, and stamped with
/// `fingerprint` last, so a template stamped is a template complete.
async fn build_template(port: u16, fingerprint: &str) {
    let admin = PgPool::connect(&admin_url(port, "postgres"))
        .await
        .expect("the admin database answers");
    sqlx::raw_sql(&format!("CREATE DATABASE {TEMPLATE_DATABASE}"))
        .execute(&admin)
        .await
        .expect("the template database is made");
    let _databases = prepare_template(port).await;
    sqlx::raw_sql(&format!(
        "COMMENT ON DATABASE {TEMPLATE_DATABASE} IS '{fingerprint}'"
    ))
    .execute(&admin)
    .await
    .expect("the template is stamped");
    admin.close().await;
}

/// Migrates the template and installs every restricted role before it can be stamped.
async fn prepare_template(port: u16) -> Databases {
    let options = PgConnectOptions::from_str(&admin_url(port, TEMPLATE_DATABASE))
        .expect("the template's address reads");
    let limits = PoolLimits {
        platform_connections: 2,
        dedicated_connections: 1,
        acquire_timeout: Duration::from_secs(10),
    };
    let databases = Databases::new(options, limits);
    migrate_platform(&databases)
        .await
        .expect("the template is migrated");
    let owner = PgPool::connect(&admin_url(port, TEMPLATE_DATABASE))
        .await
        .expect("the template answers");
    ensure_roles(&owner, &test_roles())
        .await
        .expect("the app's, the audit purge's, the gateway's and the nameservers' roles are made");
    owner.close().await;
    databases
}

/// The fixed credentials used by the app, purge, gateway and nameserver test pools.
fn test_roles() -> PlatformRoles<'static> {
    PlatformRoles {
        app: LoginRole {
            name: APP_ROLE,
            password: APP_ROLE_PASSWORD,
        },
        audit_purge: LoginRole {
            name: AUDIT_PURGE_ROLE,
            password: AUDIT_PURGE_ROLE_PASSWORD,
        },
        gateway: Some(LoginRole {
            name: GATEWAY_ROLE,
            password: GATEWAY_ROLE_PASSWORD,
        }),
        nameserver: Some(LoginRole {
            name: NAMESERVER_ROLE,
            password: NAMESERVER_ROLE_PASSWORD,
        }),
    }
}

/// Gives every nextest test the address of this run's shared database server.
fn publish_port(port: u16) {
    let path = std::env::var("NEXTEST_ENV").expect("this runs as a nextest setup script");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("the nextest environment file opens");
    writeln!(file, "IANUA_TEST_PG_PORT={port}").expect("the port is written");
}

/// The local test server's administrator connection to one database.
fn admin_url(port: u16, database: &str) -> String {
    format!("postgres://postgres:postgres@127.0.0.1:{port}/{database}")
}

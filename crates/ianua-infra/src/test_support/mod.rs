//! What the infra tests run on: one shared Postgres for the run, and a fresh
//! database per test cloned from a migrated template.
//!
//! A test connects as the app's own role, never as a superuser, so
//! row-level security confines it exactly as it confines a deployment. The
//! retention purge's tests connect as the audit purge's role, the only one
//! that may remove an audit record, the gateway's as the gateway's, and
//! the nameservers' as theirs.
//!
//! Each test's database is dropped when the test is done with it, so a run
//! of thousands of tests does not fill the container's disk and slow every
//! later clone. A database a test leaves behind by crashing is dropped by
//! the next run's setup.

pub mod bus;
pub mod cache;
pub mod cleanup;
pub mod objects;
pub(crate) mod plane;
pub mod rows;

use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

pub use ianua_domain::shared::clock;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgRow};
use sqlx::{FromRow, PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::postgres::tenant::TenantSchemaAccess;
use crate::postgres::{Databases, DedicatedDatabase, PoolLimits};

/// The database the migrations are applied to once, and every test's
/// database is cloned from.
pub const TEMPLATE_DATABASE: &str = "ianua_template";

/// The start of every test database's name.
pub const TEST_DATABASE_PREFIX: &str = "ianua_test_";

/// The ordinary role tests connect as.
pub const APP_ROLE: &str = "ianua_app";

/// The test role's password.
pub const APP_ROLE_PASSWORD: &str = "ianua_app";

/// The role the audit purge's tests connect as.
pub const AUDIT_PURGE_ROLE: &str = "ianua_audit_purge";

/// The audit purge's test role's password.
pub const AUDIT_PURGE_ROLE_PASSWORD: &str = "ianua_audit_purge";

/// The role the gateway's tests connect as.
pub const GATEWAY_ROLE: &str = "ianua_gateway";

/// The gateway's test role's password.
pub const GATEWAY_ROLE_PASSWORD: &str = "ianua_gateway";

/// The role the nameservers' tests connect as.
pub const NAMESERVER_ROLE: &str = "ianua_nameserver";

/// The nameservers' test role's password.
pub const NAMESERVER_ROLE_PASSWORD: &str = "ianua_nameserver";

/// The advisory lock every clone of the template is made under: Postgres
/// refuses to copy a database while another session is connected to it,
/// and the clones of every test process on the shared server would
/// otherwise race.
const CLONE_LOCK: i64 = 0x1a2b_3c4d;

/// A database of its own for one test, connected as the app's role, as the
/// audit purge's for the purge's tests, as the gateway's for the
/// gateway's, and as the nameservers' for theirs.
pub struct TestDb {
    /// The database's pools, as the stores reach it.
    pub databases: Arc<Databases>,
    /// The database's pools as the audit purge's role reaches it, with
    /// routes of their own.
    pub audit_purge: Arc<Databases>,
    /// The database's pools as the gateway's role reaches it, with routes
    /// of their own.
    pub gateway: Arc<Databases>,
    /// The database's pools as the nameservers' role reaches it.
    pub nameserver: Arc<Databases>,
    /// A connection as the owner, past every store and row-level security.
    owner: PgPool,
    /// How the app's role reaches this database.
    app: PgConnectOptions,
    /// The database's name, to drop it when the test is done.
    name: String,
    /// The shared server's port.
    port: String,
}

static NEXT: AtomicU32 = AtomicU32::new(0);

/// The restricted role used by each set of adapter test pools.
#[derive(Clone, Copy)]
enum TestRole {
    App,
    AuditPurge,
    Gateway,
    Nameserver,
}

/// Builds local connection options using the selected test role's fixed credentials.
fn role_options(port: &str, name: &str, role: TestRole) -> PgConnectOptions {
    let (user, password) = match role {
        TestRole::App => (APP_ROLE, APP_ROLE_PASSWORD),
        TestRole::AuditPurge => (AUDIT_PURGE_ROLE, AUDIT_PURGE_ROLE_PASSWORD),
        TestRole::Gateway => (GATEWAY_ROLE, GATEWAY_ROLE_PASSWORD),
        TestRole::Nameserver => (NAMESERVER_ROLE, NAMESERVER_ROLE_PASSWORD),
    };
    PgConnectOptions::from_str(&url(port, user, password, name))
        .expect("the test database's address reads")
}

impl TestDb {
    /// A fresh database cloned from the migrated template.
    ///
    /// # Panics
    ///
    /// When the shared Postgres is not running: run the tests with
    /// `cargo nextest run`, whose setup script starts it.
    pub async fn fresh() -> Self {
        let port = std::env::var("IANUA_TEST_PG_PORT").expect(
            "IANUA_TEST_PG_PORT is set by the nextest setup script; run with cargo nextest",
        );
        let name = format!(
            "{TEST_DATABASE_PREFIX}{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let owner = clone_template(&port, &name).await;
        let app = role_options(&port, &name, TestRole::App);
        let purge = role_options(&port, &name, TestRole::AuditPurge);
        let gateway = role_options(&port, &name, TestRole::Gateway);
        let nameserver = role_options(&port, &name, TestRole::Nameserver);
        Self {
            databases: Arc::new(Databases::new(app.clone(), limits())),
            audit_purge: Arc::new(Databases::audit_purge(purge, limits())),
            gateway: Arc::new(Databases::gateway(gateway, limits())),
            nameserver: Arc::new(Databases::nameserver(nameserver, limits())),
            owner,
            app,
            name,
            port,
        }
    }

    /// This database as the own database of a tenant registered in another
    /// test database, for tests of where a tenant's rows land.
    ///
    /// # Panics
    ///
    /// Never: the database has no schema to pin.
    #[must_use]
    pub fn as_dedicated(&self) -> DedicatedDatabase {
        DedicatedDatabase::new(self.app.clone(), None).expect("a database with no schema to pin")
    }

    /// The same database as another node of the platform reaches it: its
    /// own pools and its own routes, which start knowing of no tenant's
    /// own database.
    #[must_use]
    pub fn another_node(&self) -> Arc<Databases> {
        Arc::new(Databases::new(self.app.clone(), limits()))
    }

    /// How the database's owner reaches it, for a test of what only the
    /// owner does, such as making a tenant's schema.
    ///
    /// # Panics
    ///
    /// Never: the address is made here and reads.
    #[must_use]
    pub fn owner_options(&self) -> PgConnectOptions {
        PgConnectOptions::from_str(&url(&self.port, "postgres", "postgres", &self.name))
            .expect("the test database's owner address reads")
    }

    /// The `postgres://` address of this database as `user` signing in with
    /// `password`, for a test that configures a whole server against it.
    #[must_use]
    pub fn address(&self, user: &str, password: &str) -> String {
        url(&self.port, user, password, &self.name)
    }

    /// How tenant schemas are made in this database: by its owner, opened
    /// to the test roles of the app, the audit purge and the gateway.
    #[must_use]
    pub fn schema_access(&self) -> TenantSchemaAccess {
        TenantSchemaAccess {
            owner: self.owner_options(),
            app_role: APP_ROLE.to_owned(),
            audit_purge_role: AUDIT_PURGE_ROLE.to_owned(),
            gateway_role: Some(GATEWAY_ROLE.to_owned()),
        }
    }

    /// Runs `sql` as the database's owner, past every store and row-level
    /// security: for a test that makes a row no store would write, such as
    /// a corrupt one, or a table of its own to test the foundation on.
    ///
    /// # Panics
    ///
    /// When the statement fails, which is a mistake in the test.
    pub async fn tamper(&self, sql: &str) {
        sqlx::raw_sql(sql)
            .execute(&self.owner)
            .await
            .expect("the tampering statement runs");
    }

    /// Holds the row selected by `sql` and its bound id in a transaction,
    /// letting a test exercise competing workers without changing stored data.
    /// The statement must select the row with `FOR UPDATE`.
    ///
    /// # Panics
    ///
    /// When the database cannot begin the transaction or the row is absent.
    pub async fn lock_row(&self, sql: &str, id: &Uuid) -> Transaction<'static, Postgres> {
        let mut held = self
            .owner
            .begin()
            .await
            .expect("the lock transaction begins");
        sqlx::query(sql)
            .bind(id)
            .fetch_one(&mut *held)
            .await
            .expect("the selected row is locked");
        held
    }

    /// The rows `sql` reads as the database's owner, past every store and
    /// row-level security: for a test of a store that writes a table no
    /// store reads back, such as the records only the gateway writes.
    ///
    /// # Panics
    ///
    /// When the query fails, which is a mistake in the test.
    pub async fn read_back<T>(&self, sql: &str) -> Vec<T>
    where
        T: for<'r> FromRow<'r, PgRow> + Send + Unpin,
    {
        sqlx::query_as(sql)
            .fetch_all(&self.owner)
            .await
            .expect("the read-back query runs")
    }

    /// How Postgres would run `sql` for any values of its parameters, as a
    /// JSON plan, with scans of whole tables made a last resort: a plan
    /// that still scans one has no index it can use.
    ///
    /// # Panics
    ///
    /// When Postgres cannot plan `sql`, which is a broken query.
    pub async fn plan(&self, sql: &str) -> serde_json::Value {
        let mut connection = self
            .owner
            .acquire()
            .await
            .expect("the test database answers");
        sqlx::raw_sql("SET enable_seqscan = off")
            .execute(&mut *connection)
            .await
            .expect("whole-table scans are made a last resort");
        let explain = format!("EXPLAIN (GENERIC_PLAN, FORMAT JSON) {sql}");
        sqlx::raw_sql(&explain)
            .fetch_one(&mut *connection)
            .await
            .and_then(|row| row.try_get(0))
            .expect("Postgres plans the query")
    }
}

impl Drop for TestDb {
    /// Drops the test's database. `Drop` cannot wait on the test's own
    /// runtime, so the drop runs to its end on a thread of its own; the
    /// connections the test still holds are closed by `WITH (FORCE)`.
    fn drop(&mut self) {
        let admin = url(&self.port, "postgres", "postgres", "postgres");
        let statement = format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.name);
        let dropped = std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            runtime.block_on(async move {
                let Ok(admin) = PgPool::connect(&admin).await else {
                    return;
                };
                let _ = sqlx::raw_sql(&statement).execute(&admin).await;
                admin.close().await;
            });
        });
        let _ = dropped.join();
    }
}

/// How a test's pools are sized: small, as thousands of tests share one
/// server.
fn limits() -> PoolLimits {
    PoolLimits {
        platform_connections: 4,
        dedicated_connections: 2,
        acquire_timeout: Duration::from_secs(10),
    }
}

/// Copies the template and opens its owner while holding the clone lock.
/// Keeping one owner connection alive prevents another run's cleanup from
/// mistaking this database for an abandoned one, even between requests.
async fn clone_template(port: &str, name: &str) -> PgPool {
    let admin = PgPool::connect(&url(port, "postgres", "postgres", "postgres"))
        .await
        .expect("the shared Postgres answers");
    let mut connection = admin.acquire().await.expect("the shared Postgres answers");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(CLONE_LOCK)
        .execute(&mut *connection)
        .await
        .expect("the clone lock is taken");
    let cloned = sqlx::raw_sql(&format!(
        "CREATE DATABASE {name} TEMPLATE {TEMPLATE_DATABASE}"
    ))
    .execute(&mut *connection)
    .await;
    cloned.expect("the test database is cloned");
    let owner = owner_pool(port, name).await;
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(CLONE_LOCK)
        .execute(&mut *connection)
        .await
        .expect("the clone lock is released");
    drop(connection);
    admin.close().await;
    owner
}

/// Keeps one owner connection alive so cleanup recognizes the test database as in use.
async fn owner_pool(port: &str, name: &str) -> PgPool {
    PgPoolOptions::new()
        .min_connections(1)
        .max_lifetime(None)
        .idle_timeout(None)
        .connect(&url(port, "postgres", "postgres", name))
        .await
        .expect("the test database answers its owner")
}

/// The local test database as one of the deliberately fixed test roles.
fn url(port: &str, user: &str, password: &str, database: &str) -> String {
    format!("postgres://{user}:{password}@127.0.0.1:{port}/{database}")
}

#[cfg(test)]
pub(crate) mod certificates;

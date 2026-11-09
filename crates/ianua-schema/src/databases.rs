//! Throwaway databases: one is made for each folder of SQL, built by the
//! same migrator the platform starts with, read back, and dropped.
//!
//! They are made on the server `SCHEMA_DATABASE_URL` names, which the tool
//! may create and drop databases on. Without it, the tool starts a Postgres
//! container of its own, the image the tests use, and keeps it for the next
//! run.

use std::borrow::Cow;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use sqlx::migrate::Migrator;
use sqlx::{Connection as _, PgConnection, PgPool};

use crate::catalog::{self, Catalog};

/// The setting naming the server the tool makes its databases on.
const SERVER_SETTING: &str = "SCHEMA_DATABASE_URL";

/// The container the tool starts when no server is named.
const CONTAINER: &str = "ianua-schema-postgres";

/// The image that container runs: Postgres with pgvector, as in the tests.
const IMAGE: &str = "pgvector/pgvector:pg16";

/// The start of a migration's description that keeps it out of a tenant's
/// own database.
const PLATFORM_ONLY: &str = "platform";

/// How many databases this run has made, for their names.
static MADE: AtomicU32 = AtomicU32::new(0);

/// Which database a folder is built as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    /// The platform database: every file.
    Platform,
    /// A tenant's own database: no platform file.
    Tenant,
}

impl Scope {
    /// Both, the platform first.
    pub(crate) const BOTH: [Self; 2] = [Self::Platform, Self::Tenant];

    /// What the scope is called in a report.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Platform => "platform database",
            Self::Tenant => "a tenant's own database",
        }
    }
}

/// Why a database could not be built or read.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BuildError {
    /// The server did not answer, or refused a statement.
    #[error("the database server refused: {0}")]
    Server(#[from] sqlx::Error),
    /// A folder's files could not be read or applied.
    #[error("the SQL files could not be applied: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// No server was named and no container could be started.
    #[error("no database server: set {SERVER_SETTING}, or let the tool start Docker ({0})")]
    NoServer(String),
}

/// The server the tool makes its databases on.
pub(crate) struct Server {
    admin_url: String,
}

impl Server {
    /// The server `SCHEMA_DATABASE_URL` names, or the tool's own container.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::NoServer`] when neither can be reached.
    pub(crate) async fn reach() -> Result<Self, BuildError> {
        let admin_url = match std::env::var(SERVER_SETTING) {
            Ok(url) => url,
            Err(_) => container_url()?,
        };
        wait_until_ready(&admin_url).await?;
        Ok(Self { admin_url })
    }

    /// What `folder` builds as `scope`, read from a database made for it
    /// and dropped after.
    ///
    /// # Errors
    ///
    /// Returns the server's or the migrator's error.
    pub(crate) async fn built(&self, folder: &Path, scope: Scope) -> Result<Catalog, BuildError> {
        let name = format!(
            "ianua_schema_{}_{}",
            std::process::id(),
            MADE.fetch_add(1, Ordering::Relaxed)
        );
        self.execute(&format!("CREATE DATABASE {name}")).await?;
        let read = self.read_built(&name, folder, scope).await;
        self.execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
            .await?;
        read
    }

    /// Applies `folder` to the database `name` and reads its catalog.
    async fn read_built(
        &self,
        name: &str,
        folder: &Path,
        scope: Scope,
    ) -> Result<Catalog, BuildError> {
        let pool = PgPool::connect(&database_url(&self.admin_url, name)).await?;
        let migrator = migrator_for(folder, scope).await?;
        let applied = migrator.run(&pool).await;
        let read = match applied {
            Ok(()) => catalog::read(&pool).await.map_err(BuildError::from),
            Err(error) => Err(BuildError::from(error)),
        };
        pool.close().await;
        read
    }

    /// Runs `statement` on the server's own database.
    async fn execute(&self, statement: &str) -> Result<(), BuildError> {
        let mut connection = PgConnection::connect(&self.admin_url).await?;
        sqlx::raw_sql(statement).execute(&mut connection).await?;
        connection.close().await?;
        Ok(())
    }
}

/// The migrator of `folder`'s files, a tenant's leaving platform files out.
async fn migrator_for(folder: &Path, scope: Scope) -> Result<Migrator, BuildError> {
    let every = Migrator::new(folder).await?;
    if scope == Scope::Platform {
        return Ok(every);
    }
    let migrations = every
        .iter()
        .filter(|migration| !migration.description.starts_with(PLATFORM_ONLY))
        .cloned()
        .collect();
    Ok(Migrator {
        migrations: Cow::Owned(migrations),
        ..Migrator::DEFAULT
    })
}

/// The address of the database `name` on the server `admin_url` reaches.
fn database_url(admin_url: &str, name: &str) -> String {
    let (server, rest) = admin_url.rsplit_once('/').unwrap_or((admin_url, ""));
    let options = rest.split_once('?').map_or("", |(_, options)| options);
    if options.is_empty() {
        return format!("{server}/{name}");
    }
    format!("{server}/{name}?{options}")
}

/// Waits a bounded time for the server to take a connection.
async fn wait_until_ready(admin_url: &str) -> Result<(), BuildError> {
    for _ in 0..60 {
        if PgConnection::connect(admin_url).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(BuildError::NoServer(format!(
        "{admin_url} did not take a connection within 30 seconds"
    )))
}

/// The address of the tool's own container, started when it is not
/// running.
fn container_url() -> Result<String, BuildError> {
    let port = running_port().map_or_else(start_container, Ok)?;
    Ok(format!(
        "postgres://postgres:postgres@127.0.0.1:{port}/postgres"
    ))
}

/// The host port of the tool's container, when it is running.
fn running_port() -> Option<u16> {
    let running = Command::new("docker")
        .args(["inspect", "-f", "{{.State.Running}}", CONTAINER])
        .output()
        .ok()?;
    if String::from_utf8_lossy(&running.stdout).trim() != "true" {
        return None;
    }
    mapped_port()
}

/// Starts the tool's container and returns its host port.
fn start_container() -> Result<u16, BuildError> {
    let no_docker = |reason: &str| BuildError::NoServer(reason.to_owned());
    let _left_over = Command::new("docker")
        .args(["rm", "-f", "-v", CONTAINER])
        .output();
    let status = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            CONTAINER,
            "-p",
            "127.0.0.1::5432",
            "-e",
            "POSTGRES_USER=postgres",
            "-e",
            "POSTGRES_PASSWORD=postgres",
            IMAGE,
            "postgres",
            "-c",
            "fsync=off",
            "-c",
            "synchronous_commit=off",
        ])
        .status()
        .map_err(|error| no_docker(&error.to_string()))?;
    if !status.success() {
        return Err(no_docker("`docker run` failed"));
    }
    mapped_port().ok_or_else(|| no_docker("the container published no port"))
}

/// The host port Docker gave the container's Postgres.
fn mapped_port() -> Option<u16> {
    let output = Command::new("docker")
        .args(["port", CONTAINER, "5432/tcp"])
        .output()
        .ok()?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()?
        .rsplit(':')
        .next()?
        .trim()
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A database's address swaps the server's own database for it and
    /// keeps the connection's options.
    #[test]
    fn a_databases_address_keeps_the_servers_options() {
        let plain = database_url("postgres://u:p@host:5432/postgres", "made");
        let with_options =
            database_url("postgres://u:p@host:5432/postgres?sslmode=require", "made");

        assert_eq!(plain, "postgres://u:p@host:5432/made");
        assert_eq!(
            with_options,
            "postgres://u:p@host:5432/made?sslmode=require"
        );
    }
}

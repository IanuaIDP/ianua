//! The schema, brought up to date at start.
//!
//! The migrations are the files in `migrations/`, built into the binary and
//! applied in the order of their numbers. A new file is picked up on its
//! own; nothing lists them. Each is applied once and recorded, and one
//! already applied that has since changed stops the start, since the schema
//! would no longer be what the files say.
//!
//! The platform database holds every table. A tenant's own database holds
//! only the tables of a tenant's records, so a migration named
//! `NNNN_platform_*.sql`, for the platform's own tables such as
//! organizations and operators, is left out of it.

use std::borrow::Cow;

use ianua_domain::shared::errors::DomainError;
use sqlx::PgPool;
use sqlx::migrate::Migrator;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

static EVERY_TABLE: Migrator = sqlx::migrate!("./migrations");

/// The start of the name of a migration for the platform's own tables.
const PLATFORM_ONLY: &str = "platform";

/// Brings the platform database up to date, every table included.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a migration fails, or one
/// already applied no longer matches its file.
pub async fn migrate_platform(databases: &Databases) -> Result<(), DomainError> {
    EVERY_TABLE
        .run(databases.platform())
        .await
        .map_err(DomainError::infra)
}

/// Brings a tenant's own database, reached by `pool`, up to date: every
/// table of a tenant's records, and none of the platform's own.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a migration fails, or one
/// already applied no longer matches its file.
pub(crate) async fn migrate_dedicated(pool: &PgPool) -> Result<(), DomainError> {
    tenant_tables().run(pool).await.map_err(DomainError::infra)
}

/// Whether every migration this build carries has been applied to the
/// platform database `databases` reach, for a process that does not
/// migrate and waits until whoever does is done: on an upgrade the schema
/// is older than the code until the migration has run.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the database cannot be
/// reached, or holds no record of migrations yet.
pub async fn schema_is_current(databases: &Databases) -> Result<bool, DomainError> {
    let applied: Vec<i64> = scoped(databases, RowScope::Unscoped, async |connection| {
        sqlx::query_scalar::<_, i64>("SELECT version FROM public._sqlx_migrations WHERE success")
            .fetch_all(connection)
            .await
    })
    .await?;
    Ok(EVERY_TABLE
        .iter()
        .all(|migration| applied.contains(&migration.version)))
}

/// The migrations of a tenant's records alone.
fn tenant_tables() -> Migrator {
    let migrations = EVERY_TABLE
        .iter()
        .filter(|migration| !migration.description.starts_with(PLATFORM_ONLY))
        .cloned()
        .collect();
    Migrator {
        migrations: Cow::Owned(migrations),
        ..Migrator::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDb;

    /// A database every migration of this build was applied to is current.
    #[tokio::test]
    async fn a_migrated_database_is_current() {
        let db = TestDb::fresh().await;

        assert!(schema_is_current(&db.databases).await.unwrap());
    }

    /// Removing the latest migration record makes the database report that
    /// its schema is not current.
    #[tokio::test]
    async fn a_database_missing_a_migration_is_not_current() {
        let db = TestDb::fresh().await;
        db.tamper(
            "DELETE FROM public._sqlx_migrations \
             WHERE version = (SELECT max(version) FROM public._sqlx_migrations)",
        )
        .await;

        assert!(!schema_is_current(&db.databases).await.unwrap());
    }
}

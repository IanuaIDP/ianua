//! Reclaims test databases left behind by finished runs.

use sqlx::{PgConnection, PgPool};

use crate::test_support::{CLONE_LOCK, TEST_DATABASE_PREFIX, url};

/// Removes unused test databases on the shared server before a run.
/// Connected databases belong to live tests and stay. The clone lock
/// covers the gap between creating a database and opening its owner.
///
/// # Panics
///
/// When the server cannot list or remove the abandoned databases.
pub async fn discard_unused_databases(port: &str) {
    discard_matching(port, TEST_DATABASE_PREFIX).await;
}

/// Reclaims matching databases; tests use one exact database name so a
/// planted violation never interferes with another scenario's database.
async fn discard_matching(port: &str, prefix: &str) {
    let admin = PgPool::connect(&url(port, "postgres", "postgres", "postgres"))
        .await
        .expect("the admin database answers");
    let mut connection = admin.acquire().await.expect("an admin connection");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(CLONE_LOCK)
        .execute(&mut *connection)
        .await
        .expect("cleanup holds the clone lock");
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT quote_ident(d.datname) FROM pg_database d \
         WHERE starts_with(d.datname, $1) AND NOT EXISTS \
         (SELECT 1 FROM pg_stat_activity a WHERE a.datname = d.datname)",
    )
    .bind(prefix)
    .fetch_all(&mut *connection)
    .await
    .expect("the databases are listed");
    for name in names {
        discard_unconnected(&mut connection, &name).await;
    }
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(CLONE_LOCK)
        .execute(&mut *connection)
        .await
        .expect("cleanup releases the clone lock");
    drop(connection);
    admin.close().await;
}

/// Drops a quoted database name without forcing any connection closed.
/// A connection opened since the listing keeps its database; other errors
/// fail setup rather than silently leave broken cleanup behind.
async fn discard_unconnected(connection: &mut PgConnection, quoted_name: &str) {
    let result = sqlx::raw_sql(&format!("DROP DATABASE IF EXISTS {quoted_name}"))
        .execute(connection)
        .await;
    if matches!(&result, Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("55006"))
    {
        return;
    }
    result.expect("an abandoned database is dropped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDb;

    /// Cleanup preserves a connected test database: its owner still reads and a
    /// new connection still opens.
    #[tokio::test]
    async fn cleanup_preserves_a_running_tests_database() {
        let db = TestDb::fresh().await;
        discard_matching(&db.port, &db.name).await;
        let value: i32 = sqlx::query_scalar("SELECT 1")
            .fetch_one(&db.owner)
            .await
            .expect("the live connection still reads");
        assert_eq!(value, 1);
        let other = PgPool::connect(&db.address("postgres", "postgres"))
            .await
            .expect("a new connection still opens");
        other.close().await;
    }

    /// A test that lost its connections leaves a database behind; cleanup
    /// removes it so crashed runs do not fill the shared server's disk.
    #[tokio::test]
    async fn cleanup_reclaims_an_abandoned_database() {
        let db = TestDb::fresh().await;
        db.owner.close().await;
        discard_matching(&db.port, &db.name).await;
        let admin = PgPool::connect(&url(&db.port, "postgres", "postgres", "postgres"))
            .await
            .expect("the admin database answers");
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)")
                .bind(&db.name)
                .fetch_one(&admin)
                .await
                .expect("the database is looked up");
        assert!(!exists, "the abandoned database was reclaimed");
        admin.close().await;
    }
}

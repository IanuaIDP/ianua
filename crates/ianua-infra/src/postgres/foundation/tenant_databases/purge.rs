//! Removing everything a deleted tenant holds in one database, in the
//! caller's transaction.
//!
//! The tables are read from the database itself: every table of the
//! connection's schema with a `tenant_id` column, but the audit trail's
//! and those the caller keeps. So a table added later is purged without anyone listing it. A
//! table is emptied of the tenant's rows only once no other table still to
//! be emptied refers to it, so no link stops a delete half way; tables that
//! refer to each other in a circle stop the purge before it removes
//! anything. A table's name comes from the database's catalog, and is
//! quoted as an identifier all the same.

use std::collections::BTreeSet;

use sqlx::PgConnection;
use uuid::Uuid;

/// The tables of the connection's schema with a `tenant_id` column.
const TENANT_TABLES: &str = "SELECT c.relname::text FROM pg_class c \
     JOIN pg_attribute a ON a.attrelid = c.oid \
     WHERE c.relnamespace = current_schema()::regnamespace \
     AND c.relkind IN ('r', 'p') AND a.attname = 'tenant_id' AND NOT a.attisdropped";

/// The links between tables of the connection's schema: the table that
/// refers, and the table it refers to.
const LINKS: &str = "SELECT child.relname::text, parent.relname::text FROM pg_constraint k \
     JOIN pg_class child ON child.oid = k.conrelid \
     JOIN pg_class parent ON parent.oid = k.confrelid \
     WHERE k.contype = 'f' AND k.conrelid <> k.confrelid \
     AND child.relnamespace = current_schema()::regnamespace \
     AND parent.relnamespace = current_schema()::regnamespace";

/// The audit trail's tables, which no purge empties: the app's role holds
/// no delete on them, and the retention purge alone removes their rows.
const TRAIL: &[&str] = &[
    "audit_records",
    "audit_chain_anchors",
    "audit_chain_heads",
    "audit_chain_verdicts",
];

/// Removes `tenant`'s rows from every tenant table of the connection's
/// schema but the trail's and `kept`, and answers how many went.
pub(crate) async fn purge(
    connection: &mut PgConnection,
    tenant: Uuid,
    kept: &[&str],
) -> Result<u64, sqlx::Error> {
    let tables: Vec<String> = sqlx::query_scalar(TENANT_TABLES)
        .fetch_all(&mut *connection)
        .await?;
    let links: Vec<(String, String)> = sqlx::query_as(LINKS).fetch_all(&mut *connection).await?;
    let purged: BTreeSet<String> = tables
        .into_iter()
        .filter(|table| !TRAIL.contains(&table.as_str()) && !kept.contains(&table.as_str()))
        .collect();
    let order = deletion_order(purged, &links).ok_or_else(|| {
        sqlx::Error::InvalidArgument("tenant tables refer to each other in a circle".to_owned())
    })?;
    let mut removed: u64 = 0;
    for table in order {
        let delete = format!("DELETE FROM {} WHERE tenant_id = $1", quoted(&table));
        let gone = sqlx::query(&delete)
            .bind(tenant)
            .execute(&mut *connection)
            .await?
            .rows_affected();
        removed = removed.saturating_add(gone);
    }
    Ok(removed)
}

/// `tables` in an order where each comes before every table it refers to
/// by `links`, or `None` when some refer to each other in a circle.
fn deletion_order(mut left: BTreeSet<String>, links: &[(String, String)]) -> Option<Vec<String>> {
    let mut order = Vec::with_capacity(left.len());
    while !left.is_empty() {
        let free: Vec<String> = left
            .iter()
            .filter(|table| {
                !links
                    .iter()
                    .any(|(child, parent)| parent == *table && left.contains(child))
            })
            .cloned()
            .collect();
        if free.is_empty() {
            return None;
        }
        for table in free {
            left.remove(&table);
            order.push(table);
        }
    }
    Some(order)
}

/// `name` quoted as an identifier, a quote in it doubled.
fn quoted(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::postgres::foundation::security::RowScope;
    use crate::postgres::foundation::unit::scoped;
    use crate::test_support::TestDb;

    /// A database with a `notes` table made after every migration, as a
    /// later migration would add one, holding one note of each tenant.
    async fn with_notes(acme: TenantId, globex: TenantId) -> TestDb {
        let db = TestDb::fresh().await;
        db.tamper(&format!(
            "CREATE TABLE notes (id uuid PRIMARY KEY, tenant_id uuid NOT NULL);
             GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO ianua_app;
             INSERT INTO notes VALUES (gen_random_uuid(), '{acme}'), (gen_random_uuid(), '{globex}');"
        ))
        .await;
        db
    }

    /// Purges `tenant` keeping `kept`, and answers the notes left of each
    /// of `counted`.
    async fn purged(
        db: &TestDb,
        tenant: TenantId,
        kept: &[&str],
        counted: [TenantId; 2],
    ) -> Vec<i64> {
        scoped(&db.databases, RowScope::Platform, async |connection| {
            purge(&mut *connection, *tenant.as_uuid(), kept).await?;
            let mut left = Vec::new();
            for held in counted {
                let count: i64 =
                    sqlx::query_scalar("SELECT count(*) FROM notes WHERE tenant_id = $1")
                        .bind(held.as_uuid())
                        .fetch_one(&mut *connection)
                        .await?;
                left.push(count);
            }
            Ok(left)
        })
        .await
        .unwrap()
    }

    /// Purging Acme also discovers a table added after migration, removes
    /// Acme's note and leaves Globex's note intact.
    #[tokio::test]
    async fn a_table_added_later_is_purged_too() {
        let (acme, globex) = (TenantId::new(), TenantId::new());
        let db = with_notes(acme, globex).await;

        let left = purged(&db, acme, &[], [acme, globex]).await;

        assert_eq!(left, [0, 1]);
    }

    /// A table the caller keeps keeps the tenant's rows.
    #[tokio::test]
    async fn a_kept_table_keeps_its_rows() {
        let (acme, globex) = (TenantId::new(), TenantId::new());
        let db = with_notes(acme, globex).await;

        let left = purged(&db, acme, &["notes"], [acme, globex]).await;

        assert_eq!(left, [1, 1]);
    }

    /// The migrated schema admits a deletion order; purging an absent
    /// tenant succeeds without removing any rows.
    #[tokio::test]
    async fn the_platforms_tables_purge_in_an_order() {
        let db = TestDb::fresh().await;

        let removed = scoped(&db.databases, RowScope::Platform, async |connection| {
            purge(connection, *TenantId::new().as_uuid(), &[]).await
        })
        .await;

        assert_eq!(removed.unwrap(), 0);
    }

    fn tables(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    fn link(child: &str, parent: &str) -> (String, String) {
        (child.to_owned(), parent.to_owned())
    }

    /// A table is emptied before the tables it refers to: a role's
    /// assignments before the role, the role before nothing else waits.
    #[test]
    fn a_table_goes_before_the_tables_it_refers_to() {
        let links = [link("role_assignments", "roles"), link("roles", "users")];

        let order =
            deletion_order(tables(&["users", "roles", "role_assignments"]), &links).unwrap();

        assert_eq!(order, ["role_assignments", "roles", "users"]);
    }

    /// A link from or to a table not purged holds nothing back.
    #[test]
    fn a_link_outside_the_purge_holds_nothing_back() {
        let links = [link("audit_records", "users")];

        let order = deletion_order(tables(&["users"]), &links).unwrap();

        assert_eq!(order, ["users"]);
    }

    /// Mutually referencing tables yield no deletion order, so the purge
    /// cannot begin with either table.
    #[test]
    fn tables_in_a_circle_are_refused() {
        let links = [link("a", "b"), link("b", "a")];

        assert!(deletion_order(tables(&["a", "b"]), &links).is_none());
    }

    /// A quote in a table's name cannot end the identifier early.
    #[test]
    fn a_quote_in_a_name_is_doubled() {
        assert_eq!(quoted("odd\"name"), "\"odd\"\"name\"");
    }
}

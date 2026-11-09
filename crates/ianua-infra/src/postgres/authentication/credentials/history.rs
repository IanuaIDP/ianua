//! The hashes of each account's retired passwords, so a new password can
//! be checked against them, newest first.
//!
//! Each entry keeps the time it was recorded; one recorded in the same
//! instant as the one before it is placed just after it, so the order is
//! never a tie.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::PasswordHistory;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PasswordHash, UserId};

use self::record::RetiredRecord;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres history of each account's retired passwords.
pub struct PgPasswordHistory {
    databases: Arc<Databases>,
}

impl PgPasswordHistory {
    /// A history kept in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgPasswordHistory {}

#[async_trait]
impl PasswordHistory for PgPasswordHistory {
    async fn recent(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        count: u32,
    ) -> Result<Vec<PasswordHash>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RetiredRecord,
                    "queries/password_history/recent.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid(),
                    i64::from(count)
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        Ok(records.into_iter().map(RetiredRecord::into_hash).collect())
    }

    async fn record(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        hash: &PasswordHash,
    ) -> Result<(), DomainError> {
        let recorded_at = clock::now();
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/password_history/add.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid(),
                    recorded_at,
                    hash.as_str()
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::UserStore;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::shared::config::DomainLimits;

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::identity::user_row;

    /// A fresh database holding Ann and Bob in Acme, and the history on it.
    async fn fixture() -> (TestDb, PgPasswordHistory, ScopedTenant, UserId, UserId) {
        let db = TestDb::fresh().await;
        let acme = tenant();
        let users = PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default());
        let mut ids = Vec::new();
        for email in ["ann@acme.example", "bob@acme.example"] {
            let user = User::reconstitute(user_row(email)).unwrap();
            users.save(&acme, &user).await.unwrap();
            ids.push(*user.id());
        }
        let history = PgPasswordHistory::new(Arc::clone(&db.databases));
        (db, history, acme, ids[0], ids[1])
    }

    fn hash(value: &str) -> PasswordHash {
        PasswordHash::from_stored(value.to_owned())
    }

    /// Ann retired three passwords: the latest two come back newest first,
    /// and Bob's are not among them.
    #[tokio::test]
    async fn the_latest_retired_hashes_come_newest_first() {
        let (_db, history, acme, ann, bob) = fixture().await;
        for retired in ["first", "second", "third"] {
            history.record(&acme, &ann, &hash(retired)).await.unwrap();
        }
        history.record(&acme, &bob, &hash("bobs")).await.unwrap();

        let recent = history.recent(&acme, &ann, 2).await.unwrap();

        assert_eq!(recent, [hash("third"), hash("second")]);
    }

    /// Someone who never retired a password has no history.
    #[tokio::test]
    async fn an_account_without_history_has_none() {
        let (_db, history, acme, ann, _) = fixture().await;

        assert!(history.recent(&acme, &ann, 5).await.unwrap().is_empty());
    }

    /// Ann's retired password hashes are absent from another tenant's lookup.
    #[tokio::test]
    async fn another_tenants_history_is_invisible() {
        let (_db, history, acme, ann, _) = fixture().await;
        history.record(&acme, &ann, &hash("first")).await.unwrap();

        let elsewhere = history.recent(&tenant(), &ann, 5).await.unwrap();

        assert!(elsewhere.is_empty());
    }
}

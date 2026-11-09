//! The codes mailed or texted for an account's second factor: the store of
//! `ports/authentication/sent_codes.rs`.
//!
//! An account has one row, the latest code sent, so a new code replaces
//! the one before and a code read late stops working. Only the code's
//! keyed hash is kept. A caller that checks a typed code holds the row
//! until its unit of work ends, so two answers sent at once both count.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::SentCodeStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authentication::mfa::one_time_code::OneTimeCode;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::UserId;

use self::record::{SentCodeColumns, SentCodeRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of the codes sent for second factors.
pub struct PgSentCodeStore {
    databases: Arc<Databases>,
}

impl PgSentCodeStore {
    /// A store keeping sent codes in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgSentCodeStore {}

#[async_trait]
impl SentCodeStore for PgSentCodeStore {
    async fn latest(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<OneTimeCode<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    SentCodeRecord,
                    "queries/mfa_sent_codes/of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(SentCodeRecord::into_code).transpose()
    }

    async fn hold_latest(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<OneTimeCode<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    SentCodeRecord,
                    "queries/mfa_sent_codes/hold.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(SentCodeRecord::into_code).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        code: &OneTimeCode<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = SentCodeColumns::of(code);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/mfa_sent_codes/keep.sql",
                    tenant_id.as_uuid(),
                    columns.user_id,
                    columns.enrolled_at,
                    columns.method,
                    columns.code_hash,
                    columns.issued_at,
                    columns.expires_at,
                    columns.wrong_tries,
                    columns.spent_at,
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
    use ianua_domain::domains::authentication::mfa::one_time_code::OneTimeCodeRow;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::Usage;

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authentication::{hash, sent_code_row};
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::identity::user_row;

    /// A fresh database holding Ann in Acme, and the store on it.
    async fn fixture() -> (TestDb, PgSentCodeStore, ScopedTenant, UserId) {
        let db = TestDb::fresh().await;
        let acme = tenant();
        let ann = User::reconstitute(user_row("ann@acme.example")).unwrap();
        PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&acme, &ann)
            .await
            .unwrap();
        let store = PgSentCodeStore::new(Arc::clone(&db.databases));
        (db, store, acme, *ann.id())
    }

    fn code(row: OneTimeCodeRow) -> OneTimeCode<ResolvedTenant> {
        OneTimeCode::reconstitute(row).unwrap()
    }

    /// The code mailed to Ann is found as her latest, and holding it reads
    /// the same.
    #[tokio::test]
    async fn a_sent_code_is_found_and_held_as_the_latest() {
        let (_db, store, acme, ann) = fixture().await;
        let sent = code(sent_code_row(ann, "code-1", 10));

        store.save(&acme, &sent).await.unwrap();

        let latest = store.latest(&acme, &ann).await.unwrap().unwrap();
        let held = store.hold_latest(&acme, &ann).await.unwrap().unwrap();
        for read in [&latest, &held] {
            assert_eq!(read.code_hash(), &hash("code-1"));
            assert_eq!(read.issued_at(), at(10));
            assert_eq!(read.wrong_tries(), 0);
            assert_eq!(read.spent_at(), None);
        }
    }

    /// Someone who was never sent a code has none.
    #[tokio::test]
    async fn a_user_never_sent_a_code_has_none() {
        let (_db, store, acme, ann) = fixture().await;

        assert!(store.latest(&acme, &ann).await.unwrap().is_none());
        assert!(store.hold_latest(&acme, &ann).await.unwrap().is_none());
    }

    /// Saving a newer code replaces the hash returned as Ann's latest code.
    #[tokio::test]
    async fn a_new_code_replaces_the_one_before() {
        let (_db, store, acme, ann) = fixture().await;
        store
            .save(&acme, &code(sent_code_row(ann, "code-1", 10)))
            .await
            .unwrap();

        store
            .save(&acme, &code(sent_code_row(ann, "code-2", 60)))
            .await
            .unwrap();

        let latest = store.latest(&acme, &ann).await.unwrap().unwrap();
        assert_eq!(latest.code_hash(), &hash("code-2"));
    }

    /// A wrong try counted and the code's spending are kept.
    #[tokio::test]
    async fn saving_again_keeps_the_tries_and_the_spending() {
        let (_db, store, acme, ann) = fixture().await;
        store
            .save(&acme, &code(sent_code_row(ann, "code-1", 10)))
            .await
            .unwrap();
        let spent = code(OneTimeCodeRow {
            wrong_tries: 2,
            usage: Usage::Used { at: at(40) },
            ..sent_code_row(ann, "code-1", 10)
        });

        store.save(&acme, &spent).await.unwrap();

        let latest = store.latest(&acme, &ann).await.unwrap().unwrap();
        assert_eq!(latest.wrong_tries(), 2);
        assert_eq!(latest.spent_at(), Some(at(40)));
    }

    /// Another tenant's lookup returns none of Ann's sent codes.
    #[tokio::test]
    async fn another_tenants_codes_are_invisible() {
        let (_db, store, acme, ann) = fixture().await;
        store
            .save(&acme, &code(sent_code_row(ann, "code-1", 10)))
            .await
            .unwrap();

        assert!(store.latest(&tenant(), &ann).await.unwrap().is_none());
    }

    /// Extending a stored sent code's lifetime to one day makes its lookup
    /// fail as corrupt storage.
    #[tokio::test]
    async fn a_code_living_too_long_is_refused() {
        let (db, store, acme, ann) = fixture().await;
        store
            .save(&acme, &code(sent_code_row(ann, "code-1", 10)))
            .await
            .unwrap();
        db.tamper("UPDATE mfa_sent_codes SET expires_at = issued_at + interval '1 day'")
            .await;

        let read = store.latest(&acme, &ann).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}

//! The one-time codes that carry a single sign-on back to the dashboard.
//!
//! A code is taken by deleting it, in one statement that hands back what it
//! deleted, so a code is used once however many times it is sent. It goes
//! with the session it carries.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::SignInCodeStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authentication::sessions::sign_in_code::SignInCode;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TokenHash;

use self::record::{CodeColumns, CodeRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of the codes that carry a single sign-on back.
pub struct PgSignInCodeStore {
    databases: Arc<Databases>,
}

impl PgSignInCodeStore {
    /// A store keeping sign-in codes in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgSignInCodeStore {}

#[async_trait]
impl SignInCodeStore for PgSignInCodeStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        code: &SignInCode<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = CodeColumns::of(code);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/sign_in_codes/save.sql",
                    tenant_id.as_uuid(),
                    columns.token_hash,
                    columns.dashboard_hash,
                    columns.session_id,
                    columns.expires_at,
                    columns.consumed_at,
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn take(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<SignInCode<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    CodeRecord,
                    "queries/sign_in_codes/take.sql",
                    tenant_id.as_uuid(),
                    token_hash.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(CodeRecord::into_code).transpose()
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::UserStore;
    use ianua_app::ports::shared::SessionStore;
    use ianua_domain::domains::authentication::sessions::session::Session;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::SessionId;

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::postgres::shared::PgSessionStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::authentication::{hash, session_row, sign_in_code_row};
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::identity::user_row;

    /// A fresh database holding Ann's session in Acme, and the store on it.
    async fn fixture() -> (TestDb, PgSignInCodeStore, ScopedTenant, SessionId) {
        let db = TestDb::fresh().await;
        let acme = tenant();
        let ann = User::reconstitute(user_row("ann@acme.example")).unwrap();
        PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&acme, &ann)
            .await
            .unwrap();
        let session = Session::reconstitute(session_row(*ann.id(), "refresh-1")).unwrap();
        PgSessionStore::new(Arc::clone(&db.databases))
            .save(&acme, &session)
            .await
            .unwrap();
        let store = PgSignInCodeStore::new(Arc::clone(&db.databases));
        (db, store, acme, *session.id())
    }

    fn code(session: SessionId, token: &str) -> SignInCode<ResolvedTenant> {
        SignInCode::reconstitute(sign_in_code_row(session, token, "dashboard-1")).unwrap()
    }

    /// Taking a sign-in code returns its saved session, dashboard hash and
    /// expiry once; repeating the take finds nothing.
    #[tokio::test]
    async fn a_code_is_taken_once() {
        let (_db, store, acme, session) = fixture().await;
        let kept = code(session, "code-1");
        store.save(&acme, &kept).await.unwrap();

        let first = store.take(&acme, &hash("code-1")).await.unwrap().unwrap();
        let again = store.take(&acme, &hash("code-1")).await.unwrap();

        assert_eq!(first.session_id(), &session);
        assert_eq!(first.dashboard_hash(), &hash("dashboard-1"));
        assert_eq!(first.expires_at(), kept.expires_at());
        assert!(again.is_none());
    }

    /// A code nobody was given takes nothing.
    #[tokio::test]
    async fn an_unknown_code_is_not_taken() {
        let (_db, store, acme, _) = fixture().await;

        assert!(store.take(&acme, &hash("nobody")).await.unwrap().is_none());
    }

    /// Another tenant cannot take Ann's code, which remains available in Acme.
    #[tokio::test]
    async fn another_tenants_codes_are_invisible() {
        let (_db, store, acme, session) = fixture().await;
        store.save(&acme, &code(session, "code-1")).await.unwrap();

        let elsewhere = store.take(&tenant(), &hash("code-1")).await.unwrap();

        assert!(elsewhere.is_none());
        assert!(store.take(&acme, &hash("code-1")).await.unwrap().is_some());
    }

    /// A stored code marked consumed after its expiry is refused as corrupt
    /// storage when taken.
    #[tokio::test]
    async fn a_code_used_after_it_lapsed_is_refused() {
        let (db, store, acme, session) = fixture().await;
        store.save(&acme, &code(session, "code-1")).await.unwrap();
        db.tamper(
            "ALTER TABLE sign_in_codes DROP CONSTRAINT sign_in_codes_used_in_time; \
             UPDATE sign_in_codes SET consumed_at = expires_at + interval '1 hour'",
        )
        .await;

        let read = store.take(&acme, &hash("code-1")).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}

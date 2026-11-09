//! The one-time passes that carry a session to the host of a service
//! accepting it with a cookie of its own.
//!
//! A pass is taken by deleting it, in one statement that hands back what
//! it deleted, so a code is used once however many times it is sent.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::HandoffStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authentication::sessions::handoff::SessionHandoff;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TokenHash;

use self::record::{HandoffColumns, HandoffRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of the passes that carry a session to another host.
pub struct PgHandoffStore {
    databases: Arc<Databases>,
}

impl PgHandoffStore {
    /// A store keeping passes in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgHandoffStore {}

#[async_trait]
impl HandoffStore for PgHandoffStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        handoff: &SessionHandoff<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = HandoffColumns::of(handoff);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/session_handoffs/save.sql",
                    tenant_id.as_uuid(),
                    columns.token_hash,
                    columns.browser_hash,
                    columns.session_id,
                    columns.service_id,
                    columns.host,
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
    ) -> Result<Option<SessionHandoff<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    HandoffRecord,
                    "queries/session_handoffs/take.sql",
                    tenant_id.as_uuid(),
                    token_hash.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(HandoffRecord::into_handoff).transpose()
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::UserStore;
    use ianua_app::ports::routing::ServiceStore;
    use ianua_app::ports::shared::SessionStore;
    use ianua_domain::domains::authentication::sessions::session::Session;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::domains::routing::service::Service;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{ServiceId, SessionId};

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::postgres::routing::PgServiceStore;
    use crate::postgres::shared::PgSessionStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::authentication::{app_session_row, handoff_row, hash};
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::identity::user_row;
    use crate::test_support::rows::routing::service_row;

    /// A fresh database holding the shop and Ann's session on it in Acme,
    /// and the store on it.
    async fn fixture() -> (TestDb, PgHandoffStore, ScopedTenant, SessionId, ServiceId) {
        let db = TestDb::fresh().await;
        let acme = tenant();
        let ann = User::reconstitute(user_row("ann@acme.example")).unwrap();
        PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&acme, &ann)
            .await
            .unwrap();
        let shop = Service::reconstitute(service_row("shop")).unwrap();
        PgServiceStore::new(Arc::clone(&db.databases))
            .save(&acme, &shop)
            .await
            .unwrap();
        let session =
            Session::reconstitute(app_session_row(*ann.id(), *shop.id(), "refresh-1")).unwrap();
        PgSessionStore::new(Arc::clone(&db.databases))
            .save(&acme, &session)
            .await
            .unwrap();
        let store = PgHandoffStore::new(Arc::clone(&db.databases));
        (db, store, acme, *session.id(), *shop.id())
    }

    fn handoff(
        session: SessionId,
        service: ServiceId,
        code: &str,
    ) -> SessionHandoff<ResolvedTenant> {
        SessionHandoff::reconstitute(handoff_row(session, service, code)).unwrap()
    }

    /// Taking a handoff returns its session, browser, service, host and
    /// expiry once; a second take finds nothing.
    #[tokio::test]
    async fn a_pass_is_taken_once() {
        let (_db, store, acme, session, shop) = fixture().await;
        let pass = handoff(session, shop, "code-1");
        store.save(&acme, &pass).await.unwrap();

        let first = store.take(&acme, &hash("code-1")).await.unwrap().unwrap();
        let again = store.take(&acme, &hash("code-1")).await.unwrap();

        assert_eq!(first.session_id(), &session);
        assert_eq!(first.browser_hash(), pass.browser_hash());
        assert_eq!(first.service_id(), &shop);
        assert_eq!(first.host(), pass.host());
        assert_eq!(first.expires_at(), pass.expires_at());
        assert!(again.is_none());
    }

    /// A code nobody was given takes nothing.
    #[tokio::test]
    async fn an_unknown_pass_is_not_taken() {
        let (_db, store, acme, _, _) = fixture().await;

        assert!(store.take(&acme, &hash("nobody")).await.unwrap().is_none());
    }

    /// Another tenant cannot take Ann's handoff, which remains available
    /// through Acme's scope.
    #[tokio::test]
    async fn another_tenants_passes_are_invisible() {
        let (_db, store, acme, session, shop) = fixture().await;
        store
            .save(&acme, &handoff(session, shop, "code-1"))
            .await
            .unwrap();

        let elsewhere = store.take(&tenant(), &hash("code-1")).await.unwrap();

        assert!(elsewhere.is_none());
        assert!(store.take(&acme, &hash("code-1")).await.unwrap().is_some());
    }

    /// An invalid host written directly into a handoff makes taking it
    /// fail as corrupt storage.
    #[tokio::test]
    async fn a_pass_with_a_broken_host_is_refused() {
        let (db, store, acme, session, shop) = fixture().await;
        store
            .save(&acme, &handoff(session, shop, "code-1"))
            .await
            .unwrap();
        db.tamper("UPDATE session_handoffs SET host = 'not a host!'")
            .await;

        let read = store.take(&acme, &hash("code-1")).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}

//! The sessions a connection's provider keeps behind sessions here: whom
//! it named, and the session index its assertion carried, one per session
//! here.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::federation::{ProviderSession, ProviderSessionStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::SessionId;

use self::record::SessionRecord;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of provider sessions.
pub struct PgProviderSessionStore {
    databases: Arc<Databases>,
}

impl PgProviderSessionStore {
    /// A store keeping provider sessions in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgProviderSessionStore {}

#[async_trait]
impl ProviderSessionStore for PgProviderSessionStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        session: &ProviderSession,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/provider_sessions/keep.sql",
                    tenant_id.as_uuid(),
                    session.session_id.as_uuid(),
                    session.connection_id.as_uuid(),
                    session.subject.as_str(),
                    session.session_index.as_str()
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn find_by_session(
        &self,
        tenant_id: &ScopedTenant,
        session_id: &SessionId,
    ) -> Result<Option<ProviderSession>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    SessionRecord,
                    "queries/provider_sessions/of_session.sql",
                    tenant_id.as_uuid(),
                    session_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(SessionRecord::into_session).transpose()
    }

    async fn delete_by_session(
        &self,
        tenant_id: &ScopedTenant,
        session_id: &SessionId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/provider_sessions/delete.sql",
                    tenant_id.as_uuid(),
                    session_id.as_uuid()
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
    use ianua_app::ports::federation::ConnectionStore;
    use ianua_domain::domains::federation::connection::FederatedIdpConnection;
    use ianua_domain::types::ConnectionId;

    use super::*;
    use crate::postgres::federation::PgConnectionStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::authentication::signed_in_session;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::federation::{connection_row, provider_session, saml_config};

    struct Fixture {
        db: TestDb,
        store: PgProviderSessionStore,
        tenant: ScopedTenant,
        okta: ConnectionId,
    }

    /// A fresh database holding a tenant with Okta, and the store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = tenant();
        let okta =
            FederatedIdpConnection::reconstitute(connection_row("Okta", saml_config())).unwrap();
        PgConnectionStore::new(Arc::clone(&db.databases))
            .save(&tenant, &okta)
            .await
            .unwrap();
        Fixture {
            store: PgProviderSessionStore::new(Arc::clone(&db.databases)),
            okta: *okta.id(),
            tenant,
            db,
        }
    }

    impl Fixture {
        /// A session of a new user of the tenant, saved through its store.
        async fn session(&self) -> SessionId {
            signed_in_session(&self.db.databases, &self.tenant).await
        }
    }

    /// The provider session behind Ann's session is found as it was kept.
    #[tokio::test]
    async fn a_provider_session_is_found_by_its_session() {
        let fx = fixture().await;
        let kept = provider_session(fx.session().await, fx.okta, "okta|ann");
        fx.store.save(&fx.tenant, &kept).await.unwrap();

        let found = fx
            .store
            .find_by_session(&fx.tenant, &kept.session_id)
            .await
            .unwrap();

        assert_eq!(found, Some(kept));
    }

    /// A session opened without a SAML provider finds none.
    #[tokio::test]
    async fn a_session_without_one_finds_none() {
        let fx = fixture().await;

        let found = fx
            .store
            .find_by_session(&fx.tenant, &SessionId::new())
            .await
            .unwrap();

        assert!(found.is_none());
    }

    /// Ann signs in again on the same session: the newer provider session
    /// replaces the one before.
    #[tokio::test]
    async fn saving_again_replaces_the_one_before() {
        let fx = fixture().await;
        let session = fx.session().await;
        fx.store
            .save(&fx.tenant, &provider_session(session, fx.okta, "okta|ann"))
            .await
            .unwrap();
        let newer = provider_session(session, fx.okta, "okta|ann-again");

        fx.store.save(&fx.tenant, &newer).await.unwrap();

        let found = fx
            .store
            .find_by_session(&fx.tenant, &session)
            .await
            .unwrap();
        assert_eq!(found, Some(newer));
    }

    /// A forgotten provider session is gone.
    #[tokio::test]
    async fn a_deleted_provider_session_is_gone() {
        let fx = fixture().await;
        let kept = provider_session(fx.session().await, fx.okta, "okta|ann");
        fx.store.save(&fx.tenant, &kept).await.unwrap();

        fx.store
            .delete_by_session(&fx.tenant, &kept.session_id)
            .await
            .unwrap();

        let found = fx
            .store
            .find_by_session(&fx.tenant, &kept.session_id)
            .await
            .unwrap();
        assert!(found.is_none());
    }

    /// Looking up Acme's provider session from Globex returns nothing.
    #[tokio::test]
    async fn another_tenants_provider_session_is_not_found() {
        let fx = fixture().await;
        let kept = provider_session(fx.session().await, fx.okta, "okta|ann");
        fx.store.save(&fx.tenant, &kept).await.unwrap();

        let found = fx
            .store
            .find_by_session(&tenant(), &kept.session_id)
            .await
            .unwrap();

        assert!(found.is_none());
    }

    /// A stored provider session with an empty subject fails to load as
    /// corrupt storage.
    #[tokio::test]
    async fn a_row_holding_a_broken_value_is_refused() {
        let fx = fixture().await;
        let kept = provider_session(fx.session().await, fx.okta, "okta|ann");
        fx.store.save(&fx.tenant, &kept).await.unwrap();
        fx.db
            .tamper("UPDATE provider_sessions SET subject = ''")
            .await;

        let found = fx.store.find_by_session(&fx.tenant, &kept.session_id).await;

        assert!(matches!(found, Err(DomainError::Infrastructure(_))));
    }
}

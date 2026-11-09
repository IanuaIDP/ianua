//! The SAML apps each session here signed in to, each sign-in once, so a
//! logout reaches every one of them.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::federation::{SamlAppSession, SamlAppSessionStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::SessionId;

use self::record::AppSessionRecord;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of the SAML apps sessions signed in to.
pub struct PgSamlAppSessionStore {
    databases: Arc<Databases>,
}

impl PgSamlAppSessionStore {
    /// A store keeping app sessions in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgSamlAppSessionStore {}

#[async_trait]
impl SamlAppSessionStore for PgSamlAppSessionStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        app_session: &SamlAppSession,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/saml_app_sessions/keep.sql",
                    tenant_id.as_uuid(),
                    app_session.session_id.as_uuid(),
                    app_session.provider_id.as_uuid(),
                    app_session.name_id.as_str(),
                    app_session.session_index.as_str()
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn list_by_session(
        &self,
        tenant_id: &ScopedTenant,
        session_id: &SessionId,
    ) -> Result<Vec<SamlAppSession>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    AppSessionRecord,
                    "queries/saml_app_sessions/of_session.sql",
                    tenant_id.as_uuid(),
                    session_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(AppSessionRecord::into_app_session)
            .collect()
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
                    "queries/saml_app_sessions/delete.sql",
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
    use ianua_app::ports::federation::SamlServiceProviderStore;
    use ianua_domain::domains::federation::service_provider::SamlServiceProvider;
    use ianua_domain::types::SamlServiceProviderId;

    use super::*;
    use crate::postgres::federation::PgSamlServiceProviderStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::authentication::signed_in_session;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::federation::{app_session, service_provider_row};

    struct Fixture {
        db: TestDb,
        store: PgSamlAppSessionStore,
        tenant: ScopedTenant,
        apps: PgSamlServiceProviderStore,
        wiki: SamlServiceProviderId,
        chat: SamlServiceProviderId,
    }

    /// A fresh database holding a tenant with two SAML apps, and the store
    /// on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = tenant();
        let apps = PgSamlServiceProviderStore::new(Arc::clone(&db.databases));
        let wiki = SamlServiceProvider::reconstitute(service_provider_row(
            "Wiki",
            "https://wiki.acme.example",
        ))
        .unwrap();
        let chat = SamlServiceProvider::reconstitute(service_provider_row(
            "Chat",
            "https://chat.acme.example",
        ))
        .unwrap();
        apps.save(&tenant, &wiki).await.unwrap();
        apps.save(&tenant, &chat).await.unwrap();
        Fixture {
            store: PgSamlAppSessionStore::new(Arc::clone(&db.databases)),
            wiki: *wiki.id(),
            chat: *chat.id(),
            apps,
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

    /// Ann's session signed in to the wiki and the chat: both are listed,
    /// and the same sign-in kept twice is listed once.
    #[tokio::test]
    async fn the_apps_a_session_signed_in_to_are_listed_once_each() {
        let fx = fixture().await;
        let session = fx.session().await;
        let wiki = app_session(session, fx.wiki, "pairwise-ann-wiki", "_s1");
        let chat = app_session(session, fx.chat, "pairwise-ann-chat", "_s2");
        for kept in [&wiki, &chat, &wiki] {
            fx.store.save(&fx.tenant, kept).await.unwrap();
        }

        let listed = fx
            .store
            .list_by_session(&fx.tenant, &session)
            .await
            .unwrap();

        assert_eq!(listed.len(), 2);
        assert!(listed.contains(&wiki));
        assert!(listed.contains(&chat));
    }

    /// Another session's sign-ins are not listed for this one.
    #[tokio::test]
    async fn another_sessions_sign_ins_are_not_listed() {
        let fx = fixture().await;
        fx.store
            .save(
                &fx.tenant,
                &app_session(fx.session().await, fx.wiki, "pairwise-bob", "_s1"),
            )
            .await
            .unwrap();

        let listed = fx
            .store
            .list_by_session(&fx.tenant, &SessionId::new())
            .await
            .unwrap();

        assert!(listed.is_empty());
    }

    /// Once logouts went out, the session's sign-ins are forgotten.
    #[tokio::test]
    async fn a_sessions_sign_ins_are_forgotten() {
        let fx = fixture().await;
        let session = fx.session().await;
        fx.store
            .save(
                &fx.tenant,
                &app_session(session, fx.wiki, "pairwise-ann", "_s1"),
            )
            .await
            .unwrap();

        fx.store
            .delete_by_session(&fx.tenant, &session)
            .await
            .unwrap();

        let listed = fx
            .store
            .list_by_session(&fx.tenant, &session)
            .await
            .unwrap();
        assert!(listed.is_empty());
    }

    /// A removed app takes the record of every sign-in to it.
    #[tokio::test]
    async fn a_removed_app_takes_its_sign_ins() {
        let fx = fixture().await;
        let session = fx.session().await;
        fx.store
            .save(
                &fx.tenant,
                &app_session(session, fx.wiki, "pairwise-ann", "_s1"),
            )
            .await
            .unwrap();

        fx.apps.delete(&fx.tenant, &fx.wiki).await.unwrap();

        let listed = fx
            .store
            .list_by_session(&fx.tenant, &session)
            .await
            .unwrap();
        assert!(listed.is_empty());
    }

    /// Listing Acme's app sessions from Globex returns an empty list.
    #[tokio::test]
    async fn another_tenants_sign_ins_are_not_listed() {
        let fx = fixture().await;
        let session = fx.session().await;
        fx.store
            .save(
                &fx.tenant,
                &app_session(session, fx.wiki, "pairwise-ann", "_s1"),
            )
            .await
            .unwrap();

        let listed = fx.store.list_by_session(&tenant(), &session).await.unwrap();

        assert!(listed.is_empty());
    }

    /// An app session with an empty stored NameID makes listing fail as
    /// corrupt storage.
    #[tokio::test]
    async fn a_row_holding_a_broken_value_is_refused() {
        let fx = fixture().await;
        let session = fx.session().await;
        fx.store
            .save(
                &fx.tenant,
                &app_session(session, fx.wiki, "pairwise-ann", "_s1"),
            )
            .await
            .unwrap();
        fx.db
            .tamper("UPDATE saml_app_sessions SET name_id = ''")
            .await;

        let listed = fx.store.list_by_session(&fx.tenant, &session).await;

        assert!(matches!(listed, Err(DomainError::Infrastructure(_))));
    }
}

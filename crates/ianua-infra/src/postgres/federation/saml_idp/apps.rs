//! A tenant's SAML apps, signed in to with this platform as their identity
//! provider. An app's entity id is unique within its tenant, kept so by a
//! constraint.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::federation::{SamlAppSortField, SamlServiceProviderStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::federation::service_provider::SamlServiceProvider;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{SamlEntityId, SamlServiceProviderId};
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{AppColumns, AppRecord, apps_from};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps an entity id to one app of a tenant.
const ENTITY_ID_KEY: &str = "saml_service_providers_entity_id_key";

/// The Postgres store of a tenant's SAML apps.
pub struct PgSamlServiceProviderStore {
    databases: Arc<Databases>,
}

impl PgSamlServiceProviderStore {
    /// A store keeping apps in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgSamlServiceProviderStore {}

/// The records of the apps of `tenant_id` that `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    ids: &[Uuid],
) -> Result<Vec<AppRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        AppRecord,
        "queries/saml_service_providers/by_ids.sql",
        tenant_id,
        ids
    )
    .fetch_all(connection)
    .await
}

impl SortColumns for SamlAppSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

#[async_trait]
impl SamlServiceProviderStore for PgSamlServiceProviderStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SamlServiceProviderId,
    ) -> Result<Option<SamlServiceProvider<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| records_of(connection, tenant_id.as_uuid(), &ids).await,
        )
        .await?;
        Ok(apps_from(records)?.pop())
    }

    async fn find_by_entity_id(
        &self,
        tenant_id: &ScopedTenant,
        entity_id: &SamlEntityId,
    ) -> Result<Option<SamlServiceProvider<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    AppRecord,
                    "queries/saml_service_providers/by_entity_id.sql",
                    tenant_id.as_uuid(),
                    entity_id.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(AppRecord::into_app).transpose()
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
        page: &PageRequest,
    ) -> Result<Page<SamlServiceProvider<ResolvedTenant>>, DomainError> {
        let order = SortOrder::<SamlAppSortField>::default();
        let keyset = page.keyset(&order)?;
        let listed = PageQuery::ids("id", "saml_service_providers")
            .filter("tenant_id = ?", *tenant_id.as_uuid());
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let records = records_of(connection, tenant_id.as_uuid(), &ids).await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        Ok(keyset.seal(apps_from(records)?))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        provider: &SamlServiceProvider<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = AppColumns::of(provider)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/saml_service_providers/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.name,
                    columns.entity_id,
                    columns.status,
                    columns.settings,
                    columns.created_at,
                    columns.updated_at,
                )
                .execute(connection)
                .await;
                unique_on(attempt, ENTITY_ID_KEY)
            },
        )
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-another-app-of-this-tenant-already",
                "another app of this tenant already has this entity id"
            ))),
        }
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &SamlServiceProviderId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/saml_service_providers/delete.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
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
    use ianua_app::listing::Limit;
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::domains::federation::service_provider::{
        AssertionEncryption, RequestSigningRule, SamlServiceProviderRow, SignedParts,
    };
    use ianua_domain::types::{CertificatePem, Label, Setting};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::federation::{service_provider_row, url};

    struct Fixture {
        db: TestDb,
        store: PgSamlServiceProviderStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, the store on it, and one tenant.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            store: PgSamlServiceProviderStore::new(Arc::clone(&db.databases)),
            tenant: tenant(),
            db,
        }
    }

    fn app(row: SamlServiceProviderRow) -> SamlServiceProvider<ResolvedTenant> {
        SamlServiceProvider::reconstitute(row).unwrap()
    }

    fn certificate() -> CertificatePem {
        CertificatePem::new("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----").unwrap()
    }

    /// Reads app names in the order returned by a page.
    fn names(page: &Page<SamlServiceProvider<ResolvedTenant>>) -> Vec<String> {
        page.items
            .iter()
            .map(|app| app.name().as_str().to_owned())
            .collect()
    }

    fn assert_same(
        found: &SamlServiceProvider<ResolvedTenant>,
        saved: &SamlServiceProvider<ResolvedTenant>,
    ) {
        assert_eq!(found.id(), saved.id());
        assert_eq!(found.name(), saved.name());
        assert_eq!(found.entity_id(), saved.entity_id());
        assert_eq!(found.status(), saved.status());
        assert_eq!(found.settings(), saved.settings());
        assert_eq!(found.created_at(), saved.created_at());
        assert_eq!(found.updated_at(), saved.updated_at());
    }

    /// The wiki app, sealing its assertions and signing its requests, is
    /// found by its id and by its entity id, as it was saved.
    #[tokio::test]
    async fn an_app_is_found_by_id_and_by_entity_id() {
        let fx = fixture().await;
        let mut row = service_provider_row("Wiki", "https://wiki.acme.example");
        row.settings.logout_url = Setting::Set(url("https://wiki.acme.example/slo"));
        row.settings.signing = SignedParts::AssertionAndResponse;
        row.settings.encryption = AssertionEncryption::EncryptedFor(certificate());
        row.settings.request_signing = RequestSigningRule::Required(certificate());
        let wiki = app(row);
        fx.store.save(&fx.tenant, &wiki).await.unwrap();

        let by_id = fx.store.find_by_id(&fx.tenant, wiki.id()).await.unwrap();
        let by_entity = fx
            .store
            .find_by_entity_id(&fx.tenant, wiki.entity_id())
            .await
            .unwrap();

        assert_same(&by_id.unwrap(), &wiki);
        assert_same(&by_entity.unwrap(), &wiki);
    }

    /// An id or entity id nobody has finds nothing, rather than failing.
    #[tokio::test]
    async fn an_unknown_app_is_not_found() {
        let fx = fixture().await;
        let unknown = SamlEntityId::new("https://nobody.example").unwrap();

        let by_id = fx
            .store
            .find_by_id(&fx.tenant, &SamlServiceProviderId::new())
            .await
            .unwrap();
        let by_entity = fx
            .store
            .find_by_entity_id(&fx.tenant, &unknown)
            .await
            .unwrap();

        assert!(by_id.is_none());
        assert!(by_entity.is_none());
    }

    /// Saving a second SAML app with the tenant's existing entity ID
    /// returns a conflict.
    #[tokio::test]
    async fn a_second_app_with_the_same_entity_id_is_refused() {
        let fx = fixture().await;
        let wiki = app(service_provider_row("Wiki", "https://wiki.acme.example"));
        fx.store.save(&fx.tenant, &wiki).await.unwrap();

        let twin = fx
            .store
            .save(
                &fx.tenant,
                &app(service_provider_row("Wiki 2", "https://wiki.acme.example")),
            )
            .await;

        assert!(matches!(twin, Err(DomainError::Conflict(_))));
    }

    /// Another tenant may name an app alike, and sees none of Acme's.
    #[tokio::test]
    async fn another_tenants_apps_are_apart() {
        let fx = fixture().await;
        let wiki = app(service_provider_row("Wiki", "https://wiki.acme.example"));
        fx.store.save(&fx.tenant, &wiki).await.unwrap();
        let globex = tenant();

        let theirs = app(service_provider_row("Wiki", "https://wiki.acme.example"));
        fx.store.save(&globex, &theirs).await.unwrap();
        let by_id = fx.store.find_by_id(&globex, wiki.id()).await.unwrap();

        assert!(by_id.is_none());
    }

    /// Acme's apps are read newest first, page by page.
    #[tokio::test]
    async fn apps_are_listed_newest_first_page_by_page() {
        let fx = fixture().await;
        for (name, created) in [("Wiki", 0), ("Chat", 10), ("Crm", 20)] {
            let row = SamlServiceProviderRow {
                created_at: at(created),
                updated_at: at(created),
                ..service_provider_row(name, &format!("https://{created}.acme.example"))
            };
            fx.store.save(&fx.tenant, &app(row)).await.unwrap();
        }

        let page_one = fx
            .store
            .list(&fx.tenant, &PageRequest::first(Limit::new(2).unwrap()))
            .await
            .unwrap();
        let page_two = fx
            .store
            .list(
                &fx.tenant,
                &PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap()),
            )
            .await
            .unwrap();

        assert_eq!(names(&page_one), ["Crm", "Chat"]);
        assert_eq!(names(&page_two), ["Wiki"]);
        assert!(!page_two.has_next());
    }

    /// An admin renames the wiki and switches it off: saving again keeps
    /// the new values, and when it was added stays.
    #[tokio::test]
    async fn saving_again_keeps_the_new_values() {
        let fx = fixture().await;
        let wiki = app(service_provider_row("Wiki", "https://wiki.acme.example"));
        fx.store.save(&fx.tenant, &wiki).await.unwrap();
        let changed = app(SamlServiceProviderRow {
            id: *wiki.id(),
            name: Label::new("name", "Team wiki").unwrap(),
            status: ConnectionStatus::Disabled,
            updated_at: at(5),
            ..service_provider_row("Wiki", "https://wiki.acme.example")
        });

        fx.store.save(&fx.tenant, &changed).await.unwrap();

        let found = fx.store.find_by_id(&fx.tenant, wiki.id()).await.unwrap();
        assert_same(&found.unwrap(), &changed);
    }

    /// A removed app is gone, and removing it again is no error.
    #[tokio::test]
    async fn a_deleted_app_is_gone() {
        let fx = fixture().await;
        let wiki = app(service_provider_row("Wiki", "https://wiki.acme.example"));
        fx.store.save(&fx.tenant, &wiki).await.unwrap();

        fx.store.delete(&fx.tenant, wiki.id()).await.unwrap();
        fx.store.delete(&fx.tenant, wiki.id()).await.unwrap();

        assert!(
            fx.store
                .find_by_id(&fx.tenant, wiki.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// An app whose stored assertion address uses HTTP fails to load as
    /// corrupt storage.
    #[tokio::test]
    async fn settings_with_a_broken_address_are_refused() {
        let fx = fixture().await;
        let wiki = app(service_provider_row("Wiki", "https://wiki.acme.example"));
        fx.store.save(&fx.tenant, &wiki).await.unwrap();
        fx.db
            .tamper(
                "UPDATE saml_service_providers \
                 SET settings = jsonb_set(settings, '{value,acs_urls}', '[\"http://evil.example\"]')",
            )
            .await;

        let read = fx.store.find_by_id(&fx.tenant, wiki.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}

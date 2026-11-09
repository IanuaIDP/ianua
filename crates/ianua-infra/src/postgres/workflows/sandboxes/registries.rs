//! The image registries a tenant allowed, each table row under row-level
//! security. A host is kept once per tenant, so two administrators allowing
//! it at once cannot both add it.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::workflows::ImageRegistryStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::workflows::sandbox::image::RegistryHost;
use ianua_domain::domains::workflows::sandbox::registry::ImageRegistry;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::ImageRegistryId;

use self::record::{RegistryColumns, RegistryRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a host once on a tenant's list.
const HOST_ONCE: &str = "image_registries_host_once";

/// The Postgres store of image registries.
pub struct PgImageRegistryStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgImageRegistryStore {}

impl PgImageRegistryStore {
    /// A store keeping registries in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

fn rebuilt_all(
    records: Vec<RegistryRecord>,
) -> Result<Vec<ImageRegistry<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(RegistryRecord::into_registry)
        .collect()
}

#[async_trait]
impl ImageRegistryStore for PgImageRegistryStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ImageRegistryId,
    ) -> Result<Option<ImageRegistry<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RegistryRecord,
                    "queries/image_registries/by_id.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(RegistryRecord::into_registry).transpose()
    }

    async fn find_by_host(
        &self,
        tenant_id: &ScopedTenant,
        host: &RegistryHost,
    ) -> Result<Option<ImageRegistry<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RegistryRecord,
                    "queries/image_registries/by_host.sql",
                    tenant_id.as_uuid(),
                    host.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(RegistryRecord::into_registry).transpose()
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<ImageRegistry<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RegistryRecord,
                    "queries/image_registries/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt_all(records)
    }

    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        registry: &ImageRegistry<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let c = RegistryColumns::of(registry)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/image_registries/insert.sql",
                    c.id,
                    tenant_id.as_uuid(),
                    c.host,
                    c.login,
                    c.username,
                    c.password,
                    c.allowed_by,
                    c.created_at,
                    c.updated_at,
                )
                .execute(connection)
                .await;
                unique_on(attempt, HOST_ONCE)
            },
        )
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-the-registry-is-allowed-already",
                "the tenant allowed this registry already"
            ))),
        }
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &ImageRegistryId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/image_registries/delete.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::control::WorkflowControl;
    use ianua_domain::domains::workflows::sandbox::registry::{
        AllowRegistryParams, RegistryLogin, RegistryUsername,
    };
    use ianua_domain::test_support::authority::assumed_authority;
    use ianua_domain::types::{SealedSecret, TenantId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::workflows::ann;

    const MANAGES: [SystemPermission; 1] = [SystemPermission::Workflows(WorkflowAction::Manage)];

    /// A store over a fresh database, and one tenant in it.
    struct Fixture {
        _db: TestDb,
        registries: PgImageRegistryStore,
        tenant: ScopedTenant,
    }

    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            registries: PgImageRegistryStore::new(Arc::clone(&db.databases)),
            tenant: ScopedTenant::for_background(TenantId::new()),
            _db: db,
        }
    }

    /// `host`, allowed by Ann in `tenant` with a robot login sealed.
    fn allowed(tenant: &ScopedTenant, host: &str) -> ImageRegistry<ResolvedTenant> {
        let authority = assumed_authority(&ann(), **tenant, &MANAGES, &[]);
        ImageRegistry::allow(
            AllowRegistryParams {
                id: ImageRegistryId::new(),
                host: RegistryHost::new(host).unwrap(),
                login: RegistryLogin::Password {
                    username: RegistryUsername::new("robot$acme").unwrap(),
                    password: SealedSecret::new("v1.AAECAwQF").unwrap(),
                },
            },
            &WorkflowControl::new(authority),
        )
        .unwrap()
    }

    /// Ann allows Acme's registry. It reads back by id, by host and in the
    /// list with its sealed login; another tenant finds none of it.
    #[tokio::test]
    async fn an_allowed_registry_reads_back_as_it_was_kept() {
        let f = fixture().await;
        let registry = allowed(&f.tenant, "registry.acme.example");
        let other = ScopedTenant::for_background(TenantId::new());

        f.registries.insert(&f.tenant, &registry).await.unwrap();

        let by_id = f.registries.find_by_id(&f.tenant, registry.id()).await;
        let by_host = f.registries.find_by_host(&f.tenant, registry.host()).await;
        let listed = f.registries.list(&f.tenant).await.unwrap();
        let elsewhere = f.registries.find_by_host(&other, registry.host()).await;
        assert_eq!(by_id.unwrap().unwrap().login(), registry.login());
        assert_eq!(by_host.unwrap().unwrap().id(), registry.id());
        assert_eq!(listed.len(), 1);
        assert!(elsewhere.unwrap().is_none());
    }

    /// The same host allowed twice is a conflict.
    #[tokio::test]
    async fn a_host_is_kept_once() {
        let f = fixture().await;
        let first = allowed(&f.tenant, "registry.acme.example");
        let second = allowed(&f.tenant, "registry.acme.example");
        f.registries.insert(&f.tenant, &first).await.unwrap();

        let refused = f.registries.insert(&f.tenant, &second).await;

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
    }

    /// A removed registry is gone.
    #[tokio::test]
    async fn a_deleted_registry_is_gone() {
        let f = fixture().await;
        let registry = allowed(&f.tenant, "ghcr.io");
        f.registries.insert(&f.tenant, &registry).await.unwrap();

        f.registries.delete(&f.tenant, registry.id()).await.unwrap();

        let found = f.registries.find_by_id(&f.tenant, registry.id()).await;
        assert!(found.unwrap().is_none());
    }
}

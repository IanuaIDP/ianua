//! Each tenant's setup, in the platform database beside the tenant: a
//! setup runs before a tenant with a database of its own has that
//! database, so it is read and written as platform work.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::tenant::{SetupVersion, TenantSetupStore};
use ianua_domain::domains::tenant::setup::TenantSetup;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use self::record::{SetupColumns, SetupRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// Persists provisioning progress in the platform database before tenant databases exist.
pub struct PgTenantSetupStore {
    databases: Arc<Databases>,
}

impl PgTenantSetupStore {
    /// The setups kept in `databases`' platform database.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl TenantSetupStore for PgTenantSetupStore {
    async fn find_many(&self, tenant_ids: &[TenantId]) -> Result<Vec<TenantSetup>, DomainError> {
        if tenant_ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<_> = tenant_ids.iter().map(|id| *id.as_uuid()).collect();
        let records = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_as!(SetupRecord, "queries/tenant_setups/by_tenants.sql", &ids)
                .fetch_all(connection)
                .await
        })
        .await?;
        records.into_iter().map(SetupRecord::into_setup).collect()
    }

    async fn find(&self, tenant_id: &TenantId) -> Result<Option<TenantSetup>, DomainError> {
        let record = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_as!(
                SetupRecord,
                "queries/tenant_setups/by_tenant.sql",
                tenant_id.as_uuid()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record.map(SetupRecord::into_setup).transpose()
    }

    async fn save(&self, setup: &TenantSetup) -> Result<(), DomainError> {
        let columns = SetupColumns::of(setup);
        let added = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_scalar!(
                "queries/tenant_setups/save.sql",
                columns.tenant_id,
                &columns.planned,
                &columns.done,
                columns.failed_step,
                columns.failed_reason,
                columns.started_at,
                columns.updated_at,
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        added.map(|_| ()).ok_or_else(|| {
            DomainError::conflict(message!(
                "infra-the-tenant-has-a-setup-already",
                "the tenant has a setup already"
            ))
        })
    }

    async fn save_unchanged_since(
        &self,
        setup: &TenantSetup,
        read: SetupVersion,
    ) -> Result<SetupVersion, DomainError> {
        let columns = SetupColumns::of(setup);
        let stored = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_scalar!(
                "queries/tenant_setups/save_unchanged_since.sql",
                columns.tenant_id,
                read.changed_at(),
                &columns.done,
                columns.failed_step,
                columns.failed_reason,
                columns.updated_at,
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        stored.map(SetupVersion::stored).ok_or_else(|| {
            DomainError::conflict(message!(
                "infra-the-tenant-setup-changed-since-it",
                "the tenant setup changed since it was read, or is gone"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::organization::OrganizationStore as _;
    use ianua_app::ports::tenant::TenantStore as _;
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::domains::tenant::lifecycle::{Tenant, TenantRow};
    use ianua_domain::domains::tenant::setup::SetupStep;
    use ianua_domain::domains::tenant::status::TenantStatus;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::shared::model::steps::RunOutcome;
    use ianua_domain::types::UntrustedText;

    use super::*;
    use crate::postgres::organization::PgOrganizationStore;
    use crate::postgres::tenant::PgTenantStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::organization::organization_row;
    use crate::test_support::rows::tenant::tenant_row;

    /// A tenant still provisioning, saved with its organization.
    async fn saved_tenant(db: &TestDb) -> Tenant {
        let organization = Organization::reconstitute(organization_row("acme", "acme")).unwrap();
        PgOrganizationStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&organization)
            .await
            .unwrap();
        let tenant = Tenant::reconstitute(TenantRow {
            status: TenantStatus::Provisioning,
            ..tenant_row(*organization.id(), "acme")
        })
        .unwrap();
        PgTenantStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&tenant)
            .await
            .unwrap();
        tenant
    }

    /// A tenant's setup reads back as it was kept: its steps, the ones
    /// done in order, and none failed.
    #[tokio::test]
    async fn a_saved_setup_reads_back() {
        let db = TestDb::fresh().await;
        let store = PgTenantSetupStore::new(Arc::clone(&db.databases));
        let tenant = saved_tenant(&db).await;
        store
            .save(&TenantSetup::begin(&tenant).unwrap())
            .await
            .unwrap();
        let mut setup = store.find(tenant.id()).await.unwrap().unwrap();
        let read = SetupVersion::of(&setup);
        setup.finish(SetupStep::SigningKey).unwrap();

        store.save_unchanged_since(&setup, read).await.unwrap();

        let found = store.find(tenant.id()).await.unwrap().unwrap();
        assert_eq!(found.planned(), setup.planned());
        assert_eq!(found.done(), [SetupStep::SigningKey]);
        assert_eq!(found.ready(), setup.ready());
    }

    /// Only requested setups are returned once; missing tenants and an empty
    /// request do not introduce records from elsewhere on the platform.
    #[tokio::test]
    async fn setup_batches_keep_only_requested_tenants() {
        let db = TestDb::fresh().await;
        let store = PgTenantSetupStore::new(Arc::clone(&db.databases));
        let first = saved_tenant(&db).await;
        let second = Tenant::reconstitute(TenantRow {
            status: TenantStatus::Provisioning,
            ..tenant_row(*first.organization_id(), "second")
        })
        .unwrap();
        PgTenantStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&second)
            .await
            .unwrap();
        for tenant in [&first, &second] {
            store
                .save(&TenantSetup::begin(tenant).unwrap())
                .await
                .unwrap();
        }

        let found = store
            .find_many(&[*first.id(), TenantId::new(), *first.id()])
            .await
            .unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].tenant_id(), first.id());
        assert!(store.find_many(&[]).await.unwrap().is_empty());
    }

    /// Saving a completed signing-key step makes a save from the same
    /// original version conflict, preserving only the signing-key completion.
    #[tokio::test]
    async fn a_save_over_a_version_that_moved_on_is_refused() {
        let db = TestDb::fresh().await;
        let store = PgTenantSetupStore::new(Arc::clone(&db.databases));
        let tenant = saved_tenant(&db).await;
        store
            .save(&TenantSetup::begin(&tenant).unwrap())
            .await
            .unwrap();
        let mut keyed = store.find(tenant.id()).await.unwrap().unwrap();
        let mut roled = store.find(tenant.id()).await.unwrap().unwrap();
        let read = SetupVersion::of(&keyed);
        keyed.finish(SetupStep::SigningKey).unwrap();
        roled.finish(SetupStep::StartingRoles).unwrap();

        let first = store.save_unchanged_since(&keyed, read).await;
        let second = store.save_unchanged_since(&roled, read).await;

        assert!(first.is_ok());
        assert!(matches!(second, Err(DomainError::Conflict(_))));
        let found = store.find(tenant.id()).await.unwrap().unwrap();
        assert_eq!(found.done(), [SetupStep::SigningKey]);
    }

    /// The step that lost its race, recorded again over the setup read
    /// afresh, saves, and both steps count. Every save moves the version
    /// on, so the version it gave back is the one found.
    #[tokio::test]
    async fn a_save_over_the_current_version_is_kept() {
        let db = TestDb::fresh().await;
        let store = PgTenantSetupStore::new(Arc::clone(&db.databases));
        let tenant = saved_tenant(&db).await;
        store
            .save(&TenantSetup::begin(&tenant).unwrap())
            .await
            .unwrap();
        let mut keyed = store.find(tenant.id()).await.unwrap().unwrap();
        let read = SetupVersion::of(&keyed);
        keyed.finish(SetupStep::SigningKey).unwrap();
        let moved = store.save_unchanged_since(&keyed, read).await.unwrap();
        let mut roled = store.find(tenant.id()).await.unwrap().unwrap();
        let read_afresh = SetupVersion::of(&roled);
        roled.finish(SetupStep::StartingRoles).unwrap();

        let saved = store
            .save_unchanged_since(&roled, read_afresh)
            .await
            .unwrap();

        let found = store.find(tenant.id()).await.unwrap().unwrap();
        assert_eq!(read_afresh, moved);
        assert_ne!(saved, moved);
        assert_eq!(SetupVersion::of(&found), saved);
        assert_eq!(
            found.done(),
            [SetupStep::SigningKey, SetupStep::StartingRoles]
        );
    }

    /// Inserting a second setup for a tenant returns a conflict and preserves
    /// the completed signing-key step in its existing setup.
    #[tokio::test]
    async fn a_second_new_setup_is_refused() {
        let db = TestDb::fresh().await;
        let store = PgTenantSetupStore::new(Arc::clone(&db.databases));
        let tenant = saved_tenant(&db).await;
        store
            .save(&TenantSetup::begin(&tenant).unwrap())
            .await
            .unwrap();
        let mut kept = store.find(tenant.id()).await.unwrap().unwrap();
        let read = SetupVersion::of(&kept);
        kept.finish(SetupStep::SigningKey).unwrap();
        store.save_unchanged_since(&kept, read).await.unwrap();

        let again = store.save(&TenantSetup::begin(&tenant).unwrap()).await;

        assert!(matches!(again, Err(DomainError::Conflict(_))));
        let found = store.find(tenant.id()).await.unwrap().unwrap();
        assert_eq!(found.done(), [SetupStep::SigningKey]);
    }

    /// A setup that failed reads back failed, with its step and reason.
    #[tokio::test]
    async fn a_failed_setup_reads_back_failed() {
        let db = TestDb::fresh().await;
        let store = PgTenantSetupStore::new(Arc::clone(&db.databases));
        let tenant = saved_tenant(&db).await;
        let mut setup = TenantSetup::begin(&tenant).unwrap();
        setup
            .fail(
                SetupStep::SigningKey,
                UntrustedText::record("no key service"),
            )
            .unwrap();

        store.save(&setup).await.unwrap();

        let found = store.find(tenant.id()).await.unwrap().unwrap();
        assert_eq!(found.outcome(), RunOutcome::Failed);
        let (step, why) = found.failure().unwrap();
        assert_eq!(
            (step, why.as_str()),
            (SetupStep::SigningKey, "no key service")
        );
    }

    /// A tenant with no setup finds none.
    #[tokio::test]
    async fn a_tenant_without_a_setup_finds_none() {
        let db = TestDb::fresh().await;
        let store = PgTenantSetupStore::new(Arc::clone(&db.databases));

        let found = store.find(&TenantId::new()).await.unwrap();

        assert!(found.is_none());
    }

    /// Reading a setup row with activation as its only completed step
    /// returns an infrastructure error for corrupt progress.
    #[tokio::test]
    async fn a_row_activated_too_early_is_refused() {
        let db = TestDb::fresh().await;
        let store = PgTenantSetupStore::new(Arc::clone(&db.databases));
        let tenant = saved_tenant(&db).await;
        store
            .save(&TenantSetup::begin(&tenant).unwrap())
            .await
            .unwrap();
        db.tamper(&format!(
            "UPDATE tenant_setups SET done = ARRAY['activate'] WHERE tenant_id = '{}'",
            tenant.id()
        ))
        .await;

        let found = store.find(tenant.id()).await;

        assert!(matches!(found, Err(DomainError::Infrastructure(_))));
    }
}

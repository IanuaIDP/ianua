//! Each deleted tenant's teardown, in the platform database beside the
//! tenant: a teardown outlives a database of the tenant's own, so it is
//! read and written as platform work.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::tenant::{TeardownVersion, TenantTeardownStore};
use ianua_domain::domains::tenant::teardown::TenantTeardown;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use self::record::{TeardownColumns, TeardownRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The deleted tenants' teardowns.
pub struct PgTenantTeardownStore {
    databases: Arc<Databases>,
}

impl PgTenantTeardownStore {
    /// The teardowns kept in `databases`' platform database.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl TenantTeardownStore for PgTenantTeardownStore {
    async fn find(&self, tenant_id: &TenantId) -> Result<Option<TenantTeardown>, DomainError> {
        let record = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_as!(
                TeardownRecord,
                "queries/tenant_teardowns/by_tenant.sql",
                tenant_id.as_uuid()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record.map(TeardownRecord::into_teardown).transpose()
    }

    async fn save(&self, teardown: &TenantTeardown) -> Result<(), DomainError> {
        let columns = TeardownColumns::of(teardown);
        let added = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_scalar!(
                "queries/tenant_teardowns/save.sql",
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
                "infra-the-tenant-has-a-teardown-already",
                "the tenant has a teardown already"
            ))
        })
    }

    async fn save_unchanged_since(
        &self,
        teardown: &TenantTeardown,
        read: TeardownVersion,
    ) -> Result<TeardownVersion, DomainError> {
        let columns = TeardownColumns::of(teardown);
        let stored = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_scalar!(
                "queries/tenant_teardowns/save_unchanged_since.sql",
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
        stored.map(TeardownVersion::stored).ok_or_else(|| {
            DomainError::conflict(message!(
                "infra-the-tenant-teardown-changed-since-it",
                "the tenant teardown changed since it was read, or is gone"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::organization::OrganizationStore as _;
    use ianua_app::ports::tenant::TenantStore as _;
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::domains::tenant::teardown::TeardownStep;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::shared::model::steps::RunOutcome;
    use ianua_domain::types::UntrustedText;

    use super::*;
    use crate::postgres::organization::PgOrganizationStore;
    use crate::postgres::tenant::PgTenantStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::organization::organization_row;
    use crate::test_support::rows::tenant::deleted_tenant_row;

    /// A deleted tenant, saved with its organization.
    async fn saved_tenant(db: &TestDb) -> Tenant {
        let organization = Organization::reconstitute(organization_row("acme", "acme")).unwrap();
        PgOrganizationStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&organization)
            .await
            .unwrap();
        let tenant = Tenant::reconstitute(deleted_tenant_row(*organization.id(), "acme")).unwrap();
        PgTenantStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&tenant)
            .await
            .unwrap();
        tenant
    }

    /// A deleted tenant's teardown reads back as it was kept: done, with
    /// nothing failed.
    #[tokio::test]
    async fn a_saved_teardown_reads_back() {
        let db = TestDb::fresh().await;
        let store = PgTenantTeardownStore::new(Arc::clone(&db.databases));
        let tenant = saved_tenant(&db).await;
        store
            .save(&TenantTeardown::begin(&tenant).unwrap())
            .await
            .unwrap();
        let mut teardown = store.find(tenant.id()).await.unwrap().unwrap();
        let read = TeardownVersion::of(&teardown);
        teardown.finish(TeardownStep::Data).unwrap();

        store.save_unchanged_since(&teardown, read).await.unwrap();

        let found = store.find(tenant.id()).await.unwrap().unwrap();
        assert_eq!(found.planned(), [TeardownStep::Data]);
        assert_eq!(found.done(), [TeardownStep::Data]);
        assert_eq!(found.outcome(), RunOutcome::Done);
    }

    /// After a completed teardown is saved, saving a failure from the old
    /// version returns a conflict and leaves the stored teardown done.
    #[tokio::test]
    async fn a_save_over_a_version_that_moved_on_is_refused() {
        let db = TestDb::fresh().await;
        let store = PgTenantTeardownStore::new(Arc::clone(&db.databases));
        let tenant = saved_tenant(&db).await;
        store
            .save(&TenantTeardown::begin(&tenant).unwrap())
            .await
            .unwrap();
        let mut done = store.find(tenant.id()).await.unwrap().unwrap();
        let mut failed = store.find(tenant.id()).await.unwrap().unwrap();
        let read = TeardownVersion::of(&done);
        done.finish(TeardownStep::Data).unwrap();
        failed
            .fail(TeardownStep::Data, UntrustedText::record("no host"))
            .unwrap();

        let first = store.save_unchanged_since(&done, read).await;
        let second = store.save_unchanged_since(&failed, read).await;

        assert!(first.is_ok());
        assert!(matches!(second, Err(DomainError::Conflict(_))));
        let found = store.find(tenant.id()).await.unwrap().unwrap();
        assert_eq!(found.outcome(), RunOutcome::Done);
    }

    /// A save over the version just read is kept, and gives back the
    /// version the teardown is found at.
    #[tokio::test]
    async fn a_save_over_the_current_version_is_kept() {
        let db = TestDb::fresh().await;
        let store = PgTenantTeardownStore::new(Arc::clone(&db.databases));
        let tenant = saved_tenant(&db).await;
        store
            .save(&TenantTeardown::begin(&tenant).unwrap())
            .await
            .unwrap();
        let mut teardown = store.find(tenant.id()).await.unwrap().unwrap();
        let read = TeardownVersion::of(&teardown);
        teardown.finish(TeardownStep::Data).unwrap();

        let saved = store.save_unchanged_since(&teardown, read).await.unwrap();

        let found = store.find(tenant.id()).await.unwrap().unwrap();
        assert_ne!(saved, read);
        assert_eq!(TeardownVersion::of(&found), saved);
    }

    /// Inserting a second teardown for a tenant with an existing teardown
    /// returns a conflict.
    #[tokio::test]
    async fn a_second_new_teardown_is_refused() {
        let db = TestDb::fresh().await;
        let store = PgTenantTeardownStore::new(Arc::clone(&db.databases));
        let tenant = saved_tenant(&db).await;
        store
            .save(&TenantTeardown::begin(&tenant).unwrap())
            .await
            .unwrap();

        let again = store.save(&TenantTeardown::begin(&tenant).unwrap()).await;

        assert!(matches!(again, Err(DomainError::Conflict(_))));
    }

    /// A teardown that failed reads back failed, with its step and reason.
    #[tokio::test]
    async fn a_failed_teardown_reads_back_failed() {
        let db = TestDb::fresh().await;
        let store = PgTenantTeardownStore::new(Arc::clone(&db.databases));
        let tenant = saved_tenant(&db).await;
        let mut teardown = TenantTeardown::begin(&tenant).unwrap();
        teardown
            .fail(
                TeardownStep::Data,
                UntrustedText::record("no database host"),
            )
            .unwrap();

        store.save(&teardown).await.unwrap();

        let found = store.find(tenant.id()).await.unwrap().unwrap();
        assert_eq!(found.outcome(), RunOutcome::Failed);
        let (step, why) = found.failure().unwrap();
        assert_eq!(
            (step, why.as_str()),
            (TeardownStep::Data, "no database host")
        );
    }

    /// A tenant with no teardown finds none.
    #[tokio::test]
    async fn a_tenant_without_a_teardown_finds_none() {
        let db = TestDb::fresh().await;
        let store = PgTenantTeardownStore::new(Arc::clone(&db.databases));

        let found = store.find(&TenantId::new()).await.unwrap();

        assert!(found.is_none());
    }

    /// Reading a teardown row that plans database removal without moving
    /// the audit trail returns an infrastructure error.
    #[tokio::test]
    async fn a_row_removing_a_database_without_its_trail_is_refused() {
        let db = TestDb::fresh().await;
        let store = PgTenantTeardownStore::new(Arc::clone(&db.databases));
        let tenant = saved_tenant(&db).await;
        store
            .save(&TenantTeardown::begin(&tenant).unwrap())
            .await
            .unwrap();
        db.tamper(&format!(
            "UPDATE tenant_teardowns SET planned = ARRAY['data', 'database'] WHERE tenant_id = '{}'",
            tenant.id()
        ))
        .await;

        let found = store.find(tenant.id()).await;

        assert!(matches!(found, Err(DomainError::Infrastructure(_))));
    }
}

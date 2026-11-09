//! Removing a deleted tenant's rows: from its own schema when it lives in
//! one, and from the platform's tables, where its platform records and
//! anything written before it moved are kept.
//!
//! Every table with a `tenant_id` column is emptied of the tenant's rows,
//! but the audit trail, which is kept for as long as the
//! tenant's retention says, the platform's own records of the tenant, its
//! setup and teardown, and its queued jobs, which end on their own once
//! what they work on is gone. Each database's rows go in one transaction.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::tenant::TenantDataPurger;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::tenant_databases::purge as rows;
use crate::postgres::foundation::unit::scoped;
use crate::postgres::tenant::databases::schema_of;

/// The tables a tenant's purge leaves as they are, besides the audit
/// trail's, which no purge empties.
const KEPT: &[&str] = &[
    "event_outbox",
    "audit_exports",
    "scheduled_jobs",
    "tenant_setups",
    "tenant_teardowns",
    "tenant_databases",
];

/// Removes deleted tenants' rows.
pub struct PgTenantDataPurger {
    databases: Arc<Databases>,
}

impl PgTenantDataPurger {
    /// A purger of the tenants' rows in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Removes `tenant`'s rows from the database `scope` reaches.
    async fn purged_in(&self, tenant: &TenantId, scope: RowScope) -> Result<u64, DomainError> {
        let id = *tenant.as_uuid();
        scoped(&self.databases, scope, async |connection| {
            rows::purge(connection, id, KEPT).await
        })
        .await
    }

    /// Whether `tenant` lives in a schema of its own, as the registry
    /// records it, routed there on this node when it was not yet.
    async fn routed_apart(&self, tenant: &TenantId) -> Result<bool, DomainError> {
        let Some(schema) = schema_of(&self.databases, tenant).await? else {
            return Ok(false);
        };
        if !self.databases.lives_apart(tenant) {
            let routed = self.databases.schema_of_platform(schema.name())?;
            self.databases.register(*tenant, routed);
        }
        Ok(true)
    }
}

#[async_trait]
impl TenantDataPurger for PgTenantDataPurger {
    async fn purge(&self, tenant_id: &TenantId) -> Result<(), DomainError> {
        if self.routed_apart(tenant_id).await? {
            self.purged_in(tenant_id, RowScope::Tenant(*tenant_id))
                .await?;
        }
        self.purged_in(tenant_id, RowScope::Platform).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, PageRequest, SortOrder};
    use ianua_app::ports::audit::{AuditLogFilter, TenantAuditLogStore as _};
    use ianua_app::ports::authorization::RoleStore as _;
    use ianua_app::tenancy::ScopedTenant;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::RoleId;

    use super::*;
    use crate::postgres::audit::PgTenantAuditLogStore;
    use crate::postgres::authorization::PgRoleStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::audit::{
        failed_sign_in, recorded, saved_organization, saved_tenant_of,
    };
    use crate::test_support::rows::authorization::role;

    /// A tenant holding a role and a record.
    async fn holding(db: &TestDb) -> (ScopedTenant, RoleId) {
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        let admin = role("Admin");
        PgRoleStore::new(Arc::clone(&db.databases))
            .save(&tenant, &admin)
            .await
            .unwrap();
        recorded(&db.databases, vec![failed_sign_in(*tenant, 1)]).await;
        (tenant, *admin.id())
    }

    async fn has_role(db: &TestDb, tenant: &ScopedTenant, id: &RoleId) -> bool {
        PgRoleStore::new(Arc::clone(&db.databases))
            .find_by_id(tenant, id)
            .await
            .unwrap()
            .is_some()
    }

    async fn records(db: &TestDb, tenant: &ScopedTenant) -> usize {
        PgTenantAuditLogStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .query(
                tenant,
                &AuditLogFilter::default(),
                &SortOrder::default(),
                &PageRequest::first(Limit::new(50).unwrap()),
            )
            .await
            .unwrap()
            .items
            .len()
    }

    /// A deleted tenant's rows go and its trail stays, and another
    /// tenant's rows are left alone.
    #[tokio::test]
    async fn a_tenants_rows_go_and_its_trail_stays() {
        let db = TestDb::fresh().await;
        let (gone, gone_role) = holding(&db).await;
        let (kept, kept_role) = holding(&db).await;

        PgTenantDataPurger::new(Arc::clone(&db.databases))
            .purge(&gone)
            .await
            .unwrap();

        assert!(!has_role(&db, &gone, &gone_role).await);
        assert_eq!(records(&db, &gone).await, 1);
        assert!(has_role(&db, &kept, &kept_role).await);
    }

    /// A purge run again finds nothing more to remove.
    #[tokio::test]
    async fn a_purge_run_again_removes_nothing_more() {
        let db = TestDb::fresh().await;
        let (gone, _) = holding(&db).await;
        let purger = PgTenantDataPurger::new(Arc::clone(&db.databases));
        purger.purge(&gone).await.unwrap();

        let again = purger.purge(&gone).await;

        assert!(again.is_ok());
        assert_eq!(records(&db, &gone).await, 1);
    }
}

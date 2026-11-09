//! A deleted tenant's audit trail brought back from its own schema to the
//! platform's tables before the schema is dropped, so the record of what
//! happened in the tenant outlives it for as long as its retention says.
//!
//! First, as the audit purge's role, what the schema's retention purged is
//! removed from the platform's older copy ([`trail::follow_anchor`]); then
//! the rest is merged ([`trail::merge`]) in one transaction under the
//! tenant's purge and chain locks. Each step run again adds nothing, so a
//! retry is safe. A tenant on the platform's tables has nothing to move.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::audit::AuditTrailMover;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::tenant_databases::trail;
use crate::postgres::foundation::unit::scoped;
use crate::postgres::tenant::databases::schema_of;

/// Moves deleted tenants' audit trails to the platform's tables.
pub struct PgAuditTrailMover {
    databases: Arc<Databases>,
    audit_purge: Arc<Databases>,
}

impl PgAuditTrailMover {
    /// A mover of the trails in `databases`, removing what a schema's purge
    /// removed through `audit_purge`, the audit purge's role's databases.
    #[must_use]
    pub fn new(databases: Arc<Databases>, audit_purge: Arc<Databases>) -> Self {
        Self {
            databases,
            audit_purge,
        }
    }
}

#[async_trait]
impl AuditTrailMover for PgAuditTrailMover {
    async fn move_to_platform(&self, tenant_id: &TenantId) -> Result<(), DomainError> {
        let Some(schema) = schema_of(&self.databases, tenant_id).await? else {
            return Ok(());
        };
        let id = *tenant_id.as_uuid();
        scoped(
            &self.audit_purge,
            RowScope::Tenant(*tenant_id),
            async |connection| trail::follow_anchor(connection, id, &schema).await,
        )
        .await?;
        scoped(&self.databases, RowScope::Platform, async |connection| {
            trail::merge(connection, id, &schema).await
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, PageRequest, SortOrder};
    use ianua_app::ports::audit::{
        AuditLogFilter, AuditRetentionStore as _, TenantAuditLogStore as _,
    };
    use ianua_app::ports::tenant::{ProvisionDatabaseRequest, TenantDatabaseProvisioner as _};
    use ianua_app::tenancy::ScopedTenant;
    use ianua_domain::domains::tenant::provisioning::infrastructure::{
        DeploymentRegion, IsolationLevel, Placement, TenantResidency,
    };
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::bus::MemoryBus;
    use crate::postgres::audit::{PgAuditRetentionStore, PgTenantAuditLogStore};
    use crate::postgres::tenant::PgTenantDatabaseProvisioner;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::audit::{
        chain_heads, failed_sign_in, recorded, saved_organization, saved_tenant_of,
    };

    /// A tenant with one record, and the mover on its database.
    async fn fixture() -> (TestDb, ScopedTenant, PgAuditTrailMover) {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        recorded(&db.databases, vec![failed_sign_in(*tenant, 1)]).await;
        let mover = PgAuditTrailMover::new(Arc::clone(&db.databases), Arc::clone(&db.audit_purge));
        (db, tenant, mover)
    }

    /// Gives `tenant` a schema of its own.
    async fn moved_apart(db: &TestDb, tenant: &TenantId) {
        let residency = TenantResidency::new(
            Placement::Platform {
                region: DeploymentRegion::EuCentral1,
            },
            IsolationLevel::DedicatedSchema,
        )
        .unwrap();
        PgTenantDatabaseProvisioner::new(
            Arc::clone(&db.databases),
            Arc::clone(&db.audit_purge),
            db.schema_access(),
            Arc::new(MemoryBus::new(16)),
        )
        .provision(
            tenant,
            &OrganizationId::new(),
            &ProvisionDatabaseRequest::for_residency(residency),
        )
        .await
        .unwrap();
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

    /// A tenant on the platform's tables has nothing to move.
    #[tokio::test]
    async fn a_tenant_on_the_platforms_tables_has_nothing_to_move() {
        let (db, tenant, mover) = fixture().await;

        mover.move_to_platform(&tenant).await.unwrap();

        assert_eq!(records(&db, &tenant).await, 1);
    }

    /// A tenant's records kept in its schema reach the platform's tables,
    /// each once however often the move runs.
    #[tokio::test]
    async fn a_tenants_trail_reaches_the_platforms_tables_once() {
        let (db, tenant, mover) = fixture().await;
        moved_apart(&db, &tenant).await;
        recorded(&db.databases, vec![failed_sign_in(*tenant, 2)]).await;

        mover.move_to_platform(&tenant).await.unwrap();
        mover.move_to_platform(&tenant).await.unwrap();
        db.databases.deregister(&tenant);

        assert_eq!(records(&db, &tenant).await, 2);
    }

    /// After two of four records are purged in the tenant's schema, moving
    /// its trail to the platform twice leaves two records there.
    #[tokio::test]
    async fn records_purged_in_the_schema_stay_gone_once_moved() {
        let (db, tenant, mover) = fixture().await;
        moved_apart(&db, &tenant).await;
        let later = (2..=4).map(|s| failed_sign_in(*tenant, s)).collect();
        recorded(&db.databases, later).await;
        PgAuditRetentionStore::new(Arc::clone(&db.audit_purge), chain_heads())
            .purge_before(&tenant, at(3))
            .await
            .unwrap();

        mover.move_to_platform(&tenant).await.unwrap();
        mover.move_to_platform(&tenant).await.unwrap();
        db.databases.deregister(&tenant);

        assert_eq!(records(&db, &tenant).await, 2);
    }
}

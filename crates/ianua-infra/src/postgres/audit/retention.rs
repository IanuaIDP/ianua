//! Removing a tenant's audit records once their retention ended.
//!
//! The records are only ever added. The app's role cannot remove one at
//! all: the purge signs in as a role of its own, the only one that holds a
//! delete on them, and row-level security holds it to the tenant its
//! transaction is scoped to (postgres/foundation/roles.rs). So the store
//! reaches the database only through the audit purge's own databases.
//!
//! The purge removes the oldest stretch of the tenant's chain that
//! happened before the cutoff, under the tenant's purge lock, and keeps
//! the hash of the last record removed as the chain's anchor in the same
//! transaction, so the records left still link to something and a purge
//! never reads as a break. The anchor is sealed under the anchors' own
//! key, and the walk starts from it only when the seal holds.
//!
//! A tenant is purged where the registry says it lives, read afresh for
//! every purge, and the purge is refused when the tenant moved between
//! that read and the purge's lock, so the copy of the trail nobody reads
//! is never the one purged.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::audit::AuditRetentionStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::errors::DomainError;
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::crypto::AuditChainSeals;
use crate::postgres::foundation::audit_chain;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;
use crate::postgres::tenant::databases::refresh;

/// The Postgres purge of audit records past their retention.
pub struct PgAuditRetentionStore {
    audit_purge: Arc<Databases>,
    heads: AuditChainSeals,
}

impl PgAuditRetentionStore {
    /// A purge of the audit records reached through `audit_purge`, the
    /// audit purge's role's databases ([`Databases::audit_purge`]), sealing
    /// each anchor it leaves with `heads`.
    #[must_use]
    pub fn new(audit_purge: Arc<Databases>, heads: AuditChainSeals) -> Self {
        Self { audit_purge, heads }
    }

    /// Removes `tenant`'s oldest records from before `cutoff`, keeps the
    /// last one removed as the chain's sealed anchor, and answers how many
    /// went.
    async fn purged(
        &self,
        connection: &mut PgConnection,
        tenant: Uuid,
        cutoff: OffsetDateTime,
    ) -> Result<u64, sqlx::Error> {
        let last = sqlx::query_file!("queries/audit_records/last_expired.sql", tenant, cutoff)
            .fetch_optional(&mut *connection)
            .await?;
        let Some(last) = last else {
            return Ok(0);
        };
        let removed =
            sqlx::query_file!("queries/audit_records/remove_expired.sql", tenant, last.seq)
                .execute(&mut *connection)
                .await?
                .rows_affected();
        let seal = audit_chain::anchor_seal(&self.heads, tenant, last.seq, &last.entry_hash);
        sqlx::query_file!(
            "queries/audit_chain_anchors/save.sql",
            tenant,
            last.seq,
            &last.entry_hash,
            cutoff,
            seal.as_slice()
        )
        .execute(connection)
        .await?;
        Ok(removed)
    }
}

impl TenantScoped for PgAuditRetentionStore {}

#[async_trait]
impl AuditRetentionStore for PgAuditRetentionStore {
    async fn purge_before(
        &self,
        tenant_id: &ScopedTenant,
        cutoff: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        refresh(&self.audit_purge, tenant_id).await?;
        let routed = Routed::from(self.audit_purge.lives_apart(tenant_id));
        let tenant = *tenant_id.as_uuid();
        scoped(
            &self.audit_purge,
            RowScope::from(tenant_id),
            async |connection| {
                audit_chain::lock_purges(&mut *connection, tenant).await?;
                ensure_routed(&mut *connection, tenant, routed).await?;
                self.purged(connection, tenant, cutoff).await
            },
        )
        .await
    }
}

/// Where a purge was routed: to the platform's shared tables, or to the
/// tenant's schema of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Routed {
    Shared,
    Apart,
}

impl From<bool> for Routed {
    /// The routing a registry's answer of whether the tenant lives apart
    /// names.
    fn from(apart: bool) -> Self {
        if apart {
            return Self::Apart;
        }
        Self::Shared
    }
}

/// Refuses the purge when `tenant` no longer lives where it was `routed`:
/// it moved since the registry was read, and the copy reached is not the
/// one read. Read under the purge lock, which a move takes too. The tenant
/// is purged next time.
async fn ensure_routed(
    connection: &mut PgConnection,
    tenant: Uuid,
    routed: Routed,
) -> Result<(), sqlx::Error> {
    let held = sqlx::query_file_scalar!("queries/tenant_databases/held.sql", tenant)
        .fetch_one(connection)
        .await?;
    if Routed::from(held) == routed {
        return Ok(());
    }
    Err(sqlx::Error::InvalidArgument(
        "the tenant moved since its purge was routed; it is purged next time".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ianua_app::listing::{Limit, PageRequest, SortOrder};
    use ianua_app::ports::audit::{AuditLogFilter, TenantAuditLogStore};
    use ianua_app::ports::runtime::{Settlement, atomically};
    use ianua_app::ports::tenant::{ProvisionDatabaseRequest, TenantDatabaseProvisioner as _};
    use ianua_domain::domains::tenant::provisioning::infrastructure::{
        DeploymentRegion, IsolationLevel, Placement, TenantResidency,
    };
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::bus::MemoryBus;
    use crate::postgres::audit::PgTenantAuditLogStore;
    use crate::postgres::foundation::unit::PgUnitOfWork;
    use crate::postgres::tenant::PgTenantDatabaseProvisioner;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::audit::{
        chain_heads, failed_sign_in, recorded, saved_organization, saved_tenant_of,
    };

    struct Fixture {
        db: TestDb,
        tenant: ScopedTenant,
        other: ScopedTenant,
        store: PgAuditRetentionStore,
    }

    /// A fresh database with two tenants of Acme, each holding records from
    /// seconds 1 to 4, and the purge on it, signed in as the purge's role.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        let other = saved_tenant_of(&db.databases, organization).await;
        for held in [&tenant, &other] {
            let events = (1..=4).map(|s| failed_sign_in(**held, s)).collect();
            recorded(&db.databases, events).await;
        }
        let store = PgAuditRetentionStore::new(Arc::clone(&db.audit_purge), chain_heads());
        Fixture {
            db,
            tenant,
            other,
            store,
        }
    }

    async fn left(db: &Fixture, tenant: &ScopedTenant) -> usize {
        PgTenantAuditLogStore::new(Arc::clone(&db.db.databases), DomainLimits::default())
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

    /// Gives `tenant` a schema of its own, its trail so far copied in.
    async fn moved_apart(db: &TestDb, tenant: &ScopedTenant) {
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

    /// A purge removes the tenant's records before the cutoff, says how
    /// many went, and leaves another tenant's alone.
    #[tokio::test]
    async fn a_purge_removes_the_records_before_its_cutoff() {
        let db = fixture().await;

        let removed = db.store.purge_before(&db.tenant, at(3)).await.unwrap();

        assert_eq!(removed, 2);
        assert_eq!(left(&db, &db.tenant).await, 2);
        assert_eq!(left(&db, &db.other).await, 4);
    }

    /// A second purge with the same cutoff finds nothing more, and the
    /// trail goes on after a purge: a new record links past the anchor.
    #[tokio::test]
    async fn a_purge_leaves_a_chain_the_trail_goes_on_with() {
        let db = fixture().await;
        db.store.purge_before(&db.tenant, at(5)).await.unwrap();

        let again = db.store.purge_before(&db.tenant, at(5)).await.unwrap();
        recorded(&db.db.databases, vec![failed_sign_in(*db.tenant, 6)]).await;

        assert_eq!(again, 0);
        assert_eq!(left(&db, &db.tenant).await, 1);
    }

    /// Running the purge with the app's database role fails and leaves all
    /// four tenant records intact.
    #[tokio::test]
    async fn a_purge_signed_in_as_the_apps_role_removes_nothing() {
        let db = fixture().await;
        let as_the_app = PgAuditRetentionStore::new(Arc::clone(&db.db.databases), chain_heads());

        let removed = as_the_app.purge_before(&db.tenant, at(3)).await;

        assert!(removed.is_err());
        assert_eq!(left(&db, &db.tenant).await, 4);
    }

    /// Purging two records and appending one in the same unit of work
    /// completes within the timeout and leaves three records.
    #[tokio::test]
    async fn a_purge_and_its_record_are_kept_in_one_unit() {
        let db = fixture().await;

        let kept = tokio::time::timeout(
            Duration::from_secs(20),
            atomically(
                &PgUnitOfWork,
                async {
                    db.store.purge_before(&db.tenant, at(3)).await.unwrap();
                    recorded(&db.db.databases, vec![failed_sign_in(*db.tenant, 5)]).await;
                },
                |()| Settlement::Commit,
            ),
        )
        .await;

        assert!(matches!(kept, Ok(Ok(()))));
        assert_eq!(left(&db, &db.tenant).await, 3);
    }

    /// A tenant living in a schema of its own is purged there, as the
    /// purge's role, which the schema opens to it.
    #[tokio::test]
    async fn a_tenant_in_a_schema_of_its_own_is_purged_there() {
        let db = fixture().await;
        moved_apart(&db.db, &db.tenant).await;

        let removed = db.store.purge_before(&db.tenant, at(3)).await.unwrap();

        assert_eq!(removed, 2);
        assert_eq!(left(&db, &db.tenant).await, 2);
        assert_eq!(left(&db, &db.other).await, 4);
    }
}

//! What an organization uses now, counted fresh for checking a plan
//! against it.
//!
//! The organization's tenants are read through the tenant store, deleted
//! ones left out. Their counts are read in one query per database: one in
//! the platform database for every tenant living there, and one in each
//! database of a tenant living apart, all at once. The record sets of their
//! zones and the organization's notification channels are read in the
//! platform's tables. Nothing is cached, and a count that cannot be read
//! fails the whole usage, so a plan is never checked against a part of it.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::try_join_all;
use ianua_app::listing::{Limit, PageRequest, SortOrder};
use ianua_app::ports::organization::PlanUsageCounter;
use ianua_app::ports::tenant::TenantStore;
use ianua_domain::domains::organization::billing::usage::PlanUsage;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::domains::tenant::status::TenantStatus;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrganizationId, TenantId};
use uuid::Uuid;

use self::record::{Counted, UsageRecord, into_usage};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The most tenants, deleted ones too, one usage count reads. An
/// organization past it is refused rather than counted in part.
const MOST_TENANTS: u32 = 10_000;

/// The Postgres counter of what an organization uses.
pub struct PgPlanUsageCounter {
    databases: Arc<Databases>,
    tenants: Arc<dyn TenantStore>,
}

impl PgPlanUsageCounter {
    /// A counter reading `databases`, finding the organization's tenants
    /// through `tenants`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, tenants: Arc<dyn TenantStore>) -> Self {
        Self { databases, tenants }
    }

    /// Every tenant of `organization`, deleted ones too, read in one page.
    async fn tenants_of(&self, organization: &OrganizationId) -> Result<Vec<Tenant>, DomainError> {
        let page = self
            .tenants
            .list_by_organization(
                organization,
                None,
                &SortOrder::default(),
                &PageRequest::first(Limit::internal(MOST_TENANTS)),
            )
            .await?;
        if page.next.is_some() {
            return Err(DomainError::infra_msg(
                "an organization holds more tenants than one usage count reads",
            ));
        }
        Ok(page.items)
    }

    /// The counts of the tenants `ids` living in the platform database.
    async fn shared(&self, ids: Vec<Uuid>) -> Result<UsageRecord, DomainError> {
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_as!(UsageRecord, "queries/users/plan_usage.sql", ids.as_slice())
                .fetch_one(connection)
                .await
        })
        .await
    }

    /// The counts of `tenant`, read in its own database.
    async fn own(&self, tenant: TenantId) -> Result<UsageRecord, DomainError> {
        let ids = [*tenant.as_uuid()];
        scoped(
            &self.databases,
            RowScope::Tenant(tenant),
            async |connection| {
                sqlx::query_file_as!(UsageRecord, "queries/users/plan_usage.sql", ids.as_slice())
                    .fetch_one(connection)
                    .await
            },
        )
        .await
    }

    /// The most record sets any of the tenants `ids` holds.
    async fn record_sets(&self, ids: &[Uuid]) -> Result<i64, DomainError> {
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_scalar!("queries/dns_records/most_of_tenants.sql", ids)
                .fetch_one(connection)
                .await
        })
        .await
    }

    /// The channels `organization` posts notifications to.
    async fn destinations(&self, organization: &OrganizationId) -> Result<i64, DomainError> {
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_scalar!(
                "queries/org_notification_destinations/count_of_organization.sql",
                organization.as_uuid()
            )
            .fetch_one(connection)
            .await
        })
        .await
    }

    /// Each database's counts for the tenants in it: the platform's first,
    /// then every tenant's of its own.
    async fn per_database(&self, live: &[&Tenant]) -> Result<Vec<UsageRecord>, DomainError> {
        let (apart, shared): (Vec<TenantId>, Vec<TenantId>) = live
            .iter()
            .map(|tenant| *tenant.id())
            .partition(|tenant| self.databases.lives_apart(tenant));
        let shared_ids = shared.iter().map(|tenant| *tenant.as_uuid()).collect();
        let (platform, own) = futures_util::try_join!(
            self.shared(shared_ids),
            try_join_all(apart.into_iter().map(|tenant| self.own(tenant)))
        )?;
        Ok(std::iter::once(platform).chain(own).collect())
    }
}

#[async_trait]
impl PlanUsageCounter for PgPlanUsageCounter {
    async fn usage(&self, organization_id: &OrganizationId) -> Result<PlanUsage, DomainError> {
        let tenants = self.tenants_of(organization_id).await?;
        let live: Vec<&Tenant> = tenants
            .iter()
            .filter(|tenant| tenant.status() != TenantStatus::Deleted)
            .collect();
        let ids: Vec<Uuid> = live.iter().map(|tenant| *tenant.id().as_uuid()).collect();
        let (databases, dns_record_sets, notification_destinations) = futures_util::try_join!(
            self.per_database(&live),
            self.record_sets(&ids),
            self.destinations(organization_id)
        )?;
        into_usage(Counted {
            tenants: &live,
            databases,
            dns_record_sets,
            notification_destinations,
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::authorization::RoleStore;
    use ianua_app::ports::identity::UserStore;
    use ianua_app::tenancy::ScopedTenant;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::shared::config::DomainLimits;

    use super::*;
    use crate::postgres::authorization::PgRoleStore;
    use crate::postgres::identity::PgUserStore;
    use crate::postgres::tenant::PgTenantStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::audit::{saved_organization, saved_tenant_of};
    use crate::test_support::rows::authorization::role;
    use crate::test_support::rows::identity::user_row;
    use crate::test_support::rows::tenant::deleted_tenant_row;

    fn counter(databases: &Arc<Databases>) -> PgPlanUsageCounter {
        let tenants = PgTenantStore::new(Arc::clone(databases), DomainLimits::default());
        PgPlanUsageCounter::new(Arc::clone(databases), Arc::new(tenants))
    }

    async fn saved_users(databases: &Arc<Databases>, tenant: &ScopedTenant, count: usize) {
        let store = PgUserStore::new(Arc::clone(databases), DomainLimits::default());
        for _ in 0..count {
            let address = format!("u{}@acme.example", Uuid::now_v7().simple());
            let user = User::reconstitute(user_row(&address)).unwrap();
            store.save(tenant, &user).await.unwrap();
        }
    }

    async fn saved_roles(databases: &Arc<Databases>, tenant: &ScopedTenant, names: &[&str]) {
        let store = PgRoleStore::new(Arc::clone(databases));
        for name in names {
            store.save(tenant, &role(name)).await.unwrap();
        }
    }

    /// Accounts are summed over the organization's tenants; every other
    /// count is the most any one tenant holds.
    #[tokio::test]
    async fn accounts_are_summed_and_the_rest_is_the_busiest_tenant() {
        let db = TestDb::fresh().await;
        let acme = saved_organization(&db.databases).await;
        let shop = saved_tenant_of(&db.databases, acme).await;
        let blog = saved_tenant_of(&db.databases, acme).await;
        saved_users(&db.databases, &shop, 2).await;
        saved_users(&db.databases, &blog, 3).await;
        saved_roles(&db.databases, &shop, &["a", "b", "c"]).await;
        saved_roles(&db.databases, &blog, &["a"]).await;

        let usage = counter(&db.databases).usage(&acme).await.unwrap();

        assert_eq!((usage.users, usage.roles, usage.tenants), (5, 3, 2));
    }

    /// An organization with only a deleted tenant containing two users
    /// reports zero tenants and users in its plan usage.
    #[tokio::test]
    async fn a_deleted_tenant_is_not_counted() {
        let db = TestDb::fresh().await;
        let acme = saved_organization(&db.databases).await;
        let deleted = Tenant::reconstitute(deleted_tenant_row(acme, "closed-shop")).unwrap();
        PgTenantStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&deleted)
            .await
            .unwrap();
        let gone = ScopedTenant::for_background(*deleted.id());
        saved_users(&db.databases, &gone, 2).await;

        let usage = counter(&db.databases).usage(&acme).await.unwrap();

        assert_eq!((usage.users, usage.tenants), (0, 0));
    }

    /// Globex's tenant and four users contribute nothing to Acme's tenant
    /// and user counts.
    #[tokio::test]
    async fn another_organizations_tenants_are_not_counted() {
        let db = TestDb::fresh().await;
        let acme = saved_organization(&db.databases).await;
        let globex = saved_organization(&db.databases).await;
        let theirs = saved_tenant_of(&db.databases, globex).await;
        saved_users(&db.databases, &theirs, 4).await;

        let usage = counter(&db.databases).usage(&acme).await.unwrap();

        assert_eq!((usage.users, usage.tenants), (0, 0));
    }

    /// A tenant living in a database of its own is counted there, beside
    /// the tenants in the platform database.
    #[tokio::test]
    async fn a_tenant_with_its_own_database_is_counted_there() {
        let platform = TestDb::fresh().await;
        let own = TestDb::fresh().await;
        let acme = saved_organization(&platform.databases).await;
        let shop = saved_tenant_of(&platform.databases, acme).await;
        let apart = saved_tenant_of(&platform.databases, acme).await;
        platform.databases.register(*apart, own.as_dedicated());
        saved_users(&platform.databases, &shop, 1).await;
        saved_users(&platform.databases, &apart, 2).await;
        saved_roles(&platform.databases, &apart, &["a", "b"]).await;

        let usage = counter(&platform.databases).usage(&acme).await.unwrap();

        assert_eq!((usage.users, usage.roles), (3, 2));
    }

    /// An organization's tenants report the isolation they are placed on
    /// and the audit retention they keep.
    #[tokio::test]
    async fn the_tenants_placement_and_retention_are_reported() {
        let db = TestDb::fresh().await;
        let acme = saved_organization(&db.databases).await;
        let shop = saved_tenant_of(&db.databases, acme).await;
        let stored = PgTenantStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .find_by_id(&shop)
            .await
            .unwrap()
            .unwrap();

        let usage = counter(&db.databases).usage(&acme).await.unwrap();

        assert_eq!(usage.isolation_in_use, vec![stored.residency().isolation()]);
        assert_eq!(
            usage.audit_retention_days,
            stored.compliance().audit_retention_days()
        );
    }
}

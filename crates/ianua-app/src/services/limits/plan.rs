//! Plan limits looked up from storage, for work no request brought them to.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::organization::billing::plan::PlanLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use crate::ports::limits::PlanLimitsSource;
use crate::ports::organization::OrganizationStore;
use crate::ports::tenant::TenantStore;

/// Reads a tenant's plan limits from the plan of the organization that owns
/// it, the same limits a request scoped to that tenant would carry.
pub struct StoredPlanLimits {
    tenants: Arc<dyn TenantStore>,
    organizations: Arc<dyn OrganizationStore>,
}

impl StoredPlanLimits {
    /// Creates a lookup over the tenant and organization stores.
    #[must_use]
    pub fn new(tenants: Arc<dyn TenantStore>, organizations: Arc<dyn OrganizationStore>) -> Self {
        Self {
            tenants,
            organizations,
        }
    }
}

#[async_trait]
impl PlanLimitsSource for StoredPlanLimits {
    async fn for_tenant(&self, tenant_id: &TenantId) -> Result<PlanLimits, DomainError> {
        let tenant = self
            .tenants
            .find_by_id(tenant_id)
            .await?
            .ok_or(DomainError::NotFound)?;
        let organization = self
            .organizations
            .find_by_id(tenant.organization_id())
            .await?
            .ok_or(DomainError::NotFound)?;
        Ok(organization.limits())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::billing::plan::OrganizationPlan;

    use super::*;
    use crate::test_support::block_on;
    use crate::test_support::organization::{FakeOrganizationStore, org_store_with, test_org};
    use crate::test_support::tenant::{FakeTenantStore, test_tenant};

    /// Ann's tenant belongs to a Free organization, so work done for it out
    /// of any request is held to the Free limits.
    #[test]
    fn a_tenant_is_held_to_its_organizations_plan() {
        let tenant = test_tenant("acme", "acme.example.com");
        let tenant_id = *tenant.id();
        let org = test_org(*tenant.organization_id(), "acme-org");
        let source = StoredPlanLimits::new(
            Arc::new(FakeTenantStore::holding(tenant)),
            org_store_with([org]),
        );

        let limits = block_on(source.for_tenant(&tenant_id)).unwrap();

        assert_eq!(limits, OrganizationPlan::Free.default_limits());
    }

    /// A tenant whose organization is missing returns not found when its
    /// allowance is requested.
    #[test]
    fn a_tenant_with_no_organization_gets_no_allowance() {
        let tenant = test_tenant("acme", "acme.example.com");
        let tenant_id = *tenant.id();
        let source = StoredPlanLimits::new(
            Arc::new(FakeTenantStore::holding(tenant)),
            Arc::new(FakeOrganizationStore::empty()),
        );

        let result = block_on(source.for_tenant(&tenant_id));

        assert!(matches!(result, Err(DomainError::NotFound)));
    }

    /// An unknown tenant returns not found instead of a plan allowance.
    #[test]
    fn an_unknown_tenant_gets_no_allowance() {
        let source = StoredPlanLimits::new(
            Arc::new(FakeTenantStore::empty()),
            Arc::new(FakeOrganizationStore::empty()),
        );

        let result = block_on(source.for_tenant(&TenantId::new()));

        assert!(matches!(result, Err(DomainError::NotFound)));
    }
}

//! An in-memory store of egress policies, read per tenant or, as the egress
//! gateway reads them, across every tenant; and a read that always fails.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::routing::egress::{EgressPolicy, ServiceIdentity};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{EgressPolicyId, TenantId};

use crate::ports::TenantScoped;
use crate::ports::routing::{ClaimedEgressPolicy, CrossTenantEgressPolicies, EgressPolicyStore};
use crate::tenancy::ScopedTenant;
use crate::test_support::routing::held::remove_where;
use crate::test_support::{Fake, rivals};

/// In-memory egress policy store for tests, keeping each policy under the
/// tenant it was saved for. A service has at most one policy: a second one
/// for the same service is refused, as the unique index refuses it.
#[derive(Default)]
pub struct FakeEgressPolicyStore {
    policies: Mutex<Vec<(TenantId, EgressPolicy<ResolvedTenant>)>>,
}

impl TenantScoped for FakeEgressPolicyStore {}

impl FakeEgressPolicyStore {
    fn first(
        &self,
        tenant: &ScopedTenant,
        wanted: impl Fn(&EgressPolicy<ResolvedTenant>) -> bool,
    ) -> Option<EgressPolicy<ResolvedTenant>> {
        self.policies
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, policy)| owner == &**tenant && wanted(policy))
            .map(|(_, policy)| policy.clone())
    }
}

fn is(
    entry: &(TenantId, EgressPolicy<ResolvedTenant>),
    tenant: &ScopedTenant,
    id: &EgressPolicyId,
) -> bool {
    entry.0 == **tenant && entry.1.id() == id
}

#[async_trait]
impl EgressPolicyStore for FakeEgressPolicyStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        policy: &EgressPolicy<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut policies = self.policies.lock().unwrap();
        let by_service = |kept: &EgressPolicy<ResolvedTenant>| (kept.service().clone(), *kept.id());
        if policies
            .iter()
            .any(|entry| rivals(entry, tenant_id, policy, by_service))
        {
            return Err(DomainError::conflict(
                "the service already has an egress policy",
            ));
        }
        policies.retain(|entry| !is(entry, tenant_id, policy.id()));
        policies.push((**tenant_id, policy.clone()));
        Ok(())
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &EgressPolicyId,
    ) -> Result<Option<EgressPolicy<ResolvedTenant>>, DomainError> {
        Ok(self.first(tenant_id, |policy| policy.id() == id))
    }

    async fn find_by_service(
        &self,
        tenant_id: &ScopedTenant,
        service: &ServiceIdentity,
    ) -> Result<Option<EgressPolicy<ResolvedTenant>>, DomainError> {
        Ok(self.first(tenant_id, |policy| policy.service() == service))
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<EgressPolicy<ResolvedTenant>>, DomainError> {
        let mut all: Vec<_> = self
            .policies
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, _)| owner == &**tenant_id)
            .map(|(_, policy)| policy.clone())
            .collect();
        all.sort_by(|a, b| a.name().as_str().cmp(b.name().as_str()));
        Ok(all)
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &EgressPolicyId,
    ) -> Result<(), DomainError> {
        remove_where(&self.policies, |entry| is(entry, tenant_id, id));
        Ok(())
    }
}

#[async_trait]
impl CrossTenantEgressPolicies for FakeEgressPolicyStore {
    async fn claiming(
        &self,
        service: &ServiceIdentity,
    ) -> Result<Vec<ClaimedEgressPolicy>, DomainError> {
        Ok(self
            .policies
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, policy)| policy.service() == service)
            .map(|(tenant_id, policy)| ClaimedEgressPolicy {
                tenant_id: *tenant_id,
                policy: policy.clone(),
            })
            .collect())
    }
}

/// Every tenant's policies, read from a database that cannot be reached.
pub struct FailingEgressPolicies;

#[async_trait]
impl CrossTenantEgressPolicies for FailingEgressPolicies {
    async fn claiming(
        &self,
        _service: &ServiceIdentity,
    ) -> Result<Vec<ClaimedEgressPolicy>, DomainError> {
        Err(DomainError::infra_msg("the policies cannot be read"))
    }
}

impl Fake for Arc<dyn EgressPolicyStore> {
    fn fake() -> Self {
        Arc::new(FakeEgressPolicyStore::default())
    }
}

impl Fake for Arc<dyn CrossTenantEgressPolicies> {
    fn fake() -> Self {
        Arc::new(FakeEgressPolicyStore::default())
    }
}

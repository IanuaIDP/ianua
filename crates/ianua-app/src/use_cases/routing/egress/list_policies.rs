//! List egress policies: where each service may go.

use std::sync::Arc;

use ianua_domain::domains::routing::egress::EgressPolicy;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::routing::EgressPolicyStore;
use crate::use_case::Query;
use crate::use_cases::routing::lookup::ensure_may_view_routing;

/// The ports [`ListPoliciesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPoliciesPorts {
    /// Keeps the tenant's egress policies.
    pub egress_store: Arc<dyn EgressPolicyStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tenant's egress policies.
pub struct ListPoliciesUseCase {
    ports: ListPoliciesPorts,
}

impl ListPoliciesUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPoliciesPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListPoliciesUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<EgressPolicy<ResolvedTenant>>, AppError>;

    /// Every policy in the tenant, by name.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view routing.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        (): (),
    ) -> Result<Vec<EgressPolicy<ResolvedTenant>>, AppError> {
        ensure_may_view_routing(self.ports.tenant_authorities.as_ref(), caller).await?;
        self.ports
            .egress_store
            .list(&caller.tenant())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::routing::{FakeEgressPolicyStore, egress_policy_for};
    use crate::test_support::{block_on, test_ctx};

    fn list(
        authorities: FakeTenantAuthorities,
    ) -> Result<Vec<EgressPolicy<ResolvedTenant>>, AppError> {
        let policies = Arc::new(FakeEgressPolicyStore::default());
        for service in [
            "spiffe://ianua.test/ns/svc/sa/fetcher",
            "spiffe://ianua.test/ns/svc/sa/billing",
        ] {
            block_on(policies.save(&test_ctx().tenant(), &egress_policy_for(service))).unwrap();
        }
        let use_case = ListPoliciesUseCase::new(ListPoliciesPorts {
            egress_store: policies,
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), ()))
    }

    /// Acme has policies for two services. Ann lists both.
    #[test]
    fn every_policy_is_listed() {
        let policies = list(FakeTenantAuthorities::holding_everything()).unwrap();

        assert_eq!(policies.len(), 2);
    }

    /// Listing egress policies requires the routing viewing right.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let result = list(FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list egress policies.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

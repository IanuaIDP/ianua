//! Get egress policy: where one service may go.

use std::sync::Arc;

use ianua_domain::domains::routing::egress::EgressPolicy;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::EgressPolicyId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::routing::EgressPolicyStore;
use crate::use_case::Query;
use crate::use_cases::routing::lookup::{ensure_may_view_routing, existing_egress_policy};

/// The ports [`GetPolicyUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPolicyPorts {
    /// Keeps the tenant's egress policies.
    pub egress_store: Arc<dyn EgressPolicyStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one egress policy.
pub struct GetPolicyUseCase {
    ports: GetPolicyPorts,
}

impl GetPolicyUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetPolicyPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetPolicyUseCase {
    type Caller = CallerContext;
    type Input = EgressPolicyId;
    type Output = Result<EgressPolicy<ResolvedTenant>, AppError>;

    /// The tenant's policy `policy_id`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view routing.
    /// - `AppError::NotFound` when the policy is not in the tenant.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        policy_id: EgressPolicyId,
    ) -> Result<EgressPolicy<ResolvedTenant>, AppError> {
        ensure_may_view_routing(self.ports.tenant_authorities.as_ref(), caller).await?;
        existing_egress_policy(
            self.ports.egress_store.as_ref(),
            &caller.tenant(),
            &policy_id,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::routing::{FakeEgressPolicyStore, egress_policy_for};
    use crate::test_support::{block_on, test_ctx};

    fn use_case_holding(authorities: FakeTenantAuthorities) -> (GetPolicyUseCase, EgressPolicyId) {
        let policy = egress_policy_for("spiffe://ianua.test/ns/svc/sa/fetcher");
        let policies = Arc::new(FakeEgressPolicyStore::default());
        block_on(policies.save(&test_ctx().tenant(), &policy)).unwrap();
        let use_case = GetPolicyUseCase::new(GetPolicyPorts {
            egress_store: policies,
            tenant_authorities: Arc::new(authorities),
        });
        (use_case, *policy.id())
    }

    /// Ann opens the fetcher's policy. She sees it.
    #[test]
    fn a_stored_policy_is_returned() {
        let (use_case, id) = use_case_holding(FakeTenantAuthorities::holding_everything());

        let policy = block_on(use_case.execute(&test_ctx(), id)).unwrap();

        assert_eq!(policy.name().as_str(), "fetcher");
    }

    /// Ann opens a policy that does not exist. She is told it was not found.
    #[test]
    fn an_unknown_policy_is_not_found() {
        let (use_case, _) = use_case_holding(FakeTenantAuthorities::holding_everything());

        let result = block_on(use_case.execute(&test_ctx(), EgressPolicyId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Reading an egress policy requires the routing viewing right.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let (use_case, id) = use_case_holding(FakeTenantAuthorities::holding(&[]));

        let result = block_on(use_case.execute(&test_ctx(), id));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read an egress policy.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (use_case, id) = use_case_holding(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = block_on(use_case.execute(&test_ctx(), id));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

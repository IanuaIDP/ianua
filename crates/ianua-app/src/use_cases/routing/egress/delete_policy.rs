//! Delete egress policy: let a service reach nothing from now on.

use std::sync::Arc;

use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::EgressPolicyId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::routing::EgressPolicyStore;
use crate::use_case::Command;
use crate::use_cases::routing::lookup::existing_egress_policy;

/// The ports [`DeletePolicyUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeletePolicyPorts {
    /// Keeps the tenant's egress policies.
    pub egress_store: Arc<dyn EgressPolicyStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Deletes an egress policy.
pub struct DeletePolicyUseCase {
    ports: DeletePolicyPorts,
}

impl DeletePolicyUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeletePolicyPorts) -> Self {
        Self { ports }
    }
}

impl Command for DeletePolicyUseCase {
    type Caller = CallerContext;
    type Input = EgressPolicyId;
    type Output = Result<(), AppError>;

    /// Deletes the policy once the domain agrees it may go, so the service
    /// reaches nothing from its next connection on, and records
    /// `routing.egress_policy_deleted`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not delete routing.
    /// - `AppError::NotFound` when the policy is not in the tenant.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        policy_id: EgressPolicyId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = RoutingControl::new(&authority);
        control
            .ensure_may(RoutingRight::Delete)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let mut policy =
            existing_egress_policy(self.ports.egress_store.as_ref(), &tenant, &policy_id).await?;
        policy.delete(&control).map_err(AppError::from_domain)?;
        self.ports
            .egress_store
            .delete(&tenant, &policy_id)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), policy.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::routing::{FakeEgressPolicyStore, egress_policy_for};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        policies: Arc<FakeEgressPolicyStore>,
        audit: Arc<FakeEventDispatcher>,
        policy_id: EgressPolicyId,
        use_case: DeletePolicyUseCase,
    }

    fn fixture(authorities: FakeTenantAuthorities) -> Fixture {
        let policy = egress_policy_for("spiffe://ianua.test/ns/svc/sa/fetcher");
        let policies = Arc::new(FakeEgressPolicyStore::default());
        block_on(policies.save(&test_ctx().tenant(), &policy)).unwrap();
        Fixture {
            use_case: DeletePolicyUseCase::new(DeletePolicyPorts {
                egress_store: policies.clone(),
                tenant_authorities: Arc::new(authorities),
            }),
            policies,
            audit: Arc::new(FakeEventDispatcher::new()),
            policy_id: *policy.id(),
        }
    }

    fn run(f: &Fixture, policy_id: EgressPolicyId) -> Result<(), AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), policy_id),
        )
    }

    fn remaining(f: &Fixture) -> usize {
        block_on(f.policies.list(&test_ctx().tenant()))
            .unwrap()
            .len()
    }

    /// Ann deletes the fetcher's policy. It reaches nothing from now on, and
    /// the deletion is recorded.
    #[test]
    fn a_deleted_policy_is_gone_and_recorded() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        run(&f, f.policy_id).unwrap();

        assert_eq!(remaining(&f), 0);
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["routing.egress_policy_deleted"]
        );
    }

    /// Ann deletes a policy that does not exist. She is told it was not
    /// found.
    #[test]
    fn an_unknown_policy_is_not_found() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        let result = run(&f, EgressPolicyId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// The routing update right does not permit deleting an egress policy.
    /// The permission refusal leaves the policy stored.
    #[test]
    fn a_caller_without_the_delete_right_is_refused() {
        let f = fixture(FakeTenantAuthorities::holding(&[
            SystemPermission::Routing(RoutingAction::Update),
        ]));

        let result = run(&f, f.policy_id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(remaining(&f), 1);
    }

    /// A caller without the deletion right receives a permission refusal
    /// even when the requested egress policy does not exist.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_policy() {
        let f = fixture(FakeTenantAuthorities::holding(&[]));

        let result = run(&f, EgressPolicyId::new());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot delete the stored egress policy.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = run(&f, f.policy_id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(remaining(&f), 1);
    }
}

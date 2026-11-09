//! Change default action: set what the tenant's draft policy does to a
//! request no rule matches.

use std::sync::Arc;

use ianua_domain::domains::authorization::policy::action::PolicyAction;
use ianua_domain::domains::authorization::policy::set::PolicySet;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::authorization::PolicyStore;
use crate::use_case::Command;
use crate::use_cases::authorization::policies::versions::draft_edit::saved_edit;

/// The ports [`ChangeDefaultActionUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeDefaultActionPorts {
    /// Loads and saves the policy.
    pub policy_store: Arc<dyn PolicyStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes the default action of the caller's tenant's draft policy.
pub struct ChangeDefaultActionUseCase {
    ports: ChangeDefaultActionPorts,
}

impl ChangeDefaultActionUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ChangeDefaultActionPorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangeDefaultActionUseCase {
    type Caller = CallerContext;
    type Input = PolicyAction;
    type Output = Result<PolicySet, AppError>;

    /// Gives the draft the default action `action`, for the caller, and
    /// records the action before and after.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no policy.
    /// - `AppError::Forbidden` when the caller may not update the policy.
    /// - `AppError::Conflict` when the policy is not a draft.
    /// - `AppError::Internal` when the policy cannot be read or written, or
    ///   the change cannot be recorded.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        action: PolicyAction,
    ) -> Result<PolicySet, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        saved_edit(
            self.ports.policy_store.as_ref(),
            &tenant,
            auditor,
            &authority.actor(),
            |policy| {
                policy
                    .change_default_action(action, &authority)
                    .map_err(AppError::from_domain)
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{PolicySetAction, SystemPermission};
    use ianua_domain::domains::authorization::policy::status::PolicyStatus;
    use ianua_domain::types::Text;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakePolicyStore, policy_in};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The tenant's policy store, holding a policy in `status` that allows
    /// by default.
    fn store_in(status: PolicyStatus) -> Arc<FakePolicyStore> {
        let tenant = test_ctx().tenant_id();
        Arc::new(FakePolicyStore::holding(
            tenant,
            policy_in(status, Vec::new()),
        ))
    }

    fn ports_over(store: &Arc<FakePolicyStore>) -> ChangeDefaultActionPorts {
        ChangeDefaultActionPorts {
            policy_store: store.clone(),
            ..ChangeDefaultActionPorts::fakes()
        }
    }

    fn deny() -> PolicyAction {
        PolicyAction::Deny {
            reason: Text::new("reason", "not allowed").unwrap(),
        }
    }

    fn change(ports: ChangeDefaultActionPorts) -> Result<PolicySet, AppError> {
        block_on(ChangeDefaultActionUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            deny(),
        ))
    }

    fn denies_by_default(store: &FakePolicyStore) -> bool {
        let stored = store.stored(test_ctx().tenant_id()).unwrap();
        stored.default_action().is_deny()
    }

    /// Ann makes the draft deny what no rule matches. It is saved that way.
    #[test]
    fn the_draft_takes_the_new_default_action() {
        let store = store_in(PolicyStatus::Draft);

        change(ports_over(&store)).unwrap();

        assert!(denies_by_default(&store));
    }

    /// Ann changes the default action in a tenant without a policy. There
    /// is nothing to change.
    #[test]
    fn a_tenant_without_a_policy_is_not_found() {
        let store = Arc::new(FakePolicyStore::empty());

        let result = change(ports_over(&store));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann changes the default action of the draft Bob is reviewing. What
    /// he reads must stay as it is, so she is refused and it keeps allowing.
    #[test]
    fn a_draft_in_review_is_not_edited() {
        let store = store_in(PolicyStatus::Review);

        let result = change(ports_over(&store));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(!denies_by_default(&store));
    }

    /// Policy view permission cannot change the default action, which keeps allowing.
    #[test]
    fn a_caller_who_may_not_update_the_policy_is_refused() {
        let store = store_in(PolicyStatus::Draft);
        let ports = ChangeDefaultActionPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::PolicySet(PolicySetAction::View),
            ])),
            ..ports_over(&store)
        };

        let result = change(ports);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(!denies_by_default(&store));
    }

    /// A signed-out session cannot change the policy's default action.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = store_in(PolicyStatus::Draft);
        let ports = ChangeDefaultActionPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = change(ports);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

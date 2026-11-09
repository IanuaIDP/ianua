//! Add policy rule: put one more rule into the tenant's draft policy.
//!
//! The rule takes its place by priority; rules of equal priority are
//! checked in the order they were added.

use std::sync::Arc;

use ianua_domain::domains::authorization::policy::rule::PolicyRule;
use ianua_domain::domains::authorization::policy::set::PolicySet;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::authorization::PolicyStore;
use crate::use_case::Command;
use crate::use_cases::authorization::policies::versions::draft_edit::saved_edit;

/// The ports [`AddRuleUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AddRulePorts {
    /// Loads and saves the policy.
    pub policy_store: Arc<dyn PolicyStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Adds a rule to the draft policy of the caller's tenant.
pub struct AddRuleUseCase {
    ports: AddRulePorts,
}

impl AddRuleUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AddRulePorts) -> Self {
        Self { ports }
    }
}

impl Command for AddRuleUseCase {
    type Caller = CallerContext;
    type Input = PolicyRule;
    type Output = Result<PolicySet, AppError>;

    /// Adds `rule` to the draft, for the caller, and records it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no policy; a draft is
    ///   opened first.
    /// - `AppError::Forbidden` when the caller may not update the policy.
    /// - `AppError::Conflict` when the policy is not a draft, or already has
    ///   a rule of that name.
    /// - `AppError::Internal` when the policy cannot be read or written.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        rule: PolicyRule,
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
                    .add_rule(rule, &authority)
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

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakePolicyStore, block_admin_rule, policy_in};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The tenant's policy store, holding a policy in `status` with `rules`.
    fn store_in(status: PolicyStatus, rules: Vec<PolicyRule>) -> Arc<FakePolicyStore> {
        let tenant = test_ctx().tenant_id();
        Arc::new(FakePolicyStore::holding(tenant, policy_in(status, rules)))
    }

    fn ports_over(store: &Arc<FakePolicyStore>) -> AddRulePorts {
        AddRulePorts {
            policy_store: store.clone(),
            ..AddRulePorts::fakes()
        }
    }

    fn add(ports: AddRulePorts, sink: &Arc<FakeEventDispatcher>) -> Result<PolicySet, AppError> {
        block_on(AddRuleUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            block_admin_rule(),
        ))
    }

    fn quietly(ports: AddRulePorts) -> Result<PolicySet, AppError> {
        add(ports, &Arc::new(FakeEventDispatcher::new()))
    }

    fn stored(store: &FakePolicyStore) -> PolicySet {
        store.stored(test_ctx().tenant_id()).unwrap()
    }

    /// Ann adds "block-admin" to the draft. It is saved there and the rule
    /// added is recorded.
    #[test]
    fn a_rule_is_added_to_the_draft_and_recorded() {
        let store = store_in(PolicyStatus::Draft, Vec::new());
        let sink = Arc::new(FakeEventDispatcher::new());

        add(ports_over(&store), &sink).unwrap();

        assert_eq!(stored(&store).rules()[0].name().as_str(), "block-admin");
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.policy_rule_added"]
        );
    }

    /// Ann adds a rule in a tenant that never opened a draft. There is no
    /// policy to add it to.
    #[test]
    fn a_tenant_without_a_policy_is_not_found() {
        let store = Arc::new(FakePolicyStore::empty());

        let result = quietly(ports_over(&store));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann adds "block-admin" to a draft that has it already. The two could
    /// not be told apart, so she is refused and nothing is recorded.
    #[test]
    fn a_rule_name_already_taken_is_a_conflict() {
        let store = store_in(PolicyStatus::Draft, vec![block_admin_rule()]);
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = add(ports_over(&store), &sink);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(stored(&store).rule_count(), 1);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann adds a rule to the draft Bob is reviewing. What he reads must
    /// stay as it is, so she is refused and it keeps its rules.
    #[test]
    fn a_draft_in_review_is_not_edited() {
        let store = store_in(PolicyStatus::Review, Vec::new());

        let result = quietly(ports_over(&store));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(stored(&store).rules().is_empty());
    }

    /// Policy view permission cannot add a rule; the draft stays without rules.
    #[test]
    fn a_caller_who_may_not_update_the_policy_is_refused() {
        let store = store_in(PolicyStatus::Draft, Vec::new());
        let ports = AddRulePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::PolicySet(PolicySetAction::View),
            ])),
            ..ports_over(&store)
        };

        let result = quietly(ports);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(stored(&store).rules().is_empty());
    }

    /// A signed-out session cannot add a policy rule.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = store_in(PolicyStatus::Draft, Vec::new());
        let ports = AddRulePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = quietly(ports);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

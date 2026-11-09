//! Remove policy rule: take one rule, by name, out of the tenant's draft
//! policy.

use std::sync::Arc;

use ianua_domain::domains::authorization::policy::set::PolicySet;
use ianua_domain::types::Label;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::authorization::PolicyStore;
use crate::use_case::Command;
use crate::use_cases::authorization::policies::versions::draft_edit::saved_edit;

/// The ports [`RemoveRuleUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RemoveRulePorts {
    /// Loads and saves the policy.
    pub policy_store: Arc<dyn PolicyStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Removes a rule from the draft policy of the caller's tenant.
pub struct RemoveRuleUseCase {
    ports: RemoveRulePorts,
}

impl RemoveRuleUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RemoveRulePorts) -> Self {
        Self { ports }
    }
}

impl Command for RemoveRuleUseCase {
    type Caller = CallerContext;
    type Input = Label;
    type Output = Result<PolicySet, AppError>;

    /// Removes the rule named `rule_name` from the draft, for the caller,
    /// and records it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no policy, or the draft no
    ///   rule of that name.
    /// - `AppError::Forbidden` when the caller may not update the policy.
    /// - `AppError::Conflict` when the policy is not a draft.
    /// - `AppError::Internal` when the policy cannot be read or written.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        rule_name: Label,
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
                    .remove_rule(&rule_name, &authority)
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

    fn name(value: &str) -> Label {
        Label::new("rule_name", value).unwrap()
    }

    /// The tenant's policy store, holding a policy in `status` with the
    /// "block-admin" rule.
    fn store_in(status: PolicyStatus) -> Arc<FakePolicyStore> {
        let tenant = test_ctx().tenant_id();
        Arc::new(FakePolicyStore::holding(
            tenant,
            policy_in(status, vec![block_admin_rule()]),
        ))
    }

    fn ports_over(store: &Arc<FakePolicyStore>) -> RemoveRulePorts {
        RemoveRulePorts {
            policy_store: store.clone(),
            ..RemoveRulePorts::fakes()
        }
    }

    fn remove(
        ports: RemoveRulePorts,
        sink: &Arc<FakeEventDispatcher>,
        rule: &str,
    ) -> Result<PolicySet, AppError> {
        block_on(RemoveRuleUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            name(rule),
        ))
    }

    fn quietly(ports: RemoveRulePorts, rule: &str) -> Result<PolicySet, AppError> {
        remove(ports, &Arc::new(FakeEventDispatcher::new()), rule)
    }

    fn rules_left(store: &FakePolicyStore) -> usize {
        store.stored(test_ctx().tenant_id()).unwrap().rule_count()
    }

    /// Ann removes "block-admin" from the draft. It is gone and the removal
    /// is recorded.
    #[test]
    fn a_rule_is_removed_from_the_draft_and_recorded() {
        let store = store_in(PolicyStatus::Draft);
        let sink = Arc::new(FakeEventDispatcher::new());

        remove(ports_over(&store), &sink, "block-admin").unwrap();

        assert_eq!(rules_left(&store), 0);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.policy_rule_removed"]
        );
    }

    /// Ann removes a rule the draft does not have. It is not found and
    /// nothing is recorded.
    #[test]
    fn an_unknown_rule_is_not_found() {
        let store = store_in(PolicyStatus::Draft);
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = remove(ports_over(&store), &sink, "no-such-rule");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann removes a rule from the draft Bob is reviewing. What he reads
    /// must stay as it is, so she is refused and the rule stays.
    #[test]
    fn a_draft_in_review_is_not_edited() {
        let store = store_in(PolicyStatus::Review);

        let result = quietly(ports_over(&store), "block-admin");

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(rules_left(&store), 1);
    }

    /// Policy view permission cannot remove block-admin; the draft keeps its rule.
    #[test]
    fn a_caller_who_may_not_update_the_policy_is_refused() {
        let store = store_in(PolicyStatus::Draft);
        let ports = RemoveRulePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::PolicySet(PolicySetAction::View),
            ])),
            ..ports_over(&store)
        };

        let result = quietly(ports, "block-admin");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(rules_left(&store), 1);
    }

    /// A signed-out session cannot remove a policy rule.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = store_in(PolicyStatus::Draft);
        let ports = RemoveRulePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = quietly(ports, "block-admin");

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

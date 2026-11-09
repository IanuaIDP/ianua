//! Change policy rule: rewrite one rule of the tenant's draft where it
//! stands, on or off as it was.
//!
//! Removing the rule and adding it back would move it behind the rules of
//! its priority, and the first match of a priority decides: a rule asking
//! for a second factor could end up behind one that allows.

use std::sync::Arc;

use ianua_domain::domains::authorization::policy::rule::PolicyRule;
use ianua_domain::domains::authorization::policy::set::PolicySet;
use ianua_domain::types::Label;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::authorization::PolicyStore;
use crate::use_case::Command;
use crate::use_cases::authorization::policies::versions::draft_edit::saved_edit;

/// Which rule to rewrite, and what it becomes.
pub struct ChangeRuleRequest {
    /// The rule's name now.
    pub rule_name: Label,
    /// The rule as it should read, its name included.
    pub rule: PolicyRule,
}

/// The ports [`ChangeRuleUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeRulePorts {
    /// Loads and saves the draft.
    pub policy_store: Arc<dyn PolicyStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Rewrites a rule of the caller's tenant's draft policy.
pub struct ChangeRuleUseCase {
    ports: ChangeRulePorts,
}

impl ChangeRuleUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ChangeRulePorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangeRuleUseCase {
    type Caller = CallerContext;
    type Input = ChangeRuleRequest;
    type Output = Result<PolicySet, AppError>;

    /// Rewrites the rule `request` names, for the caller, and records its
    /// name before and after.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no open draft, or the
    ///   draft no rule of that name.
    /// - `AppError::Forbidden` when the caller may not update the policy.
    /// - `AppError::Conflict` when the draft is in review, or the new name
    ///   is another rule's.
    /// - `AppError::Internal` when the draft cannot be read or written, or
    ///   the change cannot be recorded.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ChangeRuleRequest,
    ) -> Result<PolicySet, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let ChangeRuleRequest { rule_name, rule } = request;
        saved_edit(
            self.ports.policy_store.as_ref(),
            &tenant,
            auditor,
            &authority.actor(),
            |draft| {
                draft
                    .change_rule(&rule_name, rule, &authority)
                    .map_err(AppError::from_domain)
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
    use ianua_domain::domains::authorization::permission::{PolicySetAction, SystemPermission};
    use ianua_domain::domains::authorization::policy::action::PolicyAction;
    use ianua_domain::domains::authorization::policy::status::PolicyStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakePolicyStore, policy_in};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn name(value: &str) -> Label {
        Label::new("rule_name", value).unwrap()
    }

    fn rule(rule_name: &str, action: PolicyAction) -> PolicyRule {
        PolicyRule::new(name(rule_name), Vec::new(), action, 10).unwrap()
    }

    /// A draft asking for a second factor, then allowing, both at 10.
    fn store_in(status: PolicyStatus) -> Arc<FakePolicyStore> {
        let rules = vec![
            rule(
                "require-mfa",
                PolicyAction::RequireAal(AssuranceLevel::Aal2),
            ),
            rule("allow-all", PolicyAction::Allow),
        ];
        Arc::new(FakePolicyStore::holding(
            test_ctx().tenant_id(),
            policy_in(status, rules),
        ))
    }

    fn ports_over(store: &Arc<FakePolicyStore>) -> ChangeRulePorts {
        ChangeRulePorts {
            policy_store: store.clone(),
            ..ChangeRulePorts::fakes()
        }
    }

    fn change(
        ports: ChangeRulePorts,
        sink: &Arc<FakeEventDispatcher>,
        from: &str,
        to: PolicyRule,
    ) -> Result<PolicySet, AppError> {
        block_on(ChangeRuleUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            ChangeRuleRequest {
                rule_name: name(from),
                rule: to,
            },
        ))
    }

    fn names(store: &FakePolicyStore) -> Vec<String> {
        store
            .stored(test_ctx().tenant_id())
            .unwrap()
            .rules()
            .iter()
            .map(|rule| rule.name().as_str().to_owned())
            .collect()
    }

    /// Ann renames "require-mfa" to "require-aal3" and asks for more. It
    /// keeps its place ahead of "allow-all", and the change is recorded.
    #[test]
    fn a_rule_is_rewritten_where_it_stands() {
        let store = store_in(PolicyStatus::Draft);
        let sink = Arc::new(FakeEventDispatcher::new());
        let stronger = rule(
            "require-aal3",
            PolicyAction::RequireAal(AssuranceLevel::Aal3),
        );

        change(ports_over(&store), &sink, "require-mfa", stronger).unwrap();

        assert_eq!(names(&store), ["require-aal3", "allow-all"]);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.policy_rule_changed"]
        );
    }

    /// Ann rewrites "require-mfa" under the name "allow-all", which another
    /// rule carries. The two could not be told apart, so it is refused.
    #[test]
    fn a_rule_cannot_take_another_rules_name() {
        let store = store_in(PolicyStatus::Draft);
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = change(
            ports_over(&store),
            &sink,
            "require-mfa",
            rule("allow-all", PolicyAction::Allow),
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann rewrites a rule the draft does not have. It is not found.
    #[test]
    fn an_unknown_rule_is_not_found() {
        let store = store_in(PolicyStatus::Draft);

        let result = change(
            ports_over(&store),
            &Arc::new(FakeEventDispatcher::new()),
            "no-such-rule",
            rule("anything", PolicyAction::Allow),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann rewrites a rule of the draft Bob is reviewing. What he reads
    /// must stay as it is, so she is refused.
    #[test]
    fn a_draft_in_review_is_not_edited() {
        let store = store_in(PolicyStatus::Review);

        let result = change(
            ports_over(&store),
            &Arc::new(FakeEventDispatcher::new()),
            "require-mfa",
            rule("require-mfa", PolicyAction::Allow),
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(names(&store), ["require-mfa", "allow-all"]);
    }

    /// Policy view permission cannot replace the second-factor rule with an
    /// allow action. The refusal records no rule change.
    #[test]
    fn a_caller_who_may_not_update_the_policy_is_refused() {
        let store = store_in(PolicyStatus::Draft);
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = ChangeRulePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::PolicySet(PolicySetAction::View),
            ])),
            ..ports_over(&store)
        };

        let result = change(
            ports,
            &sink,
            "require-mfa",
            rule("require-mfa", PolicyAction::Allow),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot rewrite a policy rule.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = store_in(PolicyStatus::Draft);
        let ports = ChangeRulePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = change(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            "require-mfa",
            rule("require-mfa", PolicyAction::Allow),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

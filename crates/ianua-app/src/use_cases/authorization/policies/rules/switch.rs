//! Switch policy rule: turn one rule of the tenant's draft policy on or
//! off, where it stands. A rule switched off is skipped when requests are
//! judged but kept for editing.

use std::sync::Arc;

use ianua_domain::domains::authorization::policy::set::PolicySet;
use ianua_domain::types::{Enablement, Label};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::authorization::PolicyStore;
use crate::use_case::Command;
use crate::use_cases::authorization::policies::versions::draft_edit::saved_edit;

/// Which rule to switch, and which way.
pub struct SwitchRuleRequest {
    /// The rule's name.
    pub rule_name: Label,
    /// Whether it takes part afterwards.
    pub enablement: Enablement,
}

/// The ports [`SwitchRuleUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SwitchRulePorts {
    /// Loads and saves the policy.
    pub policy_store: Arc<dyn PolicyStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Switches a rule of the caller's tenant's draft policy on or off.
pub struct SwitchRuleUseCase {
    ports: SwitchRulePorts,
}

impl SwitchRuleUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SwitchRulePorts) -> Self {
        Self { ports }
    }
}

impl Command for SwitchRuleUseCase {
    type Caller = CallerContext;
    type Input = SwitchRuleRequest;
    type Output = Result<PolicySet, AppError>;

    /// Switches the rule `request` names the way it says, for the caller,
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
    /// - `AppError::Internal` when the policy cannot be read or written, or
    ///   the change cannot be recorded.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: SwitchRuleRequest,
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
                    .switch_rule(&request.rule_name, request.enablement, &authority)
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
    use ianua_domain::domains::authorization::policy::rule::PolicyRule;
    use ianua_domain::domains::authorization::policy::status::PolicyStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        FakePolicyStore, block_admin_rule, draft_beside, policy_in,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn name(value: &str) -> Label {
        Label::new("rule_name", value).unwrap()
    }

    /// A rule with no conditions at priority 10, doing `action`.
    fn rule(rule_name: &str, action: PolicyAction) -> PolicyRule {
        PolicyRule::new(name(rule_name), Vec::new(), action, 10).unwrap()
    }

    /// The tenant's policy store, holding a policy in `status` with `rules`.
    fn store_in(status: PolicyStatus, rules: Vec<PolicyRule>) -> Arc<FakePolicyStore> {
        let tenant = test_ctx().tenant_id();
        Arc::new(FakePolicyStore::holding(tenant, policy_in(status, rules)))
    }

    fn ports_over(store: &Arc<FakePolicyStore>) -> SwitchRulePorts {
        SwitchRulePorts {
            policy_store: store.clone(),
            ..SwitchRulePorts::fakes()
        }
    }

    fn switch(
        ports: SwitchRulePorts,
        rule_name: &str,
        enablement: Enablement,
    ) -> Result<PolicySet, AppError> {
        switch_recorded(
            ports,
            rule_name,
            enablement,
            &Arc::new(FakeEventDispatcher::new()),
        )
    }

    fn switch_recorded(
        ports: SwitchRulePorts,
        rule_name: &str,
        enablement: Enablement,
        events: &Arc<FakeEventDispatcher>,
    ) -> Result<PolicySet, AppError> {
        block_on(SwitchRuleUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(events.clone()),
            SwitchRuleRequest {
                rule_name: name(rule_name),
                enablement,
            },
        ))
    }

    fn turn_off_block_admin(ports: SwitchRulePorts) -> Result<PolicySet, AppError> {
        switch(ports, "block-admin", Enablement::Disabled)
    }

    fn stored(store: &FakePolicyStore) -> PolicySet {
        store.stored(test_ctx().tenant_id()).unwrap()
    }

    fn block_admin_on(store: &FakePolicyStore) -> bool {
        stored(store)
            .find_rule(&name("block-admin"))
            .unwrap()
            .enabled()
    }

    /// Ann switches "block-admin" off in the draft. It is saved off, and
    /// kept.
    #[test]
    fn a_rule_is_switched_off_and_kept() {
        let store = store_in(PolicyStatus::Draft, vec![block_admin_rule()]);

        turn_off_block_admin(ports_over(&store)).unwrap();

        assert!(!block_admin_on(&store));
        assert_eq!(stored(&store).rule_count(), 1);
    }

    /// Ann switches "block-admin" off. The audit trail records which rule
    /// she switched, and that it is now off.
    #[test]
    fn switching_a_rule_is_recorded() {
        let store = store_in(PolicyStatus::Draft, vec![block_admin_rule()]);
        let events = Arc::new(FakeEventDispatcher::new());

        switch_recorded(
            ports_over(&store),
            "block-admin",
            Enablement::Disabled,
            &events,
        )
        .unwrap();

        assert_eq!(
            events
                .payload_of("authorization.policy_rule_switched")
                .get("state"),
            Some("disabled")
        );
    }

    /// Ann switches a rule she switched off back on. It is saved on.
    #[test]
    fn a_rule_is_switched_back_on() {
        let store = store_in(PolicyStatus::Draft, vec![block_admin_rule()]);
        turn_off_block_admin(ports_over(&store)).unwrap();

        switch(ports_over(&store), "block-admin", Enablement::Enabled).unwrap();

        assert!(block_admin_on(&store));
    }

    /// Ann's draft asks for a second factor before it allows, both at
    /// priority 10. She switches the second-factor rule off and on again.
    /// It still comes first, so a request is not let in without the factor.
    #[test]
    fn a_switched_rule_keeps_its_place_among_rules_of_its_priority() {
        let store = store_in(
            PolicyStatus::Draft,
            vec![
                rule(
                    "require-mfa",
                    PolicyAction::RequireAal(AssuranceLevel::Aal2),
                ),
                rule("allow-all", PolicyAction::Allow),
            ],
        );
        switch(ports_over(&store), "require-mfa", Enablement::Disabled).unwrap();

        switch(ports_over(&store), "require-mfa", Enablement::Enabled).unwrap();

        let names: Vec<_> = stored(&store)
            .rules()
            .iter()
            .map(|rule| rule.name().as_str().to_owned())
            .collect();
        assert_eq!(names, ["require-mfa", "allow-all"]);
    }

    /// Ann switches a rule the draft does not have. It is not found.
    #[test]
    fn an_unknown_rule_is_not_found() {
        let store = store_in(PolicyStatus::Draft, vec![block_admin_rule()]);

        let result = switch(ports_over(&store), "no-such-rule", Enablement::Disabled);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann switches a rule off while only the live policy exists. Edits go
    /// to a draft beside it, and there is none, so it is not found and the
    /// live rule stays on.
    #[test]
    fn the_live_policy_is_not_edited_in_place() {
        let store = store_in(PolicyStatus::Active, vec![block_admin_rule()]);

        let result = turn_off_block_admin(ports_over(&store));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(block_admin_on(&store));
    }

    /// Ann switches a rule off in the draft Bob is reviewing. What he reads
    /// must stay as it is, so she is refused and the rule stays on.
    #[test]
    fn a_draft_in_review_is_not_edited() {
        let store = store_in(PolicyStatus::Review, vec![block_admin_rule()]);

        let result = turn_off_block_admin(ports_over(&store));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(block_admin_on(&store));
    }

    /// Ann switches "block-admin" off in a draft beside the live policy.
    /// The draft changes; the live version, still deciding requests, keeps
    /// it on.
    #[test]
    fn a_draft_beside_the_live_policy_changes_alone() {
        let live = policy_in(PolicyStatus::Active, vec![block_admin_rule()]);
        let draft = draft_beside(&live);
        let live_version = live.version();
        let store = Arc::new(FakePolicyStore::holding_versions(
            test_ctx().tenant_id(),
            [live, draft],
        ));

        turn_off_block_admin(ports_over(&store)).unwrap();

        assert!(!block_admin_on(&store));
        let still_live = store.version(test_ctx().tenant_id(), live_version).unwrap();
        assert!(
            still_live
                .find_rule(&name("block-admin"))
                .unwrap()
                .enabled()
        );
    }

    /// Policy view permission cannot disable block-admin; the rule stays enabled.
    #[test]
    fn a_caller_who_may_not_update_the_policy_is_refused() {
        let store = store_in(PolicyStatus::Draft, vec![block_admin_rule()]);
        let ports = SwitchRulePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::PolicySet(PolicySetAction::View),
            ])),
            ..ports_over(&store)
        };

        let result = turn_off_block_admin(ports);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(block_admin_on(&store));
    }

    /// A signed-out session cannot disable a policy rule.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = store_in(PolicyStatus::Draft, vec![block_admin_rule()]);
        let ports = SwitchRulePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = turn_off_block_admin(ports);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

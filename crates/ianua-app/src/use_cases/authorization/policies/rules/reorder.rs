//! Reorder policy rules: put every rule of the tenant's draft in the order
//! an admin dragged them into, ten priority steps apart.

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

/// The ports [`ReorderRulesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ReorderRulesPorts {
    /// Loads and saves the draft.
    pub policy_store: Arc<dyn PolicyStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Puts the rules of the caller's tenant's draft policy in a new order.
pub struct ReorderRulesUseCase {
    ports: ReorderRulesPorts,
}

impl ReorderRulesUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ReorderRulesPorts) -> Self {
        Self { ports }
    }
}

impl Command for ReorderRulesUseCase {
    type Caller = CallerContext;
    type Input = Vec<Label>;
    type Output = Result<PolicySet, AppError>;

    /// Puts the draft's rules in the order `order` names them, for the
    /// caller, and records the order.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without policy-update rights.
    /// - `AppError::NotFound` for no open draft; `Conflict` when it is under review.
    /// - `AppError::Domain` when the order does not name each rule exactly once; `Internal` on read, write or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        order: Vec<Label>,
    ) -> Result<PolicySet, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        saved_edit(
            self.ports.policy_store.as_ref(),
            &tenant,
            auditor,
            &authority.actor(),
            |draft| {
                draft
                    .reorder_rules(&order, &authority)
                    .map_err(AppError::from_domain)
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{PolicySetAction, SystemPermission};
    use ianua_domain::domains::authorization::policy::action::PolicyAction;
    use ianua_domain::domains::authorization::policy::rule::PolicyRule;
    use ianua_domain::domains::authorization::policy::status::PolicyStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakePolicyStore, block_admin_rule, policy_in};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn name(value: &str) -> Label {
        Label::new("rule_name", value).unwrap()
    }

    /// A draft that blocks the admin pages, then allows everything.
    fn store_in(status: PolicyStatus) -> Arc<FakePolicyStore> {
        let allow =
            PolicyRule::new(name("allow-all"), Vec::new(), PolicyAction::Allow, 20).unwrap();
        Arc::new(FakePolicyStore::holding(
            test_ctx().tenant_id(),
            policy_in(status, vec![block_admin_rule(), allow]),
        ))
    }

    fn ports_over(store: &Arc<FakePolicyStore>) -> ReorderRulesPorts {
        ReorderRulesPorts {
            policy_store: store.clone(),
            ..ReorderRulesPorts::fakes()
        }
    }

    fn reorder(
        ports: ReorderRulesPorts,
        sink: &Arc<FakeEventDispatcher>,
        order: &[&str],
    ) -> Result<PolicySet, AppError> {
        block_on(ReorderRulesUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            order.iter().map(|rule| name(rule)).collect(),
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

    /// Ann moves "allow-all" ahead of "block-admin". The draft keeps them
    /// in that order, and the new order is recorded.
    #[test]
    fn the_rules_take_the_new_order() {
        let store = store_in(PolicyStatus::Draft);
        let sink = Arc::new(FakeEventDispatcher::new());

        reorder(ports_over(&store), &sink, &["allow-all", "block-admin"]).unwrap();

        assert_eq!(names(&store), ["allow-all", "block-admin"]);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.policy_rules_reordered"]
        );
    }

    /// Ann's new order leaves "block-admin" out. Dropping a rule that way
    /// would remove it unseen, so the order is refused and nothing moves.
    #[test]
    fn an_order_missing_a_rule_is_refused() {
        let store = store_in(PolicyStatus::Draft);
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = reorder(ports_over(&store), &sink, &["allow-all"]);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(names(&store), ["block-admin", "allow-all"]);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann reorders the draft Bob is reviewing. What he reads must stay as
    /// it is, so she is refused.
    #[test]
    fn a_draft_in_review_is_not_reordered() {
        let store = store_in(PolicyStatus::Review);

        let result = reorder(
            ports_over(&store),
            &Arc::new(FakeEventDispatcher::new()),
            &["allow-all", "block-admin"],
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Policy view permission cannot move allow-all ahead of block-admin;
    /// the stored order remains unchanged.
    #[test]
    fn a_caller_who_may_not_update_the_policy_is_refused() {
        let store = store_in(PolicyStatus::Draft);
        let ports = ReorderRulesPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::PolicySet(PolicySetAction::View),
            ])),
            ..ports_over(&store)
        };

        let result = reorder(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            &["allow-all", "block-admin"],
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(names(&store), ["block-admin", "allow-all"]);
    }

    /// A signed-out session cannot reorder policy rules.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = store_in(PolicyStatus::Draft);
        let ports = ReorderRulesPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = reorder(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            &["allow-all", "block-admin"],
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

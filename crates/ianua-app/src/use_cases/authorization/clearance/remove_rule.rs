//! Remove clearance rule: holding an app permission no longer clears for
//! anything beyond what everyone in the tenant sees.

use std::sync::Arc;

use ianua_domain::domains::authorization::clearance::ClearanceRules;
use ianua_domain::domains::authorization::permission::CustomPermission;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::authorization::ClearanceRuleStore;
use crate::use_case::Command;
use crate::use_cases::authorization::clearance::lookup::saved_change;

/// The ports [`RemoveRuleUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RemoveRulePorts {
    /// Loads and saves the rules.
    pub clearance_rules: Arc<dyn ClearanceRuleStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Removes a clearance rule of the caller's tenant.
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
    type Input = CustomPermission;
    type Output = Result<ClearanceRules<ResolvedTenant>, AppError>;

    /// Removes the rule naming `permission`, for the caller, and records
    /// it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when no rule names the permission.
    /// - `AppError::Forbidden` when the caller may not change how data is
    ///   classified, or is not cleared for what the rule clears for.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        permission: CustomPermission,
    ) -> Result<ClearanceRules<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        saved_change(
            self.ports.clearance_rules.as_ref(),
            &tenant,
            auditor,
            &authority.actor(),
            |rules| {
                rules
                    .remove_rule(&permission, &authority)
                    .map_err(AppError::from_domain)
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::clearance::ClearanceRule;
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::test_support::authority::anyone_holding;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::FakeClearanceRuleStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn payroll_read() -> CustomPermission {
        CustomPermission::new("payroll", "read").unwrap()
    }

    /// A store where `payroll:read` clears for confidential data.
    fn clearing_confidential() -> Arc<FakeClearanceRuleStore> {
        let mut rules = ClearanceRules::none();
        let rule = ClearanceRule::new(payroll_read(), DataClassLevel::Confidential).unwrap();
        rules
            .add_rule(rule, anyone_holding(SystemPermission::all()))
            .unwrap();
        let store = Arc::new(FakeClearanceRuleStore::empty());
        block_on(store.save(&test_ctx().tenant(), &rules)).unwrap();
        store
    }

    fn remove(
        ports: RemoveRulePorts,
        sink: &Arc<FakeEventDispatcher>,
        permission: CustomPermission,
    ) -> Result<ClearanceRules<ResolvedTenant>, AppError> {
        block_on(RemoveRuleUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            permission,
        ))
    }

    fn ports_over(store: &Arc<FakeClearanceRuleStore>) -> RemoveRulePorts {
        RemoveRulePorts {
            clearance_rules: store.clone(),
            ..RemoveRulePorts::fakes()
        }
    }

    fn rules_left(store: &FakeClearanceRuleStore) -> usize {
        store.stored(test_ctx().tenant_id()).unwrap().rules().len()
    }

    /// Ann removes the rule for `payroll:read`. It is gone and recorded.
    #[test]
    fn a_rule_is_removed_and_recorded() {
        let store = clearing_confidential();
        let sink = Arc::new(FakeEventDispatcher::new());

        remove(ports_over(&store), &sink, payroll_read()).unwrap();

        assert_eq!(rules_left(&store), 0);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.clearance_rule_removed"]
        );
    }

    /// Ann removes the rule for `notes:read`, which has none. It is not
    /// found.
    #[test]
    fn an_unknown_rule_is_not_found() {
        let store = clearing_confidential();
        let notes = CustomPermission::new("notes", "read").unwrap();

        let result = remove(
            ports_over(&store),
            &Arc::new(FakeEventDispatcher::new()),
            notes,
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Removing a clearance rule requires classification update permission.
    /// Without it, the rule stays stored and no removal is recorded.
    #[test]
    fn a_caller_who_may_not_change_classification_is_refused() {
        let store = clearing_confidential();
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = RemoveRulePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ports_over(&store)
        };

        let result = remove(ports, &sink, payroll_read());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(rules_left(&store), 1);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot remove a clearance rule.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = clearing_confidential();
        let ports = RemoveRulePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = remove(ports, &Arc::new(FakeEventDispatcher::new()), payroll_read());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

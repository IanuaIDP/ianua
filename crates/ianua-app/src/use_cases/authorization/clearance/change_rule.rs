//! Change clearance rule: change what holding one app permission clears
//! for.
//!
//! Lowering a clearance takes data away from its holders, so whoever
//! changes it must be cleared for both the level before and the level
//! after.

use std::sync::Arc;

use ianua_domain::domains::authorization::clearance::ClearanceRules;
use ianua_domain::domains::authorization::permission::CustomPermission;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::authorization::ClearanceRuleStore;
use crate::use_case::Command;
use crate::use_cases::authorization::clearance::lookup::saved_change;

/// The ports [`ChangeRuleUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeRulePorts {
    /// Loads and saves the rules.
    pub clearance_rules: Arc<dyn ClearanceRuleStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which permission's rule changes, and to what.
pub struct ChangeRuleRequest {
    /// The app permission whose rule changes.
    pub permission: CustomPermission,
    /// The most sensitive data it clears for from now on.
    pub up_to: DataClassLevel,
}

/// Changes a clearance rule of the caller's tenant.
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
    type Output = Result<ClearanceRules<ResolvedTenant>, AppError>;

    /// Changes the rule `request` names, for the caller, and records the
    /// level before and after.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when no rule names the permission.
    /// - `AppError::Domain` when the new level is public or internal.
    /// - `AppError::Forbidden` when the caller may not change how data is
    ///   classified, or is not cleared for the level before or after.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ChangeRuleRequest,
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
                    .change_rule(&request.permission, request.up_to, &authority)
                    .map_err(AppError::from_domain)
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::clearance::ClearanceRule;
    use ianua_domain::domains::authorization::permission::{
        ClassificationAction, SystemPermission,
    };
    use ianua_domain::test_support::authority::anyone_holding;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::FakeClearanceRuleStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn payroll_read() -> CustomPermission {
        CustomPermission::new("payroll", "read").unwrap()
    }

    /// A store where `payroll:read` clears for restricted data.
    fn clearing_restricted() -> Arc<FakeClearanceRuleStore> {
        let mut rules = ClearanceRules::none();
        let rule = ClearanceRule::new(payroll_read(), DataClassLevel::Restricted).unwrap();
        rules
            .add_rule(rule, anyone_holding(SystemPermission::all()))
            .unwrap();
        let store = Arc::new(FakeClearanceRuleStore::empty());
        block_on(store.save(&test_ctx().tenant(), &rules)).unwrap();
        store
    }

    fn change(
        ports: ChangeRulePorts,
        sink: &Arc<FakeEventDispatcher>,
        permission: CustomPermission,
        up_to: DataClassLevel,
    ) -> Result<ClearanceRules<ResolvedTenant>, AppError> {
        block_on(ChangeRuleUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            ChangeRuleRequest { permission, up_to },
        ))
    }

    fn ports_over(store: &Arc<FakeClearanceRuleStore>) -> ChangeRulePorts {
        ChangeRulePorts {
            clearance_rules: store.clone(),
            ..ChangeRulePorts::fakes()
        }
    }

    fn cleared_for(store: &FakeClearanceRuleStore) -> DataClassLevel {
        store.stored(test_ctx().tenant_id()).unwrap().rules()[0].up_to()
    }

    /// Ann lowers `payroll:read` to confidential. It is saved and recorded.
    #[test]
    fn a_rule_is_changed_and_recorded() {
        let store = clearing_restricted();
        let sink = Arc::new(FakeEventDispatcher::new());

        change(
            ports_over(&store),
            &sink,
            payroll_read(),
            DataClassLevel::Confidential,
        )
        .unwrap();

        assert_eq!(cleared_for(&store), DataClassLevel::Confidential);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.clearance_rule_changed"]
        );
    }

    /// Ann changes the rule for `notes:read`, which has none. It is not
    /// found.
    #[test]
    fn an_unknown_rule_is_not_found() {
        let store = clearing_restricted();
        let notes = CustomPermission::new("notes", "read").unwrap();

        let result = change(
            ports_over(&store),
            &Arc::new(FakeEventDispatcher::new()),
            notes,
            DataClassLevel::Confidential,
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Internal clearance cannot lower a rule granting restricted clearance.
    /// Its level stays restricted and no change is recorded.
    #[test]
    fn a_caller_not_cleared_for_the_level_before_is_refused() {
        let store = clearing_restricted();
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = ChangeRulePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Classification(ClassificationAction::Update),
            ])),
            ..ports_over(&store)
        };

        let result = change(ports, &sink, payroll_read(), DataClassLevel::Confidential);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(cleared_for(&store), DataClassLevel::Restricted);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot change a clearance rule.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = clearing_restricted();
        let ports = ChangeRulePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = change(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            payroll_read(),
            DataClassLevel::Confidential,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

//! Add clearance rule: say that holding one of the tenant's app permissions
//! clears its holder for confidential or restricted data.
//!
//! Nobody writes a rule clearing for more than they are cleared for
//! themselves.

use std::sync::Arc;

use ianua_domain::domains::authorization::clearance::{ClearanceRule, ClearanceRules};
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

/// The ports [`AddRuleUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AddRulePorts {
    /// Loads and saves the rules.
    pub clearance_rules: Arc<dyn ClearanceRuleStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which permission clears for what.
pub struct AddRuleRequest {
    /// The app permission that clears.
    pub permission: CustomPermission,
    /// The most sensitive data it clears for.
    pub up_to: DataClassLevel,
}

/// Adds a clearance rule to the caller's tenant.
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
    type Input = AddRuleRequest;
    type Output = Result<ClearanceRules<ResolvedTenant>, AppError>;

    /// Adds the rule `request` names, for the caller, and records it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Domain` when it clears for public or internal data.
    /// - `AppError::Forbidden` when the caller may not change how data is
    ///   classified, or is not cleared for that level themselves.
    /// - `AppError::Conflict` when a rule already names the permission.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: AddRuleRequest,
    ) -> Result<ClearanceRules<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let rule =
            ClearanceRule::new(request.permission, request.up_to).map_err(AppError::from_domain)?;
        saved_change(
            self.ports.clearance_rules.as_ref(),
            &tenant,
            auditor,
            &authority.actor(),
            |rules| {
                rules
                    .add_rule(rule, &authority)
                    .map_err(AppError::from_domain)
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{
        ClassificationAction, SystemPermission,
    };

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::FakeClearanceRuleStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn payroll_read(up_to: DataClassLevel) -> AddRuleRequest {
        AddRuleRequest {
            permission: CustomPermission::new("payroll", "read").unwrap(),
            up_to,
        }
    }

    fn add(
        ports: AddRulePorts,
        sink: &Arc<FakeEventDispatcher>,
        request: AddRuleRequest,
    ) -> Result<ClearanceRules<ResolvedTenant>, AppError> {
        block_on(AddRuleUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            request,
        ))
    }

    fn ports_over(store: &Arc<FakeClearanceRuleStore>) -> AddRulePorts {
        AddRulePorts {
            clearance_rules: store.clone(),
            ..AddRulePorts::fakes()
        }
    }

    /// Ann says `payroll:read` clears for confidential data. The rule is
    /// saved and recorded.
    #[test]
    fn a_rule_is_added_and_recorded() {
        let store = Arc::new(FakeClearanceRuleStore::empty());
        let sink = Arc::new(FakeEventDispatcher::new());

        add(
            ports_over(&store),
            &sink,
            payroll_read(DataClassLevel::Confidential),
        )
        .unwrap();

        let stored = store.stored(test_ctx().tenant_id()).unwrap();
        assert_eq!(stored.rules().len(), 1);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.clearance_rule_added"]
        );
    }

    /// Ann adds a second rule for `payroll:read`. One rule names each
    /// permission, so it is a conflict and nothing more is recorded.
    #[test]
    fn a_second_rule_for_one_permission_is_a_conflict() {
        let store = Arc::new(FakeClearanceRuleStore::empty());
        let sink = Arc::new(FakeEventDispatcher::new());
        add(
            ports_over(&store),
            &sink,
            payroll_read(DataClassLevel::Confidential),
        )
        .unwrap();

        let again = add(
            ports_over(&store),
            &sink,
            payroll_read(DataClassLevel::Restricted),
        );

        assert!(matches!(again, Err(AppError::Conflict(_))));
        assert_eq!(sink.records.lock().unwrap().len(), 1);
    }

    /// Ann says `payroll:read` clears for internal data, which everyone in
    /// the tenant sees already. It is refused.
    #[test]
    fn a_rule_for_what_everyone_sees_is_refused() {
        let store = Arc::new(FakeClearanceRuleStore::empty());

        let result = add(
            ports_over(&store),
            &Arc::new(FakeEventDispatcher::new()),
            payroll_read(DataClassLevel::Internal),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(store.stored(test_ctx().tenant_id()).is_none());
    }

    /// Internal clearance cannot authorize a rule granting restricted clearance,
    /// even with classification update permission. Nothing is saved or recorded.
    #[test]
    fn nobody_clears_for_more_than_their_own_clearance() {
        let store = Arc::new(FakeClearanceRuleStore::empty());
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = AddRulePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Classification(ClassificationAction::Update),
            ])),
            ..ports_over(&store)
        };

        let result = add(ports, &sink, payroll_read(DataClassLevel::Restricted));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(store.stored(test_ctx().tenant_id()).is_none());
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Adding a clearance rule requires a session that is still signed in.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = Arc::new(FakeClearanceRuleStore::empty());
        let ports = AddRulePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = add(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            payroll_read(DataClassLevel::Confidential),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

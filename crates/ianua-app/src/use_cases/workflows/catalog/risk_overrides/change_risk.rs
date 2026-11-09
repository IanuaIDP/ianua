//! Change risk: a tenant changes what an operation it raised counts as.
//!
//! The new class must still raise the operation; dropping the override
//! altogether is
//! [`remove_risk`](crate::use_cases::workflows::catalog::risk_overrides::remove_risk),
//! which needs more.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::integration::risk_override::OperationRiskOverride;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{DeclaredAction, OperationRiskOverrideId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::OperationRiskOverrideStore;
use crate::use_case::Command;
use crate::use_cases::workflows::lookup::existing_risk;

/// Which override to change, and what its operation counts as now.
pub struct ChangeRiskRequest {
    /// The tenant's existing operation classification to replace.
    pub override_id: OperationRiskOverrideId,
    /// What the operation counts as: a high-risk class, or undeclared.
    pub effect: DeclaredAction,
}

/// The ports [`ChangeRiskUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeRiskPorts {
    /// Keeps the overrides.
    pub risks: Arc<dyn OperationRiskOverrideStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes raised operations.
pub struct ChangeRiskUseCase {
    ports: ChangeRiskPorts,
}

impl ChangeRiskUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ChangeRiskPorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangeRiskUseCase {
    type Caller = CallerContext;
    type Input = ChangeRiskRequest;
    type Output = Result<OperationRiskOverride<ResolvedTenant>, AppError>;

    /// Sets what the overridden operation counts as, as the person `ctx`
    /// names.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such override.
    /// - `AppError::Forbidden` when the caller may not change workflows.
    /// - `AppError::Domain` when `effect` raises nothing.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ChangeRiskRequest,
    ) -> Result<OperationRiskOverride<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        control
            .ensure_may(WorkflowAction::Update)
            .map_err(AppError::from_domain)?;
        let mut risk = existing_risk(
            self.ports.risks.as_ref(),
            &ctx.tenant(),
            &request.override_id,
        )
        .await?;
        risk.change(&control, request.effect)
            .map_err(AppError::from_domain)?;
        self.ports
            .risks
            .save(&ctx.tenant(), &risk)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&ctx.actor(), risk.take_events(&ctx.tenant()))
            .await
            .or_internal()?;
        Ok(risk)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::types::ActionClass;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::workflows::{
        FakeOperationRiskOverrideStore, person, raised_to_payment,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A raised operation kept in the store, and what changing it recorded.
    struct Kept {
        risk: OperationRiskOverride<ResolvedTenant>,
        risks: Arc<FakeOperationRiskOverrideStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Kept {
        fn new() -> Self {
            let risk = raised_to_payment(&person("bob@corp.test"));
            Self {
                risks: Arc::new(FakeOperationRiskOverrideStore::holding(&risk)),
                risk,
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn change(
            &self,
            authorities: FakeTenantAuthorities,
            class: ActionClass,
        ) -> Result<OperationRiskOverride<ResolvedTenant>, AppError> {
            let use_case = ChangeRiskUseCase::new(ChangeRiskPorts {
                risks: self.risks.clone(),
                tenant_authorities: Arc::new(authorities),
            });
            let request = ChangeRiskRequest {
                override_id: *self.risk.id(),
                effect: DeclaredAction::Declared(class),
            };
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), request))
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    fn updater() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::Update)])
    }

    /// Bob raised "append row" to a payment. Ann finds it deletes rows too
    /// and changes it to a delete. The change is kept and recorded.
    #[test]
    fn a_raised_operation_is_changed_and_it_is_recorded() {
        let kept = Kept::new();

        let changed = kept.change(updater(), ActionClass::Delete).unwrap();

        assert_eq!(
            changed.effect(),
            DeclaredAction::Declared(ActionClass::Delete)
        );
        assert_eq!(kept.records(), ["workflows.operation_risk_raised"]);
    }

    /// Changing a payment override to a plain write is refused because it raises
    /// no risk; the refusal records no audit event.
    #[test]
    fn a_change_to_a_class_that_raises_nothing_is_refused() {
        let kept = Kept::new();

        let result = kept.change(updater(), ActionClass::Write);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(kept.records().is_empty());
    }

    /// A workflow viewer cannot change an operation's risk override.
    #[test]
    fn a_caller_who_may_not_change_workflows_is_refused() {
        let kept = Kept::new();
        let sam =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]);

        let result = kept.change(sam, ActionClass::Delete);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot change an operation's risk override.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let kept = Kept::new();

        let result = kept.change(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            ActionClass::Delete,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

//! Raise risk: a tenant raises how risky an integration's operation counts
//! as, for itself.
//!
//! An integration declares what each operation does, and may be wrong. A
//! tenant that knows "update row" in its finance sheet moves money raises
//! it, so every workflow using it needs the approval a payment does. It can
//! only raise it, never lower it below what the integration declares.

use std::sync::Arc;

use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::integration::risk_override::{
    OperationRiskOverride, RaiseRiskParams,
};
use ianua_domain::domains::workflows::integration::{IntegrationKey, OperationKey};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::DeclaredAction;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::OperationRiskOverrideStore;
use crate::use_case::Command;

/// The operation to raise, and what the tenant treats it as.
pub struct RaiseRiskRequest {
    /// The integration offering it.
    pub integration: IntegrationKey,
    /// The catalog action receiving a stricter classification.
    pub operation: OperationKey,
    /// What it counts as: a high-risk class, or undeclared.
    pub effect: DeclaredAction,
}

/// The ports [`RaiseRiskUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RaiseRiskPorts {
    /// Keeps the overrides.
    pub risks: Arc<dyn OperationRiskOverrideStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Raises how risky operations count as.
pub struct RaiseRiskUseCase {
    ports: RaiseRiskPorts,
}

impl RaiseRiskUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RaiseRiskPorts) -> Self {
        Self { ports }
    }
}

impl Command for RaiseRiskUseCase {
    type Caller = CallerContext;
    type Input = RaiseRiskRequest;
    type Output = Result<OperationRiskOverride<ResolvedTenant>, AppError>;

    /// Raises the operation for the tenant, as the person `ctx` names.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change workflows.
    /// - `AppError::Domain` when `effect` raises nothing.
    /// - `AppError::Conflict` when the operation is raised already; it is
    ///   changed instead.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: RaiseRiskRequest,
    ) -> Result<OperationRiskOverride<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let params = RaiseRiskParams {
            integration: request.integration,
            operation: request.operation,
            effect: request.effect,
        };
        let mut risk = OperationRiskOverride::raise(params, &WorkflowControl::new(&authority))
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
    use crate::test_support::workflows::{APPEND_ROW, FakeOperationRiskOverrideStore, SHEETS};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The store a raise writes to, and what it recorded.
    struct Written {
        risks: Arc<FakeOperationRiskOverrideStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Written {
        fn new() -> Self {
            Self {
                risks: Arc::new(FakeOperationRiskOverrideStore::empty()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn raise(
            &self,
            authorities: FakeTenantAuthorities,
            class: ActionClass,
        ) -> Result<OperationRiskOverride<ResolvedTenant>, AppError> {
            let use_case = RaiseRiskUseCase::new(RaiseRiskPorts {
                risks: self.risks.clone(),
                tenant_authorities: Arc::new(authorities),
            });
            let request = RaiseRiskRequest {
                integration: IntegrationKey::new(SHEETS).unwrap(),
                operation: OperationKey::new(APPEND_ROW).unwrap(),
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

    /// Ann raises "append row" in the finance sheet to a payment. The
    /// override is kept and recorded.
    #[test]
    fn an_operation_is_raised_and_it_is_recorded() {
        let written = Written::new();

        let risk = written.raise(updater(), ActionClass::Financial).unwrap();

        assert_eq!(
            risk.effect(),
            DeclaredAction::Declared(ActionClass::Financial)
        );
        assert_eq!(written.risks.count(), 1);
        assert_eq!(written.records(), ["workflows.operation_risk_raised"]);
    }

    /// Ann "raises" an operation to a plain write. That raises nothing, so
    /// it is refused and nothing is kept.
    #[test]
    fn a_class_that_raises_nothing_is_refused() {
        let written = Written::new();

        let result = written.raise(updater(), ActionClass::Write);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(written.risks.count(), 0);
    }

    /// Ann raises the same operation twice. The second is refused as a
    /// conflict, so the operation has one override, which is changed
    /// instead.
    #[test]
    fn an_operation_raised_already_is_a_conflict() {
        let written = Written::new();
        written.raise(updater(), ActionClass::Financial).unwrap();

        let again = written.raise(updater(), ActionClass::Delete);

        assert!(matches!(again, Err(AppError::Conflict(_))));
        assert_eq!(written.risks.count(), 1);
    }

    /// A workflow viewer cannot raise an operation's risk; no override is saved.
    #[test]
    fn a_caller_who_may_not_change_workflows_is_refused() {
        let written = Written::new();
        let sam =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]);

        let result = written.raise(sam, ActionClass::Financial);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(written.risks.count(), 0);
    }

    /// A signed-out session cannot raise an operation's risk.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let written = Written::new();

        let result = written.raise(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            ActionClass::Financial,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

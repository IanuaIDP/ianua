//! Remove risk: a tenant drops its raised view of an operation, which then
//! counts as its integration declares again.
//!
//! Removing one lowers an operation's risk, so a step that needed an
//! approval may stop needing one. Only someone with full control of
//! workflows may.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::OperationRiskOverrideId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::OperationRiskOverrideStore;
use crate::use_case::Command;
use crate::use_cases::workflows::lookup::existing_risk;

/// The ports [`RemoveRiskUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RemoveRiskPorts {
    /// Keeps the overrides.
    pub risks: Arc<dyn OperationRiskOverrideStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Removes raised operations.
pub struct RemoveRiskUseCase {
    ports: RemoveRiskPorts,
}

impl RemoveRiskUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RemoveRiskPorts) -> Self {
        Self { ports }
    }
}

impl Command for RemoveRiskUseCase {
    type Caller = CallerContext;
    type Input = OperationRiskOverrideId;
    type Output = Result<(), AppError>;

    /// Removes the override `override_id`, as the person `ctx` names.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such override.
    /// - `AppError::Forbidden` when the caller does not have full control
    ///   of workflows.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        override_id: OperationRiskOverrideId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        control
            .ensure_may(WorkflowAction::Manage)
            .map_err(AppError::from_domain)?;
        let mut risk =
            existing_risk(self.ports.risks.as_ref(), &ctx.tenant(), &override_id).await?;
        risk.remove(&control).map_err(AppError::from_domain)?;
        self.ports
            .risks
            .delete(&ctx.tenant(), risk.id())
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), risk.take_events(&ctx.tenant()))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::integration::risk_override::OperationRiskOverride;
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::workflows::{
        FakeOperationRiskOverrideStore, person, raised_to_payment,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A raised operation kept in the store, and what removing it recorded.
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

        fn remove(&self, authorities: FakeTenantAuthorities) -> Result<(), AppError> {
            let use_case = RemoveRiskUseCase::new(RemoveRiskPorts {
                risks: self.risks.clone(),
                tenant_authorities: Arc::new(authorities),
            });
            block_on(use_case.execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                *self.risk.id(),
            ))
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    /// Ann, with full control of workflows, removes the override that made
    /// "append row" a payment. It is gone, and its removal is recorded.
    #[test]
    fn a_manager_removes_an_override_and_it_is_recorded() {
        let kept = Kept::new();
        let ann =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::Manage)]);

        kept.remove(ann).unwrap();

        assert_eq!(kept.risks.count(), 0);
        assert_eq!(
            kept.records(),
            ["workflows.operation_risk_override_removed"]
        );
    }

    /// Workflow update rights do not permit removing a risk override. The
    /// override remains saved and no audit event is recorded.
    #[test]
    fn removing_an_override_needs_full_control_of_workflows() {
        let kept = Kept::new();
        let sam =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::Update)]);

        let result = kept.remove(sam);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(kept.risks.count(), 1);
        assert!(kept.records().is_empty());
    }

    /// A signed-out session cannot remove a risk override, which remains saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let kept = Kept::new();

        let result = kept.remove(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(kept.risks.count(), 1);
    }
}

//! Show approval: the data a workflow's approval step lets through, shown
//! to a person who may decide it.
//!
//! The domain shows it only to someone holding the workflow approve right
//! and cleared for the data, so nobody reads the figures a step carries
//! before anyone asks whether they may decide it.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::design::node::NodeKey;
use ianua_domain::types::WorkflowExecutionId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::workflows::WorkflowExecutionStore;
use crate::use_case::Query;
use crate::use_cases::workflows::executions::approvals::approving::step_approver;
use crate::use_cases::workflows::lookup::existing_execution;

/// The step whose data to show.
pub struct ShowApprovalRequest {
    /// The execution waiting.
    pub execution_id: WorkflowExecutionId,
    /// The approval step.
    pub step: NodeKey,
}

/// The ports [`ShowApprovalUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ShowApprovalPorts {
    /// Keeps the executions.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Shows approvers what a step lets through.
pub struct ShowApprovalUseCase {
    ports: ShowApprovalPorts,
}

impl ShowApprovalUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ShowApprovalPorts) -> Self {
        Self { ports }
    }
}

impl Query for ShowApprovalUseCase {
    type Caller = CallerContext;
    type Input = ShowApprovalRequest;
    type Output = Result<FlowData, AppError>;

    /// The data `request.step` lets through, for the person `ctx` names to
    /// decide on. Approving later counts only for exactly this data.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing execution/step.
    /// - `AppError::Forbidden` without decision rights or clearance; `Conflict` for execution expiry.
    /// - `AppError::Domain` for a step not awaiting approval; `Internal` on storage failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: ShowApprovalRequest,
    ) -> Result<FlowData, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        WorkflowControl::new(&authority)
            .ensure_may(WorkflowAction::Approve)
            .map_err(AppError::from_domain)?;
        let execution = existing_execution(
            self.ports.executions.as_ref(),
            &ctx.tenant(),
            &request.execution_id,
        )
        .await?;
        let approver = step_approver(&authority, None)?;
        execution
            .shown_to(&request.step, &approver)
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::workflows::execution::WorkflowExecution;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::ActionClass;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::workflows::{
        FakeWorkflowExecutionStore, awaiting_approval_at, person, step,
    };
    use crate::test_support::{block_on, test_ctx};

    const APPROVES: [SystemPermission; 1] = [SystemPermission::Workflows(WorkflowAction::Approve)];

    fn waiting_at(exposure: DataClassLevel) -> WorkflowExecution<ResolvedTenant> {
        awaiting_approval_at(
            &person("author@corp.test"),
            &person("ann@corp.test"),
            ActionClass::Communicate,
            exposure,
        )
    }

    fn show(
        execution: &WorkflowExecution<ResolvedTenant>,
        authorities: FakeTenantAuthorities,
    ) -> Result<FlowData, AppError> {
        let use_case = ShowApprovalUseCase::new(ShowApprovalPorts {
            executions: Arc::new(FakeWorkflowExecutionStore::holding(execution)),
            tenant_authorities: Arc::new(authorities),
        });
        let request = ShowApprovalRequest {
            execution_id: *execution.id(),
            step: step("check"),
        };
        block_on(use_case.execute(&test_ctx(), request))
    }

    /// Bob may decide steps and opens the sign-off on Ann's internal report.
    /// He is shown exactly what the step lets through.
    #[test]
    fn an_approver_is_shown_what_the_step_lets_through() {
        let execution = waiting_at(DataClassLevel::Internal);

        let shown = show(&execution, FakeTenantAuthorities::holding(&APPROVES)).unwrap();

        assert_eq!(shown, execution.approval_input(&step("check")).unwrap());
    }

    /// An approver with only internal clearance cannot read a confidential
    /// approval step's data.
    #[test]
    fn an_approver_not_cleared_for_the_data_sees_nothing() {
        let execution = waiting_at(DataClassLevel::Confidential);

        let result = show(&execution, FakeTenantAuthorities::holding(&APPROVES));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Workflow view rights do not permit reading an approval step's data.
    #[test]
    fn someone_who_may_not_decide_sees_nothing() {
        let execution = waiting_at(DataClassLevel::Internal);

        let result = show(
            &execution,
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read an approval step's data.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let execution = waiting_at(DataClassLevel::Internal);

        let result = show(
            &execution,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

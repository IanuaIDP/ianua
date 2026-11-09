//! Get execution: one run of a workflow, for someone who may view
//! workflows, with the data they are not cleared for withheld.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::execution::ExecutionView;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::WorkflowExecutionId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::workflows::WorkflowExecutionStore;
use crate::use_case::Query;
use crate::use_cases::workflows::lookup::existing_execution;

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Keeps the executions.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one execution.
pub struct GetUseCase {
    ports: GetPorts,
}

impl GetUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetUseCase {
    type Caller = CallerContext;
    type Input = WorkflowExecutionId;
    type Output = Result<ExecutionView<ResolvedTenant>, AppError>;

    /// Execution `id`, with where each of its steps stands, as the caller
    /// may read it: data above their clearance is withheld.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view workflows.
    /// - `AppError::NotFound` when there is no such execution.
    /// - `AppError::Internal` when the store fails.
    async fn execute(
        &self,
        ctx: &CallerContext,
        id: WorkflowExecutionId,
    ) -> Result<ExecutionView<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let viewer = WorkflowControl::new(&authority);
        viewer
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        existing_execution(self.ports.executions.as_ref(), &ctx.tenant(), &id)
            .await?
            .viewed_by(viewer)
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{DataAccessAction, SystemPermission};
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::workflows::execution::step::StepPhase;
    use ianua_domain::domains::workflows::execution::{StepView, WorkflowExecution};
    use ianua_domain::types::ActionClass;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::workflows::{
        FakeWorkflowExecutionStore, awaiting_approval, awaiting_approval_at, person,
    };
    use crate::test_support::{block_on, test_ctx};

    fn kept() -> WorkflowExecution<ResolvedTenant> {
        awaiting_approval(
            &person("author@corp.test"),
            &person("ann@corp.test"),
            ActionClass::Communicate,
        )
    }

    /// Ann's payroll run, started with confidential data, waiting for an
    /// approval that shows it.
    fn payroll() -> WorkflowExecution<ResolvedTenant> {
        awaiting_approval_at(
            &person("author@corp.test"),
            &person("ann@corp.test"),
            ActionClass::Communicate,
            DataClassLevel::Confidential,
        )
    }

    fn get(
        execution: &WorkflowExecution<ResolvedTenant>,
        id: WorkflowExecutionId,
        authorities: FakeTenantAuthorities,
    ) -> Result<ExecutionView<ResolvedTenant>, AppError> {
        let use_case = GetUseCase::new(GetPorts {
            executions: Arc::new(FakeWorkflowExecutionStore::holding(execution)),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), id))
    }

    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)])
    }

    /// Bob may view workflows and opens Ann's run. He reads it as kept.
    #[test]
    fn a_viewer_reads_an_execution() {
        let execution = kept();

        let read = get(&execution, *execution.id(), viewer()).unwrap();

        assert_eq!(read.id(), execution.id());
    }

    /// A viewer with only internal clearance can read a confidential run's step
    /// phase and exposure, while its input and step data are withheld.
    #[test]
    fn data_above_the_viewers_clearance_is_withheld() {
        let execution = payroll();

        let read = get(&execution, *execution.id(), viewer()).unwrap();

        assert_eq!(read.input(), None);
        let (_, step) = read.steps().next().unwrap();
        assert_eq!(
            step,
            StepView::Withheld {
                phase: StepPhase::Running,
                exposure: DataClassLevel::Confidential,
            }
        );
    }

    /// Fay may view workflows and see confidential data. She reads Ann's
    /// payroll run whole.
    #[test]
    fn a_viewer_cleared_for_the_data_reads_it() {
        let execution = payroll();
        let cleared = FakeTenantAuthorities::holding(&[
            SystemPermission::Workflows(WorkflowAction::View),
            SystemPermission::Data(DataAccessAction::Confidential),
        ]);

        let read = get(&execution, *execution.id(), cleared).unwrap();

        assert_eq!(read.input(), Some(execution.input()));
        assert!(matches!(read.steps().next(), Some((_, StepView::Shown(_)))));
    }

    /// Bob asks for a run the tenant does not have. It is not found.
    #[test]
    fn an_unknown_execution_is_not_found() {
        let execution = kept();

        let result = get(&execution, WorkflowExecutionId::new(), viewer());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller without workflow rights cannot read an execution.
    #[test]
    fn reading_an_execution_needs_the_view_right() {
        let execution = kept();

        let result = get(
            &execution,
            *execution.id(),
            FakeTenantAuthorities::holding(&[]),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read an execution.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let execution = kept();

        let result = get(
            &execution,
            *execution.id(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

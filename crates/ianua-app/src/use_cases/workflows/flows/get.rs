//! Get flow: one agent flow and its run, for someone who may view
//! workflows, with the data they are not cleared for withheld.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::types::WorkflowId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::workflows::{WorkflowExecutionStore, WorkflowStore};
use crate::use_case::Query;
use crate::use_cases::workflows::flows::FlowProgress;
use crate::use_cases::workflows::lookup::{existing_flow, flow_run};

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Keeps the flows, as workflow versions.
    pub workflows: Arc<dyn WorkflowStore>,
    /// Keeps their runs.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one agent flow and its run.
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
    type Input = WorkflowId;
    type Output = Result<FlowProgress, AppError>;

    /// The flow `id` and its run, as the person `ctx` names may read them.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view workflows.
    /// - `AppError::NotFound` when the tenant has no such flow, or it is a
    ///   designed workflow.
    /// - `AppError::Internal` when a store fails.
    async fn execute(&self, ctx: &CallerContext, id: WorkflowId) -> Result<FlowProgress, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let viewer = WorkflowControl::new(&authority);
        viewer
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        let flow = existing_flow(self.ports.workflows.as_ref(), &tenant, &id).await?;
        let run = flow_run(self.ports.executions.as_ref(), &tenant, &flow).await?;
        let run = run.viewed_by(viewer).map_err(AppError::from_domain)?;
        Ok(FlowProgress { flow, run })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::workflows::design::workflow::Workflow;
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::caller_person;
    use crate::test_support::workflows::{
        FakeWorkflowExecutionStore, FakeWorkflowStore, draft_by, flow_by, started_by, tidy_step,
    };
    use crate::test_support::{block_on, test_ctx};

    /// The caller, holding what `authorities` say, reads `id` among
    /// `versions`, with Ann's run of `flow` kept.
    fn read(
        versions: &[Workflow<ResolvedTenant>],
        flow: &Workflow<ResolvedTenant>,
        id: WorkflowId,
        authorities: FakeTenantAuthorities,
    ) -> Result<FlowProgress, AppError> {
        let run = started_by(&caller_person(), flow);
        let use_case = GetUseCase::new(GetPorts {
            workflows: Arc::new(FakeWorkflowStore::holding(versions)),
            executions: Arc::new(FakeWorkflowExecutionStore::holding(&run)),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), id))
    }

    /// Someone who may view workflows.
    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)])
    }

    /// Bob may view workflows and opens Ann's flow. He reads it with its
    /// run.
    #[test]
    fn a_viewer_reads_a_flow_and_its_run() {
        let flow = flow_by(&caller_person());

        let read = read(std::slice::from_ref(&flow), &flow, *flow.id(), viewer()).unwrap();

        assert_eq!(read.flow.id(), flow.id());
        assert_eq!(read.run.workflow_id(), flow.id());
    }

    /// Bob opens a designed workflow as a flow. It is not found here.
    #[test]
    fn a_designed_workflow_is_not_read_as_a_flow() {
        let flow = flow_by(&caller_person());
        let designed = draft_by(&caller_person(), vec![tidy_step("tidy")], Vec::new());

        let result = read(
            &[flow.clone(), designed.clone()],
            &flow,
            *designed.id(),
            viewer(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller without workflow rights cannot read a flow and its run.
    #[test]
    fn a_caller_who_may_not_view_workflows_is_refused() {
        let flow = flow_by(&caller_person());

        let result = read(
            std::slice::from_ref(&flow),
            &flow,
            *flow.id(),
            FakeTenantAuthorities::holding(&[]),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read a flow and its run.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let flow = flow_by(&caller_person());

        let result = read(
            std::slice::from_ref(&flow),
            &flow,
            *flow.id(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

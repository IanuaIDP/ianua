//! Delete flow: a person deletes an agent flow whose run has ended, with
//! that run.
//!
//! Its maker may delete it, and so may someone who may delete workflows. A
//! flow still running is cancelled first, so no agent works on for a flow
//! that is gone.

use std::sync::Arc;

use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::WorkflowId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::{WorkflowExecutionStore, WorkflowStore};
use crate::use_case::Command;
use crate::use_cases::workflows::lookup::{flow_run, owned_flow};

/// The ports [`DeleteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// Keeps the flows, as workflow versions.
    pub workflows: Arc<dyn WorkflowStore>,
    /// Keeps their runs.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Deletes agent flows whose run has ended.
pub struct DeleteUseCase {
    ports: DeletePorts,
}

impl DeleteUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeletePorts) -> Self {
        Self { ports }
    }
}

impl Command for DeleteUseCase {
    type Caller = CallerContext;
    type Input = WorkflowId;
    type Output = Result<(), AppError>;

    /// Deletes flow `id` and its run, and records `workflows.flow_deleted`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when there is no such flow, it has no run, or
    ///   the caller neither made it nor may delete workflows, so an id
    ///   cannot be used to find out which flows exist.
    /// - `AppError::Conflict` while its run is still going.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        id: WorkflowId,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        let mut flow = owned_flow(self.ports.workflows.as_ref(), &tenant, &id, &control).await?;
        let run = flow_run(self.ports.executions.as_ref(), &tenant, &flow).await?;
        flow.delete_flow(&control, &run)
            .map_err(AppError::from_domain)?;
        self.ports
            .executions
            .delete(&tenant, run.id())
            .await
            .or_internal()?;
        self.ports
            .workflows
            .delete_flow(&tenant, flow.id())
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), flow.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::design::workflow::Workflow;
    use ianua_domain::domains::workflows::execution::WorkflowExecution;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::Human;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::caller_person;
    use crate::test_support::workflows::{
        FakeWorkflowExecutionStore, FakeWorkflowStore, flow_by, managing, person, started_by,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A flow, the stores it and its run are kept in, and what a delete
    /// recorded.
    struct Deleting {
        flow: Workflow<ResolvedTenant>,
        workflows: Arc<FakeWorkflowStore>,
        executions: Arc<FakeWorkflowExecutionStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Deleting {
        /// `flow`, kept with `run` as its run.
        fn over(flow: Workflow<ResolvedTenant>, run: &WorkflowExecution<ResolvedTenant>) -> Self {
            Self {
                workflows: Arc::new(FakeWorkflowStore::holding(std::slice::from_ref(&flow))),
                executions: Arc::new(FakeWorkflowExecutionStore::holding(run)),
                flow,
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// The flow `maker` made, its run cancelled by them.
        fn ended_for(maker: &Human) -> Self {
            let flow = flow_by(maker);
            let mut run = started_by(maker, &flow);
            run.cancel(&managing(maker)).unwrap();
            Self::over(flow, &run)
        }

        /// The flow `maker` made, its run still going.
        fn running_for(maker: &Human) -> Self {
            let flow = flow_by(maker);
            let run = started_by(maker, &flow);
            Self::over(flow, &run)
        }

        /// The caller, holding what `authorities` say, deletes the flow.
        fn delete(&self, authorities: FakeTenantAuthorities) -> Result<(), AppError> {
            let use_case = DeleteUseCase::new(DeletePorts {
                workflows: self.workflows.clone(),
                executions: self.executions.clone(),
                tenant_authorities: Arc::new(authorities),
            });
            block_on(use_case.execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                *self.flow.id(),
            ))
        }

        /// Whether the flow and its run are both still kept.
        fn still_kept(&self) -> bool {
            self.workflows.count() == 1 && self.executions.all().len() == 1
        }

        /// The names of the events recorded.
        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    /// Someone who may view workflows, and nothing more.
    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)])
    }

    /// Ann's flow has ended, and she deletes it. The flow and its run are
    /// both gone, and the deletion is recorded.
    #[test]
    fn the_maker_deletes_an_ended_flow_with_its_run() {
        let deleting = Deleting::ended_for(&caller_person());

        deleting.delete(viewer()).unwrap();

        assert_eq!(deleting.workflows.count(), 0);
        assert!(deleting.executions.all().is_empty());
        assert_eq!(deleting.records(), ["workflows.flow_deleted"]);
    }

    /// Ann's flow is still running. Deleting it is refused, so its agents
    /// do not work on for a flow that is gone; she cancels it first.
    #[test]
    fn a_flow_still_running_is_not_deleted() {
        let deleting = Deleting::running_for(&caller_person());

        let result = deleting.delete(viewer());

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(deleting.still_kept());
        assert!(deleting.records().is_empty());
    }

    /// Someone who may delete workflows deletes Ann's ended flow. It is
    /// deleted.
    #[test]
    fn a_deleter_deletes_someone_elses_ended_flow() {
        let deleting = Deleting::ended_for(&person("ann@corp.test"));
        let deleter =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::Delete)]);

        deleting.delete(deleter).unwrap();

        assert_eq!(deleting.workflows.count(), 0);
    }

    /// A viewer cannot delete another person's ended flow and receives not
    /// found. The flow and run remain saved, with no audit event recorded.
    #[test]
    fn someone_who_neither_made_it_nor_may_delete_is_refused() {
        let deleting = Deleting::ended_for(&person("ann@corp.test"));

        let result = deleting.delete(viewer());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(deleting.still_kept());
        assert!(deleting.records().is_empty());
    }

    /// Ann names a flow the tenant does not have. It is not found.
    #[test]
    fn an_unknown_flow_is_not_found() {
        let use_case = DeleteUseCase::new(DeletePorts {
            tenant_authorities: Arc::new(viewer()),
            ..DeletePorts::fakes()
        });
        let sink = Arc::new(FakeEventDispatcher::new());

        let result =
            block_on(use_case.execute(&test_ctx(), &test_auditor(sink), WorkflowId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out session cannot delete a flow; both flow and run remain saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let deleting = Deleting::ended_for(&caller_person());

        let result = deleting.delete(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(deleting.still_kept());
    }
}

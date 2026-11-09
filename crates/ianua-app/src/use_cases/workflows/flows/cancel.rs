//! Cancel flow: a person stops an agent flow's run.
//!
//! The person it acts for, its maker, may always stop it; anyone else needs
//! full control of workflows. Every agent run it leaves going is ordered to
//! stop. Once stopped, the flow may be deleted.

use std::sync::Arc;

use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::types::WorkflowId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::workflows::{ExecutionVersion, WorkflowExecutionStore, WorkflowStore};
use crate::use_case::Command;
use crate::use_cases::agents::runs::control::stopping::StopPorts;
use crate::use_cases::workflows::executions::running::Wakeups;
use crate::use_cases::workflows::executions::running::keeping::{Keeping, Kept};
use crate::use_cases::workflows::flows::{FlowStanding, RunShown};
use crate::use_cases::workflows::lookup::{FlowStores, FlowWithRun, owned_flow_run};

/// The ports [`CancelUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CancelPorts {
    /// Keeps the flows, as workflow versions.
    pub workflows: Arc<dyn WorkflowStore>,
    /// Keeps their runs.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// Drives a run again when its next step falls due.
    pub wakeups: Wakeups,
    /// Stops the agent runs a run gives up, and settles a paused one at
    /// once.
    pub run_stops: StopPorts,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Stops agent flows.
pub struct CancelUseCase {
    ports: CancelPorts,
}

impl CancelUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CancelPorts) -> Self {
        Self { ports }
    }
}

impl Command for CancelUseCase {
    type Caller = CallerContext;
    type Input = WorkflowId;
    type Output = Result<FlowStanding, AppError>;

    /// Stops the run of flow `id` for the person `ctx` names, and answers
    /// the flow with its stopped run as they may read it: whole, with data
    /// above their clearance withheld, or only where it stands when they may
    /// not view workflows.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when there is no such flow, it has no run, or
    ///   the caller is neither the person its run acts for nor has full
    ///   control of workflows, so an id cannot be used to find out which
    ///   flows exist.
    /// - `AppError::Conflict` when the run ran out of time; it is expired
    ///   then. Also when it changed since it was read, as when the worker
    ///   took a step meanwhile; asking again cancels it.
    /// - `AppError::Domain` when the run already ended.
    /// - `AppError::Internal` on persistence or audit failure, or when a
    ///   stop order cannot be kept.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        id: WorkflowId,
    ) -> Result<FlowStanding, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        let stores = FlowStores {
            workflows: self.ports.workflows.as_ref(),
            executions: self.ports.executions.as_ref(),
        };
        let FlowWithRun { flow, mut run } = owned_flow_run(stores, &tenant, &id, &control).await?;
        let read = ExecutionVersion::of(&run);
        let records = run.cancel(&control).map_err(AppError::from_domain)?;
        let keeping = Keeping {
            executions: self.ports.executions.as_ref(),
            wakeups: &self.ports.wakeups,
            runs: &self.ports.run_stops,
        };
        let kept = Kept::Changed(&run, read);
        keeping.keep(&tenant, auditor, kept, records).await?;
        Ok(FlowStanding {
            flow,
            run: RunShown::to(control, run),
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::design::workflow::Workflow;
    use ianua_domain::domains::workflows::execution::{ExecutionStatus, WorkflowExecution};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::Human;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::caller_person;
    use crate::test_support::workflows::{
        FakeWorkflowExecutionStore, FakeWorkflowStore, flow_by, person, started_by,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A flow, its run, and what a cancel wrote and recorded.
    struct Stopping {
        flow: Workflow<ResolvedTenant>,
        run: WorkflowExecution<ResolvedTenant>,
        executions: Arc<FakeWorkflowExecutionStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Stopping {
        /// The flow `maker` made, its run under way.
        fn made_by(maker: &Human) -> Self {
            let flow = flow_by(maker);
            let run = started_by(maker, &flow);
            Self {
                executions: Arc::new(FakeWorkflowExecutionStore::holding(&run)),
                flow,
                run,
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// The caller, holding what `authorities` say, cancels the flow.
        fn cancel(&self, authorities: FakeTenantAuthorities) -> Result<FlowStanding, AppError> {
            let use_case = CancelUseCase::new(CancelPorts {
                workflows: Arc::new(FakeWorkflowStore::holding(std::slice::from_ref(&self.flow))),
                executions: self.executions.clone(),
                tenant_authorities: Arc::new(authorities),
                ..CancelPorts::fakes()
            });
            block_on(use_case.execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                *self.flow.id(),
            ))
        }

        /// Where the run stands now.
        fn status(&self) -> ExecutionStatus {
            self.executions.stored(self.run.id()).unwrap().status()
        }

        /// The names of the events recorded.
        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    /// Someone who may run workflows.
    fn runner() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::Run)])
    }

    /// Ann stops the flow she made. Its run ends cancelled, and its end is
    /// recorded.
    #[test]
    fn the_maker_cancels_their_flow() {
        let stopping = Stopping::made_by(&caller_person());

        let stopped = stopping.cancel(runner()).unwrap();

        assert_eq!(stopped.flow.id(), stopping.flow.id());
        assert!(matches!(stopping.status(), ExecutionStatus::Ended(_)));
        assert!(
            stopping
                .records()
                .contains(&"workflows.execution_ended".to_owned())
        );
    }

    /// A maker with run rights but no view rights can cancel their flow and
    /// receives only its ended status.
    #[test]
    fn a_maker_who_may_not_view_is_answered_only_the_status() {
        let stopping = Stopping::made_by(&caller_person());

        let stopped = stopping.cancel(runner()).unwrap();

        assert!(matches!(
            stopped.run,
            RunShown::StatusOnly(ExecutionStatus::Ended(_))
        ));
    }

    /// Ann may view and run workflows and stops her flow. She is answered
    /// the flow with its stopped run, as reading it would show it.
    #[test]
    fn a_maker_who_may_view_is_answered_the_stopped_run() {
        let stopping = Stopping::made_by(&caller_person());

        let stopped = stopping
            .cancel(FakeTenantAuthorities::holding(&[
                SystemPermission::Workflows(WorkflowAction::Run),
                SystemPermission::Workflows(WorkflowAction::View),
            ]))
            .unwrap();

        assert!(matches!(
            &stopped.run,
            RunShown::Viewed(run) if matches!(run.status(), ExecutionStatus::Ended(_))
        ));
    }

    /// Ann names a flow the tenant does not have. It is not found.
    #[test]
    fn an_unknown_flow_is_not_found() {
        let use_case = CancelUseCase::new(CancelPorts {
            tenant_authorities: Arc::new(runner()),
            ..CancelPorts::fakes()
        });
        let sink = Arc::new(FakeEventDispatcher::new());

        let result =
            block_on(use_case.execute(&test_ctx(), &test_auditor(sink), WorkflowId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Run rights do not permit cancelling another person's flow. It appears
    /// missing, remains running and records no audit event.
    #[test]
    fn someone_else_without_full_control_cannot_cancel() {
        let stopping = Stopping::made_by(&person("ann@corp.test"));

        let result = stopping.cancel(runner());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(stopping.status(), ExecutionStatus::Running);
        assert!(stopping.records().is_empty());
    }

    /// A signed-out session cannot cancel its maker's flow, which remains running.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let stopping = Stopping::made_by(&caller_person());

        let result = stopping.cancel(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(stopping.status(), ExecutionStatus::Running);
    }
}

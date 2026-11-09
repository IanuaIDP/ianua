//! Cancel execution: a person stops a workflow's execution.
//!
//! The person it acts for may always stop it; anyone else needs full
//! control of workflows. Every agent run it leaves going is ordered to stop,
//! so nothing keeps working for an execution nobody runs any more.

use std::sync::Arc;

use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::types::WorkflowExecutionId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::workflows::{ExecutionVersion, WorkflowExecutionStore};
use crate::use_case::Command;
use crate::use_cases::agents::runs::control::stopping::StopPorts;
use crate::use_cases::workflows::executions::approvals::decided::ExecutionDecided;
use crate::use_cases::workflows::executions::running::Wakeups;
use crate::use_cases::workflows::executions::running::keeping::{Keeping, Kept};
use crate::use_cases::workflows::lookup::owned_execution;

/// The ports [`CancelUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CancelPorts {
    /// Keeps the executions.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// Drives an execution again when its next step falls due.
    pub wakeups: Wakeups,
    /// Stops the agent runs an execution gives up, should it end, and
    /// settles a paused one at once.
    pub run_stops: StopPorts,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Stops workflow executions.
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
    type Input = WorkflowExecutionId;
    type Output = Result<ExecutionDecided, AppError>;

    /// Stops execution `id` for the person `ctx` names. Only where it stands
    /// comes back: the person it acts for may stop it without being cleared
    /// for what its steps hold.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when there is no such execution, or the caller
    ///   is neither the person it acts for nor has full control of
    ///   workflows, so an id cannot be used to find out which runs exist.
    /// - `AppError::Conflict` when it ran out of time; it is expired then.
    ///   Also when it changed since it was read, as when the worker took a
    ///   step meanwhile; asking again cancels it.
    /// - `AppError::Domain` when it already ended.
    /// - `AppError::Internal` on persistence or audit failure, or when a
    ///   stop order cannot be kept.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        id: WorkflowExecutionId,
    ) -> Result<ExecutionDecided, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        let mut execution =
            owned_execution(self.ports.executions.as_ref(), &tenant, &id, &control).await?;
        let read = ExecutionVersion::of(&execution);
        let records = execution.cancel(&control).map_err(AppError::from_domain)?;
        let keeping = Keeping {
            executions: self.ports.executions.as_ref(),
            wakeups: &self.ports.wakeups,
            runs: &self.ports.run_stops,
        };
        let kept = Kept::Changed(&execution, read);
        keeping.keep(&tenant, auditor, kept, records).await?;
        Ok(ExecutionDecided::of(&execution))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::execution::{ExecutionStatus, WorkflowExecution};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::ActionClass;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeRunControl, caller_person};
    use crate::test_support::workflows::{
        FakeWorkflowExecutionStore, agent_run_under_way, awaiting_approval, person,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The stores a cancel writes to, and what it recorded.
    struct Stopping {
        executions: Arc<FakeWorkflowExecutionStore>,
        runs: Arc<FakeRunControl>,
        sink: Arc<FakeEventDispatcher>,
        execution_id: WorkflowExecutionId,
    }

    impl Stopping {
        fn over(execution: &WorkflowExecution<ResolvedTenant>) -> Self {
            Self {
                executions: Arc::new(FakeWorkflowExecutionStore::holding(execution)),
                runs: Arc::new(FakeRunControl::empty()),
                sink: Arc::new(FakeEventDispatcher::new()),
                execution_id: *execution.id(),
            }
        }

        fn cancel(&self, authorities: FakeTenantAuthorities) -> Result<ExecutionDecided, AppError> {
            let use_case = CancelUseCase::new(CancelPorts {
                executions: self.executions.clone(),
                run_stops: StopPorts {
                    run_cancellation: self.runs.clone(),
                    ..StopPorts::fakes()
                },
                tenant_authorities: Arc::new(authorities),
                ..CancelPorts::fakes()
            });
            block_on(use_case.execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                self.execution_id,
            ))
        }

        fn status(&self) -> ExecutionStatus {
            self.executions.stored(&self.execution_id).unwrap().status()
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    fn runs_workflows() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::Run)])
    }

    fn caller_waiting() -> WorkflowExecution<ResolvedTenant> {
        awaiting_approval(
            &person("author@corp.test"),
            &caller_person(),
            ActionClass::Communicate,
        )
    }

    /// The caller stops a run that acts for her. It ends cancelled, and its
    /// end is recorded.
    #[test]
    fn the_person_a_run_acts_for_cancels_it() {
        let stopping = Stopping::over(&caller_waiting());

        let decided = stopping.cancel(runs_workflows()).unwrap();

        assert_eq!(decided.execution_id, stopping.execution_id);
        assert!(matches!(decided.status, ExecutionStatus::Ended(_)));
        assert!(matches!(stopping.status(), ExecutionStatus::Ended(_)));
        assert!(
            stopping
                .records()
                .contains(&"workflows.execution_ended".to_owned())
        );
    }

    /// Run rights do not permit cancelling another person's execution. It
    /// appears missing, remains running and records no audit event.
    #[test]
    fn someone_else_without_full_control_cannot_cancel() {
        let ann = awaiting_approval(
            &person("author@corp.test"),
            &person("ann@corp.test"),
            ActionClass::Communicate,
        );
        let stopping = Stopping::over(&ann);

        let result = stopping.cancel(runs_workflows());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(stopping.status(), ExecutionStatus::Running);
        assert!(stopping.records().is_empty());
    }

    /// The caller cancels a run whose agent is still summarising. The agent
    /// run is ordered to stop, so it does not keep working for nobody.
    #[test]
    fn an_agent_run_under_way_is_ordered_to_stop() {
        let (execution, run) = agent_run_under_way(&caller_person());
        let stopping = Stopping::over(&execution);

        stopping.cancel(runs_workflows()).unwrap();

        assert!(stopping.runs.has_order_for(run.id()));
    }

    /// A concurrent execution change makes cancellation conflict. The stored
    /// execution remains running and no audit event is recorded.
    #[test]
    fn a_cancel_read_before_the_workers_step_is_a_conflict() {
        let stopping = Stopping::over(&caller_waiting());
        stopping.executions.moves_on_before_each_save();

        let result = stopping.cancel(runs_workflows());

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(stopping.status(), ExecutionStatus::Running);
        assert!(stopping.records().is_empty());
    }

    /// A signed-out session cannot cancel its owner's execution.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let stopping = Stopping::over(&caller_waiting());

        let result = stopping.cancel(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

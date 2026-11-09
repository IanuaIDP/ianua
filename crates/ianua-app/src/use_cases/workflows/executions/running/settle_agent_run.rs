//! Settle agent run: an agent run a workflow step started has ended, and
//! its result is settled on that step.
//!
//! The agents' worker announces every run that ends. A run no workflow
//! started, or one still going, is left alone. A run whose execution ended
//! meanwhile is still recorded, and nothing goes on from it.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::run::AgentRun;
use ianua_domain::domains::workflows::design::node::NodeKey;
use ianua_domain::domains::workflows::execution::WorkflowExecution;
use ianua_domain::domains::workflows::execution::step::{StepState, Underway};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{AgentRunId, WorkflowExecutionId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::RunStore;
use crate::ports::runtime::UnitOfWork;
use crate::ports::workflows::{ExecutionLease, ExecutionVersion, WorkflowExecutionStore};
use crate::services::kept_together::kept_together;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::runs::control::stopping::StopPorts;
use crate::use_cases::workflows::executions::running::Wakeups;
use crate::use_cases::workflows::executions::running::keeping::{Keeping, Kept};

/// The ports [`SettleAgentRunUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SettleAgentRunPorts {
    /// Keeps the executions.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// The ended run.
    pub runs: Arc<dyn RunStore>,
    /// Keeps the driving worker and this settlement apart.
    pub lease: Arc<dyn ExecutionLease>,
    /// Drives the execution on from the settled step.
    pub wakeups: Wakeups,
    /// Stops the agent runs an execution gives up, should it end, and
    /// settles a paused one at once.
    pub run_stops: StopPorts,
    /// Keeps the settlement and its record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Settles ended agent runs on the workflow steps that started them.
pub struct SettleAgentRunUseCase {
    ports: SettleAgentRunPorts,
}

impl SettleAgentRunUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SettleAgentRunPorts) -> Self {
        Self { ports }
    }
}

impl Command for SettleAgentRunUseCase {
    type Caller = ScopedTenant;
    type Input = AgentRunId;
    type Output = Result<(), AppError>;

    /// Settles run `run_id` on the step that started it, once it ended.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` while a worker drives the execution, or when
    ///   a person changed it since it was read; the announcement is
    ///   delivered again.
    /// - `AppError::Domain` when the execution refuses the run's result.
    /// - `AppError::Internal` when a store, the lease or the audit trail
    ///   fails.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        run_id: AgentRunId,
    ) -> Result<(), AppError> {
        let Some(execution) = self
            .ports
            .executions
            .find_by_agent_run(tenant, &run_id)
            .await
            .or_internal()?
        else {
            return Ok(());
        };
        let Some(run) = ended_run(self.ports.runs.as_ref(), tenant, &run_id).await? else {
            return Ok(());
        };
        if !self
            .ports
            .lease
            .try_claim(execution.id())
            .await
            .or_internal()?
        {
            return Err(AppError::Conflict(message!(
                "workflows-a-worker-is-driving-the-execution",
                "a worker is driving the execution"
            )));
        }
        let settled = settle(&self.ports, tenant, auditor, &run, execution.id()).await;
        self.ports.lease.release(execution.id()).await;
        settled
    }
}

/// The run `run_id`, once it ended.
async fn ended_run(
    runs: &dyn RunStore,
    tenant: &ScopedTenant,
    run_id: &AgentRunId,
) -> Result<Option<AgentRun<ResolvedTenant>>, AppError> {
    let run = runs.find_by_id(tenant, run_id).await.or_internal()?;
    Ok(run.filter(|run| run.status().is_terminal()))
}

/// Settles `run` on the step of the execution `id` that waits on it, read
/// afresh under the lease, and keeps the result with its record.
async fn settle(
    ports: &SettleAgentRunPorts,
    tenant: &ScopedTenant,
    auditor: &RequestAuditor,
    run: &AgentRun<ResolvedTenant>,
    id: &WorkflowExecutionId,
) -> Result<(), AppError> {
    let Some(mut execution) = ports
        .executions
        .find_by_id(tenant, id)
        .await
        .or_internal()?
    else {
        return Ok(());
    };
    let Some(key) = step_waiting_on(&execution, run.id()) else {
        return Ok(());
    };
    let read = ExecutionVersion::of(&execution);
    let records = execution
        .settle_agent_run(&key, run)
        .map_err(AppError::from_domain)?;
    let keeping = Keeping {
        executions: ports.executions.as_ref(),
        wakeups: &ports.wakeups,
        runs: &ports.run_stops,
    };
    kept_together(
        ports.unit_of_work.as_ref(),
        keeping.keep(tenant, auditor, Kept::Changed(&execution, read), records),
    )
    .await
}

/// The step of `execution` that waits, or waited, on run `run_id`.
fn step_waiting_on(
    execution: &WorkflowExecution<ResolvedTenant>,
    run_id: &AgentRunId,
) -> Option<NodeKey> {
    execution
        .steps()
        .find(|(_, state)| match state {
            StepState::Running { underway, .. } | StepState::Abandoned { underway, .. } => {
                *underway == Underway::AgentRun(*run_id)
            }
            StepState::Waiting
            | StepState::Ready { .. }
            | StepState::Succeeded { .. }
            | StepState::Failed(_)
            | StepState::Skipped
            | StepState::Stopped => false,
        })
        .map(|(node, _)| node.key().clone())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::execution::ExecutionStatus;
    use ianua_domain::domains::workflows::execution::record::ExecutionEnd;

    use super::*;
    use crate::test_support::agents::FakeRunStore;
    use crate::test_support::workflows::{
        FakeExecutionLease, FakeWorkflowExecutionStore, agent_run_under_way, managing, person, step,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// What a settlement wrote, and what it recorded.
    struct Settling {
        executions: Arc<FakeWorkflowExecutionStore>,
        runs: Arc<FakeRunStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Settling {
        fn over(
            execution: &WorkflowExecution<ResolvedTenant>,
            run: &AgentRun<ResolvedTenant>,
        ) -> Self {
            let runs = Arc::new(FakeRunStore::empty());
            block_on(runs.save(&test_ctx().tenant(), run)).unwrap();
            Self {
                executions: Arc::new(FakeWorkflowExecutionStore::holding(execution)),
                runs,
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn settle(&self, lease: FakeExecutionLease, run_id: AgentRunId) -> Result<(), AppError> {
            let use_case = SettleAgentRunUseCase::new(SettleAgentRunPorts {
                executions: self.executions.clone(),
                runs: self.runs.clone(),
                lease: Arc::new(lease),
                ..SettleAgentRunPorts::fakes()
            });
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.sink.clone()),
                run_id,
            ))
        }

        fn stored(&self, id: &WorkflowExecutionId) -> WorkflowExecution<ResolvedTenant> {
            self.executions.stored(id).unwrap()
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    /// Ann's summarising agent completes its run. The step that started it
    /// succeeds with the answer, and the execution, with nothing left to
    /// do, ends as succeeded.
    #[test]
    fn a_completed_run_settles_the_step_that_started_it() {
        let (execution, mut run) = agent_run_under_way(&person("ann@corp.test"));
        run.complete("three orders are late").unwrap();
        let settling = Settling::over(&execution, &run);

        settling
            .settle(FakeExecutionLease::free(), *run.id())
            .unwrap();

        let stored = settling.stored(execution.id());
        assert!(matches!(
            stored.step(&step("summarise")),
            Some(StepState::Succeeded { .. })
        ));
        assert_eq!(
            stored.status(),
            ExecutionStatus::Ended(ExecutionEnd::Succeeded)
        );
        assert_eq!(
            settling.records(),
            ["workflows.step_succeeded", "workflows.execution_ended"]
        );
    }

    /// Ann's agent is still summarising when an announcement about its run
    /// arrives. Nothing is settled and nothing recorded.
    #[test]
    fn a_run_still_going_settles_nothing() {
        let (execution, run) = agent_run_under_way(&person("ann@corp.test"));
        let settling = Settling::over(&execution, &run);

        settling
            .settle(FakeExecutionLease::free(), *run.id())
            .unwrap();

        assert!(matches!(
            settling.stored(execution.id()).step(&step("summarise")),
            Some(StepState::Running { .. })
        ));
        assert!(settling.records().is_empty());
    }

    /// A run Ann started by hand, outside any workflow, ends. No step
    /// waits on it, so nothing is settled.
    #[test]
    fn a_run_no_workflow_started_is_left_alone() {
        let (execution, mut run) = agent_run_under_way(&person("ann@corp.test"));
        run.complete("done").unwrap();
        let settling = Settling::over(&execution, &run);

        settling
            .settle(FakeExecutionLease::free(), AgentRunId::new())
            .unwrap();

        assert!(settling.records().is_empty());
    }

    /// A worker is driving Ann's execution when its run ends. The settlement
    /// waits its turn, refused as a conflict, and is delivered again.
    #[test]
    fn a_settlement_while_a_worker_drives_waits_its_turn() {
        let (execution, mut run) = agent_run_under_way(&person("ann@corp.test"));
        run.complete("done").unwrap();
        let settling = Settling::over(&execution, &run);

        let result = settling.settle(
            FakeExecutionLease::held_elsewhere(*execution.id()),
            *run.id(),
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(settling.records().is_empty());
    }

    /// Ann cancels her execution while its agent summarises, and the run
    /// then completes. Its result is recorded, and the execution stays
    /// cancelled.
    #[test]
    fn a_late_result_is_recorded_and_moves_nothing_on() {
        let ann = person("ann@corp.test");
        let (mut execution, mut run) = agent_run_under_way(&ann);
        execution.cancel(&managing(&ann)).unwrap();
        run.complete("done after all").unwrap();
        let settling = Settling::over(&execution, &run);

        settling
            .settle(FakeExecutionLease::free(), *run.id())
            .unwrap();

        let stored = settling.stored(execution.id());
        assert!(matches!(
            stored.step(&step("summarise")),
            Some(StepState::Succeeded { .. })
        ));
        assert!(matches!(
            stored.status(),
            ExecutionStatus::Ended(ExecutionEnd::Cancelled(_))
        ));
        assert_eq!(settling.records(), ["workflows.step_succeeded"]);
    }
}

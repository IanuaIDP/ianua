//! Settle pass: a pass of a loop ended, and its loop takes it in, starts
//! the next passes and, once every pass gave back, goes on with the list
//! they made.
//!
//! The pass asks for this when it is kept ended, in the same unit of work,
//! so no ended pass is left unheard. Hearing it twice is safe: a pass taken
//! in once, or one whose loop is no longer running, changes nothing.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::domains::workflows::execution::WorkflowExecution;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::WorkflowExecutionId;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::runtime::UnitOfWork;
use crate::ports::workflows::{ExecutionLease, ExecutionVersion, WorkflowExecutionStore};
use crate::services::kept_together::kept_together;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::runs::control::stopping::StopPorts;
use crate::use_cases::scheduling::{Handled, JobHandler, payload_of};
use crate::use_cases::workflows::executions::running::Wakeups;
use crate::use_cases::workflows::executions::running::keeping::{Keeping, Kept};
use crate::use_cases::workflows::executions::running::wakeups::{
    DriveJob, SETTLE_PASS_JOB, taken_in_turn,
};

/// The ports [`SettlePassUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SettlePassPorts {
    /// Keeps the executions, passes and the runs holding their loops.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// Keeps the driving worker and this settlement apart.
    pub lease: Arc<dyn ExecutionLease>,
    /// Drives the loop's execution on, and its new passes.
    pub wakeups: Wakeups,
    /// Stops the agent runs an execution gives up, should it end.
    pub run_stops: StopPorts,
    /// Keeps the settlement, the passes it starts and their records
    /// together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Has loops take in the passes that ended.
pub struct SettlePassUseCase {
    ports: SettlePassPorts,
}

impl SettlePassUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SettlePassPorts) -> Self {
        Self { ports }
    }

    /// Has the execution `looping`, read afresh under the lease, take in
    /// `pass`, and keeps what that came to.
    async fn settle(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        pass: &WorkflowExecution<ResolvedTenant>,
        looping: &WorkflowExecutionId,
    ) -> Result<(), AppError> {
        let Some(mut execution) = self
            .ports
            .executions
            .find_by_id(tenant, looping)
            .await
            .or_internal()?
        else {
            return Ok(());
        };
        let read = ExecutionVersion::of(&execution);
        let moves = execution.settle_pass(pass).map_err(AppError::from_domain)?;
        let keeping = Keeping {
            executions: self.ports.executions.as_ref(),
            wakeups: &self.ports.wakeups,
            runs: &self.ports.run_stops,
        };
        kept_together(
            self.ports.unit_of_work.as_ref(),
            keeping.keep_loop(tenant, auditor, Kept::Changed(&execution, read), moves),
        )
        .await
    }
}

impl Command for SettlePassUseCase {
    type Caller = ScopedTenant;
    type Input = WorkflowExecutionId;
    type Output = Result<(), AppError>;

    /// Has the loop that started pass `pass_id` take it in.
    ///
    /// A pass that is gone, or a run that is no pass, is left alone.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` while a worker drives the loop's execution,
    ///   or when a person changed it since it was read; the job runs again.
    /// - `AppError::Domain` when the loop's execution refuses the pass.
    /// - `AppError::Internal` when a store, the lease or the audit trail
    ///   fails.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        pass_id: WorkflowExecutionId,
    ) -> Result<(), AppError> {
        let Some(pass) = self
            .ports
            .executions
            .find_by_id(tenant, &pass_id)
            .await
            .or_internal()?
        else {
            return Ok(());
        };
        let Some(looping) = pass.pass().map(|of| of.execution) else {
            return Ok(());
        };
        if !self.ports.lease.try_claim(&looping).await.or_internal()? {
            return Err(AppError::Conflict(message!(
                "workflows-a-worker-is-driving-the-execution",
                "a worker is driving the execution"
            )));
        }
        let settled = self.settle(tenant, auditor, &pass, &looping).await;
        self.ports.lease.release(&looping).await;
        settled
    }
}

/// Runs settle-pass jobs through [`SettlePassUseCase`].
pub struct SettlePassHandler {
    job_type: JobType,
    settle: Arc<SettlePassUseCase>,
}

impl SettlePassHandler {
    /// A handler settling passes through `settle`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when the job type is not one,
    /// which it always is.
    pub fn new(settle: Arc<SettlePassUseCase>) -> Result<Self, DomainError> {
        let job_type = JobType::new(SETTLE_PASS_JOB)?;
        Ok(Self { job_type, settle })
    }
}

#[async_trait]
impl JobHandler for SettlePassHandler {
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// Has the pass's loop take it in. A pass or loop that is gone is left
    /// alone; a loop busy with another pass is tried again within a second.
    async fn handle(
        &self,
        job: &ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let payload: DriveJob = payload_of(job)?;
        let tenant = ScopedTenant::for_background(payload.tenant_id);
        let auditor = auditor.with_tenant(payload.tenant_id);
        let settled = self
            .settle
            .execute(&tenant, &auditor, payload.execution_id)
            .await;
        taken_in_turn(settled, &payload.execution_id)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::execution::step::StepState;
    use ianua_domain::domains::workflows::execution::{ExecutionStatus, PassStart};

    use super::*;
    use crate::test_support::workflows::{
        FakeExecutionLease, FakeWorkflowExecutionStore, approve, loop_under_way, person, step,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// What a settlement wrote, and what it recorded.
    struct Settling {
        executions: Arc<FakeWorkflowExecutionStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Settling {
        fn over(
            execution: &WorkflowExecution<ResolvedTenant>,
            passes: &[WorkflowExecution<ResolvedTenant>],
        ) -> Self {
            let executions = Arc::new(FakeWorkflowExecutionStore::holding(execution));
            for pass in passes {
                block_on(executions.save(&test_ctx().tenant(), pass)).unwrap();
            }
            Self {
                executions,
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn settle(
            &self,
            lease: FakeExecutionLease,
            pass_id: WorkflowExecutionId,
        ) -> Result<(), AppError> {
            let use_case = SettlePassUseCase::new(SettlePassPorts {
                executions: self.executions.clone(),
                lease: Arc::new(lease),
                ..SettlePassPorts::fakes()
            });
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.sink.clone()),
                pass_id,
            ))
        }

        fn stored(&self, id: &WorkflowExecutionId) -> WorkflowExecution<ResolvedTenant> {
            self.executions.stored(id).unwrap()
        }
    }

    fn passes_of(starts: Vec<PassStart<ResolvedTenant>>) -> Vec<WorkflowExecution<ResolvedTenant>> {
        starts.into_iter().map(|start| start.execution).collect()
    }

    /// Ann's loop goes over two issues, one at a time. Once the first
    /// pass is approved and ends, its loop takes it in and the second pass
    /// starts, kept as a new execution beside it.
    #[test]
    fn an_ended_pass_is_taken_in_and_the_next_one_starts() {
        let (execution, starts) = loop_under_way(&person("ann@corp.test"), &["a", "b"]);
        let mut passes = passes_of(starts);
        approve(&mut passes[0], "check");
        let settling = Settling::over(&execution, &passes);

        settling
            .settle(FakeExecutionLease::free(), *passes[0].id())
            .unwrap();

        let stored = settling.stored(execution.id());
        let Some(StepState::Running { .. }) = stored.step(&step("each")) else {
            panic!("the loop is not running");
        };
        assert_eq!(settling.executions.passes_of(execution.id()).len(), 2);
    }

    /// The last pass of Ann's one-issue loop ends. The loop succeeds and,
    /// with nothing left to do, her run ends as succeeded.
    #[test]
    fn the_last_pass_ends_the_loop() {
        let (execution, starts) = loop_under_way(&person("ann@corp.test"), &["a"]);
        let mut passes = passes_of(starts);
        approve(&mut passes[0], "check");
        let settling = Settling::over(&execution, &passes);

        settling
            .settle(FakeExecutionLease::free(), *passes[0].id())
            .unwrap();

        assert!(matches!(
            settling.stored(execution.id()).status(),
            ExecutionStatus::Ended(_)
        ));
    }

    /// A worker is driving Ann's run when its pass ends. The settlement
    /// waits its turn, refused as a conflict, and runs again.
    #[test]
    fn a_settlement_while_a_worker_drives_waits_its_turn() {
        let (execution, starts) = loop_under_way(&person("ann@corp.test"), &["a"]);
        let mut passes = passes_of(starts);
        approve(&mut passes[0], "check");
        let settling = Settling::over(&execution, &passes);

        let result = settling.settle(
            FakeExecutionLease::held_elsewhere(*execution.id()),
            *passes[0].id(),
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// A run that is no pass, and a pass that is gone, settle nothing.
    #[test]
    fn a_run_that_is_no_pass_settles_nothing() {
        let (execution, _) = loop_under_way(&person("ann@corp.test"), &["a"]);
        let settling = Settling::over(&execution, &[]);

        settling
            .settle(FakeExecutionLease::free(), *execution.id())
            .unwrap();
        settling
            .settle(FakeExecutionLease::free(), WorkflowExecutionId::new())
            .unwrap();

        assert!(settling.sink.records.lock().unwrap().is_empty());
    }
}

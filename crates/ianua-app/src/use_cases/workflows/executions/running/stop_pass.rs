//! Stop pass: a loop failed, or the execution holding it ended, while one
//! of its passes still ran, and that pass is stopped.
//!
//! The loop asks for this in the unit of work that kept it failed or
//! ended. Stopping abandons the pass's steps under way, so the agent runs
//! it started are stopped too. A pass that already ended is left as it is.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::domains::workflows::execution::ExecutionStatus;
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
    DriveJob, STOP_PASS_JOB, taken_in_turn,
};

/// The ports [`StopPassUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct StopPassPorts {
    /// Keeps the passes.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// Keeps the driving worker and this stop apart.
    pub lease: Arc<dyn ExecutionLease>,
    /// Hands the stopped pass back to its loop.
    pub wakeups: Wakeups,
    /// Stops the agent runs the pass gives up.
    pub run_stops: StopPorts,
    /// Keeps the stop and its record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Stops the passes their loops left running.
pub struct StopPassUseCase {
    ports: StopPassPorts,
}

impl StopPassUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: StopPassPorts) -> Self {
        Self { ports }
    }

    /// Stops the pass `pass_id`, read afresh under the lease, unless it
    /// already ended, and keeps that with its record.
    async fn stop(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        pass_id: &WorkflowExecutionId,
    ) -> Result<(), AppError> {
        let Some(mut pass) = self
            .ports
            .executions
            .find_by_id(tenant, pass_id)
            .await
            .or_internal()?
        else {
            return Ok(());
        };
        if pass.status() != ExecutionStatus::Running {
            return Ok(());
        }
        let read = ExecutionVersion::of(&pass);
        let records = pass.stop_pass().map_err(AppError::from_domain)?;
        let keeping = Keeping {
            executions: self.ports.executions.as_ref(),
            wakeups: &self.ports.wakeups,
            runs: &self.ports.run_stops,
        };
        kept_together(
            self.ports.unit_of_work.as_ref(),
            keeping.keep(tenant, auditor, Kept::Changed(&pass, read), records),
        )
        .await
    }
}

impl Command for StopPassUseCase {
    type Caller = ScopedTenant;
    type Input = WorkflowExecutionId;
    type Output = Result<(), AppError>;

    /// Stops the tenant's pass `pass_id`. One that is gone or ended is left
    /// alone.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` while a worker drives the pass, or when a
    ///   person changed it since it was read; the job runs again.
    /// - `AppError::Domain` when the run is no pass of a loop.
    /// - `AppError::Internal` when a store, the lease or the audit trail
    ///   fails.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        pass_id: WorkflowExecutionId,
    ) -> Result<(), AppError> {
        if !self.ports.lease.try_claim(&pass_id).await.or_internal()? {
            return Err(AppError::Conflict(message!(
                "workflows-a-worker-is-driving-the-execution",
                "a worker is driving the execution"
            )));
        }
        let stopped = self.stop(tenant, auditor, &pass_id).await;
        self.ports.lease.release(&pass_id).await;
        stopped
    }
}

/// Runs stop-pass jobs through [`StopPassUseCase`].
pub struct StopPassHandler {
    job_type: JobType,
    stop: Arc<StopPassUseCase>,
}

impl StopPassHandler {
    /// A handler stopping passes through `stop`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when the job type is not one,
    /// which it always is.
    pub fn new(stop: Arc<StopPassUseCase>) -> Result<Self, DomainError> {
        let job_type = JobType::new(STOP_PASS_JOB)?;
        Ok(Self { job_type, stop })
    }
}

#[async_trait]
impl JobHandler for StopPassHandler {
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// Stops the pass. One that is gone or ended is left alone; one a
    /// worker drives is tried again within a second.
    async fn handle(
        &self,
        job: &ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let payload: DriveJob = payload_of(job)?;
        let tenant = ScopedTenant::for_background(payload.tenant_id);
        let auditor = auditor.with_tenant(payload.tenant_id);
        let stopped = self
            .stop
            .execute(&tenant, &auditor, payload.execution_id)
            .await;
        taken_in_turn(stopped, &payload.execution_id)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::execution::WorkflowExecution;
    use ianua_domain::domains::workflows::execution::record::ExecutionEnd;
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::test_support::workflows::{
        FakeExecutionLease, FakeWorkflowExecutionStore, loop_under_way, managing, person,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn stopping(
        executions: &Arc<FakeWorkflowExecutionStore>,
        sink: &Arc<FakeEventDispatcher>,
        pass_id: WorkflowExecutionId,
    ) -> Result<(), AppError> {
        let use_case = StopPassUseCase::new(StopPassPorts {
            executions: executions.clone(),
            lease: Arc::new(FakeExecutionLease::free()),
            ..StopPassPorts::fakes()
        });
        block_on(use_case.execute(&test_ctx().tenant(), &test_auditor(sink.clone()), pass_id))
    }

    fn holding(passes: &[WorkflowExecution<ResolvedTenant>]) -> Arc<FakeWorkflowExecutionStore> {
        let executions = Arc::new(FakeWorkflowExecutionStore::empty());
        for pass in passes {
            block_on(executions.save(&test_ctx().tenant(), pass)).unwrap();
        }
        executions
    }

    /// Ann's loop failed while a pass waited for its approval. The pass is
    /// stopped, ending as its loop did, and the record says so.
    #[test]
    fn a_running_pass_is_stopped_with_its_loop() {
        let (_, starts) = loop_under_way(&person("ann@corp.test"), &["a"]);
        let pass = starts.into_iter().next().unwrap().execution;
        let executions = holding(std::slice::from_ref(&pass));
        let sink = Arc::new(FakeEventDispatcher::new());

        stopping(&executions, &sink, *pass.id()).unwrap();

        assert_eq!(
            executions.stored(pass.id()).unwrap().status(),
            ExecutionStatus::Ended(ExecutionEnd::LoopEnded)
        );
        assert!(
            sink.records
                .lock()
                .unwrap()
                .contains(&"workflows.pass_ended".to_owned())
        );
    }

    /// Ann cancelled a pass herself before its loop's stop arrived. The
    /// stop leaves it cancelled and records nothing.
    #[test]
    fn a_pass_that_already_ended_is_left_as_it_is() {
        let ann = person("ann@corp.test");
        let (_, starts) = loop_under_way(&ann, &["a"]);
        let mut pass = starts.into_iter().next().unwrap().execution;
        pass.cancel(&managing(&ann)).unwrap();
        let executions = holding(std::slice::from_ref(&pass));
        let sink = Arc::new(FakeEventDispatcher::new());

        stopping(&executions, &sink, *pass.id()).unwrap();

        assert!(matches!(
            executions.stored(pass.id()).unwrap().status(),
            ExecutionStatus::Ended(ExecutionEnd::Cancelled(_))
        ));
        assert!(sink.records.lock().unwrap().is_empty());
    }
}

//! Starting a code step: the person the execution acts for is asked about
//! again, the step is started with what its code is handed, and the job
//! that runs the code is queued in the unit of work that keeps the start,
//! so no step waits on a run nobody will make.
//!
//! A step whose sandbox version holds an agent starts that agent's run
//! instead, as an agent run step starts its run.

use ianua_domain::domains::workflows::design::node::{Node, NodeKey, NodeKind};
use ianua_domain::domains::workflows::execution::step::StepRefusal;
use ianua_domain::domains::workflows::execution::{CodeStart, WorkflowExecution};
use ianua_domain::domains::workflows::sandbox::version::SandboxVersion;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::error::{AppError, OrInternal};
use crate::ports::workflows::ExecutionVersion;
use crate::services::kept_together::kept_together;
use crate::use_cases::workflows::executions::driving::Driving;
use crate::use_cases::workflows::executions::running::keeping::Kept;

impl Driving<'_> {
    /// Starts the ready code step `key` of `execution`, read at `read`: the
    /// agent its version holds, or a run of its code, queued; or fails it
    /// with the reason it may not run.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the step is not ready.
    /// - `AppError::Internal` when a store, the queue or the audit trail
    ///   fails.
    pub(super) async fn start_code(
        &self,
        execution: WorkflowExecution<ResolvedTenant>,
        read: ExecutionVersion,
        key: &NodeKey,
    ) -> Result<(), AppError> {
        match self.version_holding_an_agent(&execution, key).await? {
            Some(version) => self.start_held_agent(execution, read, key, &version).await,
            None => self.queue_code_run(execution, read, key).await,
        }
    }

    /// The version the code step `key` names, when it holds an agent.
    /// `None` for a version whose code is the step's work, and for one that
    /// is gone, whose run then fails as not run.
    async fn version_holding_an_agent(
        &self,
        execution: &WorkflowExecution<ResolvedTenant>,
        key: &NodeKey,
    ) -> Result<Option<SandboxVersion<ResolvedTenant>>, AppError> {
        let Some(NodeKind::Code(step)) = execution.graph().node(key).map(Node::kind) else {
            return Ok(None);
        };
        let version = self
            .ports
            .agent_steps
            .sandbox_versions
            .find_by_id(self.tenant, &step.version())
            .await
            .or_internal()?;
        Ok(version.filter(|version| version.held_agent().is_some()))
    }

    /// Starts the ready code step `key` with what its code is handed and
    /// queues its run, or fails it with the reason it may not run.
    async fn queue_code_run(
        &self,
        mut execution: WorkflowExecution<ResolvedTenant>,
        read: ExecutionVersion,
        key: &NodeKey,
    ) -> Result<(), AppError> {
        let Some(acting) = self.acting_for(&execution, &[]).await? else {
            return self
                .refuse(execution, read, key, StepRefusal::PersonLacksAuthority)
                .await;
        };
        let started = execution
            .begin_code(key, &acting)
            .map_err(AppError::from_domain)?;
        let (run, records) = match started {
            CodeStart::Run(run, records) => (run, records),
            CodeStart::Stopped(records) => return self.keep(&execution, read, records).await,
        };
        let keeping = self.keeping();
        let started_and_queued = async {
            keeping
                .keep(
                    self.tenant,
                    self.auditor,
                    Kept::Changed(&execution, read),
                    records,
                )
                .await?;
            self.ports
                .wakeups
                .run_code(self.tenant, execution.id(), key, run.run_id)
                .await
        };
        kept_together(self.ports.unit_of_work.as_ref(), started_and_queued).await
    }
}

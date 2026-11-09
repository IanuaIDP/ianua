//! Starting a failed execution again, from its trigger or from the steps
//! that did not finish: what re-run and retry share.
//!
//! The failed run stays as it ended. A new run of the same version starts,
//! with the same data, acting for the person the failed run acted for, who
//! alone may start it again, with what they hold now. An agent flow keeps
//! its one run, so its run is not started again; a new flow is made.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::delegation::HeldResources;
use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::execution::{RestartFrom, RestartParams, WorkflowExecution};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::WorkflowExecutionId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::workflows::{WorkflowExecutionStore, WorkflowStore};
use crate::use_cases::agents::runs::control::stopping::StopPorts;
use crate::use_cases::workflows::executions::running::Wakeups;
use crate::use_cases::workflows::executions::running::keeping::{Keeping, Kept};
use crate::use_cases::workflows::lookup::{designed_version, existing_execution};

/// The ports a re-run or a retry needs.
#[derive(ianua_macros::Fakes)]
pub struct RestartPorts {
    /// The versions, for the one the failed run ran.
    pub workflows: Arc<dyn WorkflowStore>,
    /// Keeps the executions.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// Hands the new execution to a worker.
    pub wakeups: Wakeups,
    /// Stops the agent runs an execution gives up, should it end, and
    /// settles a paused one at once.
    pub run_stops: StopPorts,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

impl RestartPorts {
    /// Starts the failed execution `id` again from where `from` says,
    /// acting for the person `ctx` names, and keeps the new run.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when there is no such execution, the version
    ///   it ran is gone, or it is an agent flow's run, which a flow has
    ///   only one of.
    /// - `AppError::Forbidden` when the caller may not run workflows, or is
    ///   not the person the failed run acted for.
    /// - `AppError::Conflict` unless it failed or ran out of time, or when
    ///   its version is no longer in service.
    /// - `AppError::Internal` on persistence or audit failure.
    pub(in crate::use_cases::workflows::executions) async fn restarted(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        id: WorkflowExecutionId,
        from: RestartFrom,
    ) -> Result<WorkflowExecution<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        control
            .ensure_may(WorkflowAction::Run)
            .map_err(AppError::from_domain)?;
        let failed = existing_execution(self.executions.as_ref(), &tenant, &id).await?;
        let workflow = designed_version(
            self.workflows.as_ref(),
            &tenant,
            failed.workflow_id(),
            Some(failed.version()),
        )
        .await?;
        let params = RestartParams {
            resources: HeldResources::answered(authority.who().principal(), Vec::new()),
            from,
        };
        let (execution, records) = failed
            .restart(&workflow, control, params)
            .map_err(AppError::from_domain)?;
        self.keeping()
            .keep(&tenant, auditor, Kept::Started(&execution), records)
            .await?;
        Ok(execution)
    }

    /// Where a restarted execution is kept.
    fn keeping(&self) -> Keeping<'_> {
        Keeping {
            executions: self.executions.as_ref(),
            wakeups: &self.wakeups,
            runs: &self.run_stops,
        }
    }
}

//! Saving a decided approval request together with the run it settled.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::run::AgentRun;
use ianua_domain::domains::agents::oversight::approval::ApprovalRequest;
use ianua_domain::domains::agents::oversight::approval_status::ApprovalStatus;
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;

use crate::error::{AppError, OrConflict, OrInternal};
use crate::ports::agents::{ApprovalStore, RunStore, RunVersion};
use crate::tenancy::ScopedTenant;
use crate::use_cases::agents::runs::RunDrives;

/// The ports a decision on an agent's paused action is kept through: the
/// request decided, the run it raised, and the queue that hands the run
/// back to a worker. Approving and denying share them.
#[derive(ianua_macros::Fakes)]
pub struct DecisionPorts {
    /// Loads and saves approval requests.
    pub approval_store: Arc<dyn ApprovalStore>,
    /// The run a request was raised by.
    pub run_store: Arc<dyn RunStore>,
    /// Where the job driving the run on is queued.
    pub run_drives: RunDrives,
}

impl DecisionPorts {
    /// Where a decision and the run it hands back are kept.
    pub(super) fn keeping(&self) -> DecisionKeeping<'_> {
        DecisionKeeping {
            approvals: self.approval_store.as_ref(),
            runs: self.run_store.as_ref(),
            drives: &self.run_drives,
        }
    }
}

/// Where a decision and the run it settled are kept.
pub(super) struct DecisionKeeping<'a> {
    /// Keeps the decided request.
    pub(super) approvals: &'a dyn ApprovalStore,
    /// Keeps the run it settled.
    pub(super) runs: &'a dyn RunStore,
    /// Queues the job that drives the run on.
    pub(super) drives: &'a RunDrives,
}

/// A run a decision hands back to a worker, and the version it was read
/// at before the decision changed it.
pub(super) struct Resumed {
    /// The run, resumed or carrying on without the call it held.
    pub(super) run: AgentRun<ResolvedTenant>,
    /// The version the run was read at.
    pub(super) read: RunVersion,
}

/// Saves `approval`, and the run it resumed or let carry on, when there is
/// one, and queues the job that hands that run back to a worker. The
/// request is saved first, so a decision that lost to another one saved
/// since it was read writes nothing. The run is saved only while it is as
/// it was read: a run stopped meanwhile, by a person or by the workflow
/// that gave it up, stays stopped rather than being resumed over the stop.
///
/// # Errors
///
/// - `AppError::Conflict` when the request was decided or spent since it
///   was read, or the run changed since it was read.
/// - `AppError::Internal` on storage or queue failure.
pub(super) async fn save_decision(
    keeping: DecisionKeeping<'_>,
    tenant: &ScopedTenant,
    approval: &ApprovalRequest<ResolvedTenant>,
    resumed: Option<&Resumed>,
) -> Result<(), AppError> {
    keeping
        .approvals
        .save(tenant, approval)
        .await
        .or_conflict(message!(
            "agents-the-request-was-decided-by-someone",
            "the request was decided by someone else meanwhile"
        ))?;
    let Some(resumed) = resumed else {
        return Ok(());
    };
    keeping
        .runs
        .save_unchanged_since(tenant, &resumed.run, resumed.read)
        .await
        .or_conflict(message!(
            "agents-the-run-was-stopped-or-changed",
            "the run was stopped or changed meanwhile"
        ))?;
    keeping.drives.hand_over(tenant, &resumed.run).await
}

/// Refuses a caller who may not decide agent actions, before any request
/// is read.
///
/// # Errors
///
/// Returns `AppError::Forbidden` when `authority` lacks the right to
/// approve agent actions.
pub(super) fn ensure_may_approve(authority: &TenantAuthority) -> Result<(), AppError> {
    authority
        .ensure_holds(SystemPermission::Agents(AgentAction::Approve))
        .map_err(AppError::from_domain)
}

/// Saves `approval` as expired when a refused decision found its time to
/// decide had run out, so the expiry is kept before the refusal goes back.
///
/// # Errors
///
/// - `AppError::Internal` on storage failure.
pub(super) async fn save_if_lapsed(
    approvals: &dyn ApprovalStore,
    tenant: &ScopedTenant,
    approval: &ApprovalRequest<ResolvedTenant>,
) -> Result<(), AppError> {
    if approval.status() != ApprovalStatus::Expired {
        return Ok(());
    }
    approvals.save(tenant, approval).await.or_internal()
}

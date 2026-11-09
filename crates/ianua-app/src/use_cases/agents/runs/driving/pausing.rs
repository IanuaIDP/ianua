//! How the loop leaves a run: waiting on a person for a held call, with the
//! approval request it raises counted against the tenant's plan, paused
//! before spending more, or ended.

use ianua_domain::domains::agents::execution::run::{AgentRun, RunStatus};
use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::oversight::approval::{ApprovalAction, ApprovalRequest};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, EventLabel};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::RunVersion;
use crate::ports::limits::ResourceKind;
use crate::services::kept_together::kept_together;
use crate::services::limits::room::{PlanSources as _, ensure_room_for_tenant};
use crate::use_cases::agents::runs::control::run_pause::{PausedRun, raised_approval};
use crate::use_cases::agents::runs::driving::drive::Driving;
use crate::use_cases::agents::runs::driving::ending::{Ending, finish, yield_to_people};
use crate::use_cases::agents::runs::driving::keeping::saved;
use crate::use_cases::agents::runs::driving::step::{Pause, Progress, Turn};

/// Keeps and announces how the loop left the run: waiting on a person, or
/// ended.
///
/// A run that would wait on a person while the tenant's plan allows no more
/// open approval requests fails instead, on the call it would have held,
/// with the reason recorded on that step. No person could be asked, so
/// waiting would hold it for nothing, and refusing the drive would only
/// have it tried again until the job gave up.
///
/// A run that paused itself before spending more is kept paused with the
/// record of why, for a person to resume or stop.
///
/// A run a person paused, or one already waiting for an approval it
/// raised before, is left as stored and its lease given back, so it is
/// driven again once a person resumes it. It is never closed here.
pub(in crate::use_cases::agents::runs::driving) async fn conclude(
    turn: &Turn<'_>,
    auditor: &RequestAuditor,
    progress: Progress,
    label: &EventLabel,
) -> Result<(), AppError> {
    let Progress {
        mut run,
        agent,
        paused,
        mut withdrawal,
        version,
        ..
    } = progress;
    match (run.status(), paused) {
        (RunStatus::Paused, Some(Pause::AtSpend)) => {
            hold_at_spend(turn.driving, auditor, &mut run, version).await
        }
        (RunStatus::AwaitingApproval, Some(Pause::ForApproval(action))) => {
            let pausing = Pausing {
                run: &mut run,
                version,
                agent: &agent,
                action,
            };
            pause_for_approval(turn, auditor, pausing, label).await
        }
        (RunStatus::AwaitingApproval | RunStatus::Paused, _) => give_back(turn, &run).await,
        _ => {
            let ending = Ending::closing(&mut run, version, withdrawal.as_mut());
            finish(turn.driving, auditor, ending, label).await
        }
    }
}

/// A run that stopped on a call a person must decide, with what the
/// approval request it raises names.
struct Pausing<'a> {
    /// The run, saved only over `version`.
    run: &'a mut AgentRun<ResolvedTenant>,
    /// The version the run was read at.
    version: RunVersion,
    /// The run's agent.
    agent: &'a AgentIdentity<ResolvedTenant>,
    /// The action the held call takes.
    action: ApprovalAction,
}

/// The run paused on its held call, holding the approval request it
/// raises, or failed when the tenant's plan has no room for another.
async fn pause_for_approval(
    turn: &Turn<'_>,
    auditor: &RequestAuditor,
    pausing: Pausing<'_>,
    label: &EventLabel,
) -> Result<(), AppError> {
    let Pausing {
        run,
        version,
        agent,
        action,
    } = pausing;
    if approval_room(turn.driving).await? == ApprovalRoom::Full {
        return fail_at_approval_limit(turn.driving, auditor, run, version, label).await;
    }
    run.announce_pause(label.clone());
    let paused = PausedRun {
        run: &*run,
        agent,
        action,
    };
    let approval = raised_approval(turn.driving, turn.toolbox, paused).await?;
    pause(turn, auditor, run, version, approval).await
}

/// Gives up the lease on `run`, left as stored for a person to resume.
async fn give_back(turn: &Turn<'_>, run: &AgentRun<ResolvedTenant>) -> Result<(), AppError> {
    turn.driving.ports.run_lease.release(run.id()).await;
    Ok(())
}

/// Keeps the run paused before it spends more, with the record of the
/// pause, then gives up its lease. A person who changed the run first
/// keeps their change, and nothing is recorded.
///
/// # Errors
///
/// - `AppError::Internal` on persistence or audit failure.
async fn hold_at_spend(
    driving: &Driving<'_>,
    auditor: &RequestAuditor,
    run: &mut AgentRun<ResolvedTenant>,
    version: RunVersion,
) -> Result<(), AppError> {
    let kept = async {
        saved(driving, run, version).await?;
        auditor
            .dispatch_by(&ActorRef::System, run.take_events(driving.tenant))
            .await
            .or_internal()
    };
    yield_to_people(kept_together(driving.ports.unit_of_work.as_ref(), kept).await)?;
    driving.ports.run_lease.release(run.id()).await;
    Ok(())
}

/// Whether a tenant's plan has room for the approval request a pause would
/// raise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalRoom {
    /// It has: the run may wait on a person.
    Left,
    /// Its open requests are at the plan's limit.
    Full,
}

/// Whether the plan of the tenant `driving` works in has room for one more
/// open approval request.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant's plan cannot be found.
/// - `AppError::Internal` when the plan or the count cannot be read.
async fn approval_room(driving: &Driving<'_>) -> Result<ApprovalRoom, AppError> {
    let checked = ensure_room_for_tenant(
        driving.ports.plan_room(),
        driving.tenant,
        ResourceKind::PendingApprovals,
    )
    .await;
    match checked {
        Ok(()) => Ok(ApprovalRoom::Left),
        Err(AppError::Forbidden(_)) => Ok(ApprovalRoom::Full),
        Err(other) => Err(other),
    }
}

/// Fails `run`, read at `version`, on the call it would have held for a
/// person, and keeps and records its end as any failed run's.
///
/// # Errors
///
/// - `AppError::Domain` when the run is not waiting on that call.
/// - `AppError::Internal` on persistence or audit failure.
async fn fail_at_approval_limit(
    driving: &Driving<'_>,
    auditor: &RequestAuditor,
    run: &mut AgentRun<ResolvedTenant>,
    version: RunVersion,
    label: &EventLabel,
) -> Result<(), AppError> {
    run.fail_at_approval_limit()
        .map_err(AppError::from_domain)?;
    finish(driving, auditor, Ending::of(run, version), label).await
}

/// Keeps the paused run with the approval request it raised and the record
/// of the pause, then gives up its lease.
///
/// A pause keeps any stop request: a stop that lands while it pauses must
/// still be there when an approval wakes it. Failing to raise the request
/// fails the pause, since a run waiting on a decision nobody can see waits
/// for nothing. A person who paused the run first keeps their pause, and
/// nothing is raised.
///
/// The request counts against the tenant's plan limit on open requests.
/// [`conclude`] fails the run at the limit before it gets here; the check
/// is made again in the unit that keeps the request, so two drives racing
/// for the last place cannot both take it. The one that loses keeps
/// nothing and is refused, and its job, tried again, finds the plan full
/// and fails its run.
async fn pause(
    turn: &Turn<'_>,
    auditor: &RequestAuditor,
    run: &mut AgentRun<ResolvedTenant>,
    version: RunVersion,
    approval: ApprovalRequest<ResolvedTenant>,
) -> Result<(), AppError> {
    let driving = turn.driving;
    let kept = async {
        ensure_room_for_tenant(
            driving.ports.plan_room(),
            driving.tenant,
            ResourceKind::PendingApprovals,
        )
        .await?;
        saved(driving, run, version).await?;
        driving
            .ports
            .stores
            .approval_store
            .save(driving.tenant, &approval)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ActorRef::System, run.take_events(driving.tenant))
            .await
            .or_internal()
    };
    yield_to_people(kept_together(driving.ports.unit_of_work.as_ref(), kept).await)?;
    driving.ports.run_lease.release(run.id()).await;
    Ok(())
}

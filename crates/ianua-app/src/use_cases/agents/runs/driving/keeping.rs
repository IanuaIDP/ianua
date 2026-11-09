//! How the worker keeps a run it drives in step with the stored one.
//!
//! People change a run while a worker drives it: they pause it, or stop
//! it. The worker writes each step over the version it last read or wrote,
//! never over a person's change. When the stored run moved on, the worker
//! takes the stored run as it now stands, with its conversation rebuilt
//! from the steps it holds, and goes on from there or stops.

use ianua_domain::domains::agents::execution::run::AgentRun;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::AgentRunId;

use crate::error::{AppError, OrInternal};
use crate::ports::agents::RunVersion;
use crate::use_cases::agents::runs::driving::conversation::conversation_so_far;
use crate::use_cases::agents::runs::driving::drive::Driving;
use crate::use_cases::agents::runs::driving::step::{Progress, Turn};

/// Why a run's write was refused: a person changed it after the worker last
/// read or wrote it.
pub(in crate::use_cases::agents::runs) const CHANGED_MEANWHILE: &str =
    "a person changed the run while it was driven";

/// Saves `run` over the version `read`, and gives back the version it is
/// stored at now.
///
/// # Errors
///
/// - `AppError::Conflict` when a person changed the stored run since `read`.
/// - `AppError::Internal` on persistence failure.
pub(in crate::use_cases::agents::runs) async fn saved(
    driving: &Driving<'_>,
    run: &AgentRun<ResolvedTenant>,
    read: RunVersion,
) -> Result<RunVersion, AppError> {
    driving
        .ports
        .stores
        .run_store
        .save_unchanged_since(driving.tenant, run, read)
        .await
        .map_err(|e| match e {
            DomainError::Conflict(_) => AppError::Conflict(CHANGED_MEANWHILE.to_owned().into()),
            other => AppError::internal(other),
        })
}

/// Saves the step the run just took. When a person changed the run
/// meanwhile, their change stands: the worker catches up with it and the
/// step it took is not kept.
///
/// # Errors
///
/// - `AppError::Conflict` when the run was removed while it was driven.
/// - `AppError::Internal` on persistence failure.
pub(in crate::use_cases::agents::runs) async fn keep(
    turn: &Turn<'_>,
    progress: &mut Progress,
) -> Result<(), AppError> {
    match saved(turn.driving, &progress.run, progress.version).await {
        Ok(version) => {
            progress.version = version;
            Ok(())
        }
        Err(AppError::Conflict(_)) => {
            tracing::warn!("a person changed the run during a step; the step is not kept");
            let stored = stored_run(turn.driving, progress.run.id()).await?;
            catch_up(turn, progress, stored);
            Ok(())
        }
        Err(other) => Err(other),
    }
}

/// Whether a person changed the run since the worker last read or wrote
/// it, catching up with their change when they did.
///
/// # Errors
///
/// - `AppError::Conflict` when the run was removed while it was driven.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::agents::runs) async fn moved_on(
    turn: &Turn<'_>,
    progress: &mut Progress,
) -> Result<bool, AppError> {
    let stored = stored_run(turn.driving, progress.run.id()).await?;
    if RunVersion::of(&stored) == progress.version {
        return Ok(false);
    }
    catch_up(turn, progress, stored);
    Ok(true)
}

/// Takes `stored` as the run the worker drives, with what its model is
/// shown rebuilt from the steps it holds.
fn catch_up(turn: &Turn<'_>, progress: &mut Progress, stored: AgentRun<ResolvedTenant>) {
    progress.version = RunVersion::of(&stored);
    progress.messages = conversation_so_far(turn.toolbox.offered(), &stored);
    progress.run = stored;
}

/// The run `id` as stored now.
///
/// # Errors
///
/// - `AppError::Conflict` when it was removed while it was driven.
/// - `AppError::Internal` on storage failure.
async fn stored_run(
    driving: &Driving<'_>,
    id: &AgentRunId,
) -> Result<AgentRun<ResolvedTenant>, AppError> {
    driving
        .ports
        .stores
        .run_store
        .find_by_id(driving.tenant, id)
        .await
        .or_internal()?
        .ok_or_else(|| {
            AppError::Conflict(message!(
                "agents-the-run-was-removed-while-it",
                "the run was removed while it was driven"
            ))
        })
}

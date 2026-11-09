//! How a driven run ends: kept with the approvals withdrawn with it and the
//! record of both, in one unit, unless a person changed the run first.

use ianua_domain::domains::agents::execution::run::{AgentRun, RunStatus};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::EventLabel;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::RunVersion;
use crate::services::kept_together::kept_together;
use crate::tenancy::ScopedTenant;
use crate::use_cases::agents::runs::control::stopping::{Withdrawal, withdrawals_recorded};
use crate::use_cases::agents::runs::driving::drive::Driving;
use crate::use_cases::agents::runs::driving::keeping::{CHANGED_MEANWHILE, saved};

/// A run as it ended, at the version the worker last read or wrote, with
/// the approvals withdrawn when it was stopped on an order.
pub(in crate::use_cases::agents::runs::driving) struct Ending<'a> {
    run: &'a mut AgentRun<ResolvedTenant>,
    version: RunVersion,
    withdrawal: Option<&'a mut Withdrawal>,
}

impl<'a> Ending<'a> {
    /// `run`, read at `version`, ended with nothing withdrawn.
    pub(in crate::use_cases::agents::runs::driving) fn of(
        run: &'a mut AgentRun<ResolvedTenant>,
        version: RunVersion,
    ) -> Self {
        Self {
            run,
            version,
            withdrawal: None,
        }
    }

    /// `run` as the loop leaves it at `version`, with what was withdrawn
    /// when it stopped. A run still running here has used its steps, and
    /// fails.
    pub(in crate::use_cases::agents::runs::driving) fn closing(
        run: &'a mut AgentRun<ResolvedTenant>,
        version: RunVersion,
        withdrawal: Option<&'a mut Withdrawal>,
    ) -> Self {
        if run.status() == RunStatus::Running {
            run.fail();
        }
        Self {
            run,
            version,
            withdrawal,
        }
    }
}

/// Keeps the ended run, any approvals withdrawn with it and the record of
/// both together, then lets go of it: its lease, and any stop order, which
/// has nothing left to stop.
///
/// A person who paused the run after its last step keeps their pause: the
/// end is not kept, and the worker gives back its lease.
pub(in crate::use_cases::agents::runs::driving) async fn finish(
    driving: &Driving<'_>,
    auditor: &RequestAuditor,
    ending: Ending<'_>,
    label: &EventLabel,
) -> Result<(), AppError> {
    let Ending {
        run,
        version,
        mut withdrawal,
    } = ending;
    let ended = async {
        saved(driving, run, version).await?;
        save_withdrawn(driving, withdrawal.as_deref_mut()).await?;
        auditor
            .dispatch(&ending_record(driving.tenant, run, withdrawal, label))
            .await
            .or_internal()
    };
    let kept = yield_to_people(kept_together(driving.ports.unit_of_work.as_ref(), ended).await)?;
    driving.ports.run_lease.release(run.id()).await;
    if kept == Kept::Yes {
        driving
            .ports
            .run_cancellation
            .clear(driving.tenant, run.id())
            .await;
    }
    Ok(())
}

/// Whether the worker's last write of a run was kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::use_cases::agents::runs::driving) enum Kept {
    /// It was.
    Yes,
    /// A person changed the run first, and their change stands.
    YieldedToAPerson,
}

/// `written`, with a write refused because a person changed the run first
/// read as yielding to them rather than as a failure.
pub(in crate::use_cases::agents::runs::driving) fn yield_to_people(
    written: Result<(), AppError>,
) -> Result<Kept, AppError> {
    match written {
        Ok(()) => Ok(Kept::Yes),
        Err(AppError::Conflict(reason)) if reason == CHANGED_MEANWHILE => {
            tracing::warn!("a person changed the run after its last step; their change stands");
            Ok(Kept::YieldedToAPerson)
        }
        Err(other) => Err(other),
    }
}

/// Saves every approval `withdrawal` withdrew. One decided or run out
/// since it was read no longer waits on anybody: it is left as its
/// decision put it, and dropped from the withdrawal, so the end is kept
/// and never records taking back a request it did not take back.
async fn save_withdrawn(
    driving: &Driving<'_>,
    withdrawal: Option<&mut Withdrawal>,
) -> Result<(), AppError> {
    let Some(withdrawal) = withdrawal else {
        return Ok(());
    };
    let mut kept = Vec::with_capacity(withdrawal.approvals.len());
    for approval in withdrawal.approvals.drain(..) {
        match driving
            .ports
            .stores
            .approval_store
            .save(driving.tenant, &approval)
            .await
        {
            Ok(()) => kept.push(approval),
            Err(DomainError::Conflict(_)) => {}
            Err(failed) => return Err(AppError::internal(failed)),
        }
    }
    withdrawal.approvals = kept;
    Ok(())
}

/// What a run's end records: the end itself, by the system, its agent
/// named `label`, then each approval withdrawn with it, by whoever stopped
/// it.
fn ending_record(
    tenant: &ScopedTenant,
    run: &mut AgentRun<ResolvedTenant>,
    withdrawal: Option<&mut Withdrawal>,
    label: &EventLabel,
) -> Vec<DomainEvent> {
    run.announce_end(label.clone());
    let mut recorded: Vec<DomainEvent> = run
        .take_events(tenant)
        .into_iter()
        .map(DomainEvent::system)
        .collect();
    let Some(withdrawal) = withdrawal else {
        return recorded;
    };
    recorded.extend(withdrawals_recorded(
        &mut withdrawal.approvals,
        tenant,
        label,
        &withdrawal.by,
    ));
    recorded
}

//! The consumers that act on an event themselves rather than plan jobs
//! from it: the agents' monitors over the actions and refused ways out
//! the gateway reports, and the settling of a finished agent run on the
//! workflow step that started it.
//!
//! Each acts on an event once: a monitor notes the event in the same unit
//! of work as what it changed, and a settled step no longer waits on its
//! run. Every one hears tenants' events alone, the only ones they act on.
//! Events of one agent may be acted on out of order across workers; the
//! monitors judge each action by the time it happened, not by when it is
//! heard, so the window a meeting is looked for in holds either way.

use std::sync::Arc;

use ianua_app::use_cases::agents::intent::{
    DetectConvergencePorts, DetectConvergenceUseCase, EvaluateDriftPorts, EvaluateDriftUseCase,
    HearConvergenceUseCase, HearDriftUseCase, HearEgressDenialUseCase, HeardPorts,
    RespondToEgressDenialPorts, RespondToEgressDenialUseCase,
};
use ianua_app::use_cases::workflows::executions::{
    SettleAgentRunPorts, SettleAgentRunUseCase, SettleFinishedRunUseCase, Wakeups,
};
use ianua_infra::cache::CacheTouchLedger;
use ianua_infra::postgres::agents::{PgAgentStore, PgDelegationStore, PgRunStore};
use ianua_infra::postgres::shared::PgEventReactions;
use ianua_infra::postgres::workflows::PgWorkflowExecutionStore;

use crate::error::{PlatformError, ServerError};
use crate::worker::consumers::{Hears, Planned, Planner};
use crate::worker::handlers::workflows::{execution_lease, run_stops};
use crate::worker::parts::Parts;

/// The consumers acting on events themselves.
///
/// # Errors
///
/// [`ServerError`] when the convergence window does not fit a duration.
pub(super) fn monitors(parts: &Parts<'_>) -> Result<Vec<Arc<dyn Planner>>, ServerError> {
    Ok(vec![
        drift(parts),
        convergence(parts)?,
        egress_denials(parts),
        run_settlements(parts),
    ])
}

/// What every monitor notes the events it acted on through.
fn heard(parts: &Parts<'_>) -> HeardPorts {
    HeardPorts {
        reactions: Arc::new(PgEventReactions::new(Arc::clone(&parts.platform.databases))),
        unit_of_work: Arc::clone(&parts.platform.unit_of_work),
    }
}

/// Every action allowed or refused an agent, judged against its intent.
fn drift(parts: &Parts<'_>) -> Arc<dyn Planner> {
    let databases = &parts.platform.databases;
    let drift = EvaluateDriftUseCase::new(EvaluateDriftPorts {
        delegation_store: Arc::new(PgDelegationStore::new(Arc::clone(databases))),
        agent_store: Arc::new(PgAgentStore::new(Arc::clone(databases))),
    });
    let use_case = HearDriftUseCase::new(Arc::new(drift), heard(parts));
    Planned::of("agent_drift", Hears::Tenants, use_case)
}

/// Every request allowed an agent, checked for meeting another agent within
/// `AGENT_CONVERGENCE_WINDOW_HOURS`, the touches kept where every node
/// shares them.
///
/// # Errors
///
/// [`ServerError`] when the window does not fit a duration.
fn convergence(parts: &Parts<'_>) -> Result<Arc<dyn Planner>, ServerError> {
    let platform = parts.platform;
    let databases = &platform.databases;
    let window = time::Duration::try_from(parts.config.agents.lifetimes.convergence_window)
        .map_err(PlatformError::of("the convergence window"))?;
    let detect = DetectConvergenceUseCase::new(
        window,
        DetectConvergencePorts {
            ledger: Arc::new(CacheTouchLedger::new(Arc::clone(&platform.shared_state))),
            delegation_store: Arc::new(PgDelegationStore::new(Arc::clone(databases))),
            agent_store: Arc::new(PgAgentStore::new(Arc::clone(databases))),
        },
    );
    let use_case = HearConvergenceUseCase::new(Arc::new(detect), heard(parts));
    Ok(Planned::of("agent_convergence", Hears::Tenants, use_case))
}

/// Every way out refused a service an agent called, held against the
/// agent.
fn egress_denials(parts: &Parts<'_>) -> Arc<dyn Planner> {
    let databases = &parts.platform.databases;
    let respond = RespondToEgressDenialUseCase::new(RespondToEgressDenialPorts {
        delegation_store: Arc::new(PgDelegationStore::new(Arc::clone(databases))),
        agent_store: Arc::new(PgAgentStore::new(Arc::clone(databases))),
    });
    let use_case = HearEgressDenialUseCase::new(Arc::new(respond), heard(parts));
    Planned::of("agent_egress_denials", Hears::Tenants, use_case)
}

/// Every finished agent run settled on the workflow step that started it,
/// under the execution's lease, so no drive runs beside it.
fn run_settlements(parts: &Parts<'_>) -> Arc<dyn Planner> {
    let platform = parts.platform;
    let databases = &platform.databases;
    let settle = SettleAgentRunUseCase::new(SettleAgentRunPorts {
        executions: Arc::new(PgWorkflowExecutionStore::new(Arc::clone(databases))),
        runs: Arc::new(PgRunStore::new(Arc::clone(databases))),
        lease: execution_lease(parts),
        wakeups: Wakeups::new(Arc::clone(&parts.jobs)),
        run_stops: run_stops(parts),
        unit_of_work: Arc::clone(&platform.unit_of_work),
    });
    let use_case = SettleFinishedRunUseCase::new(Arc::new(settle));
    Planned::of("workflow_run_settlements", Hears::Tenants, use_case)
}

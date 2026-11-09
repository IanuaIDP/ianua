//! What the use cases a person steers a run with share: the run and its
//! agent, read at the version the change is made over, and the save that
//! refuses to overwrite a change made meanwhile.

use ianua_domain::domains::agents::execution::run::AgentRun;
use ianua_domain::domains::agents::execution::tool::AgentTool;
use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::oversight::approval::ApprovalRequest;
use ianua_domain::domains::agents::oversight::approval_status::ApprovalStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentId, AgentRunId};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::agents::{AgentStore, ApprovalStore, RunStore, RunVersion, ToolStore};
use crate::services::lookup::existing_agent;
use crate::tenancy::ScopedTenant;
use crate::use_cases::agents::lookup::owned_run;

/// A run as a person found it, with its agent and the version it was read
/// at.
pub(in crate::use_cases::agents::runs) struct SteeredRun {
    /// The execution snapshot the person is changing.
    pub(in crate::use_cases::agents::runs) run: AgentRun<ResolvedTenant>,
    /// The run's agent.
    pub(in crate::use_cases::agents::runs) agent: AgentIdentity<ResolvedTenant>,
    /// The version the run was read at.
    pub(in crate::use_cases::agents::runs) version: RunVersion,
}

/// Where a steered run and its agent are read.
#[derive(Clone, Copy)]
pub(in crate::use_cases::agents::runs) struct SteeringStores<'a> {
    /// Loads and saves executions with their concurrency versions.
    pub(in crate::use_cases::agents::runs) runs: &'a dyn RunStore,
    /// Loads the identity whose ownership controls the execution.
    pub(in crate::use_cases::agents::runs) agents: &'a dyn AgentStore,
}

/// The run `run_id` of `agent_id`, with its agent, as stored now.
///
/// # Errors
///
/// - `AppError::NotFound` when the run does not exist under this agent, or
///   its agent is gone.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::agents::runs) async fn steered_run(
    stores: SteeringStores<'_>,
    tenant: &ScopedTenant,
    agent_id: &AgentId,
    run_id: &AgentRunId,
) -> Result<SteeredRun, AppError> {
    let run = owned_run(stores.runs, tenant, agent_id, run_id).await?;
    let agent = existing_agent(stores.agents, tenant, run.agent_id()).await?;
    Ok(SteeredRun {
        version: RunVersion::of(&run),
        run,
        agent,
    })
}

/// The approval request `run` raised for the call it holds, while nobody
/// has decided it.
///
/// # Errors
///
/// - `AppError::NotFound` when the run holds no open approval request.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::agents::runs) async fn open_request_of(
    approvals: &dyn ApprovalStore,
    tenant: &ScopedTenant,
    run: &AgentRun<ResolvedTenant>,
) -> Result<ApprovalRequest<ResolvedTenant>, AppError> {
    approvals
        .list_for_agent(tenant, run.agent_id(), Some(ApprovalStatus::Pending))
        .await
        .or_internal()?
        .into_iter()
        .find(|approval| approval.run_id() == Some(run.id()))
        .or_not_found(message!(
            "agents-no-open-approval-for-that-run",
            "no open approval for that run"
        ))
}

/// The registered tool the call `run` holds is for.
///
/// # Errors
///
/// - `AppError::NotFound` when the run holds no call, or its tool is no
///   longer registered.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::agents::runs) async fn held_tool(
    tools: &dyn ToolStore,
    tenant: &ScopedTenant,
    run: &AgentRun<ResolvedTenant>,
) -> Result<AgentTool<ResolvedTenant>, AppError> {
    let held = run.pending().or_not_found(message!(
        "agents-the-run-holds-no-call",
        "the run holds no call"
    ))?;
    tools
        .list(tenant)
        .await
        .or_internal()?
        .into_iter()
        .find(|tool| tool.name().as_str() == held.tool())
        .or_not_found(message!(
            "agents-the-tool-of-the-held-call",
            "the tool of the held call is no longer registered"
        ))
}

/// Saves the run a person changed, over the version they read.
///
/// # Errors
///
/// - `AppError::Conflict` when the run changed since it was read, such as
///   by the worker taking a step. The person reads it again and decides
///   again.
/// - `AppError::Internal` on persistence failure.
pub(in crate::use_cases::agents::runs) async fn save_steered(
    runs: &dyn RunStore,
    tenant: &ScopedTenant,
    steered: &SteeredRun,
) -> Result<(), AppError> {
    match runs
        .save_unchanged_since(tenant, &steered.run, steered.version)
        .await
    {
        Ok(_) => Ok(()),
        Err(DomainError::Conflict(_)) => Err(AppError::Conflict(message!(
            "agents-the-run-moved-on-since-it",
            "the run moved on since it was read; read it again"
        ))),
        Err(other) => Err(AppError::internal(other)),
    }
}

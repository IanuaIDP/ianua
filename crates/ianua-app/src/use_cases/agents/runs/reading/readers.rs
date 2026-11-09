//! Who may read an agent's runs: its owner, or someone allowed to view
//! agents. A run shows its goal, every tool call and what each returned, so
//! reading it is reading what the agent read.

use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::AgentAction;
use ianua_domain::types::AgentId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::agents::AgentStore;
use crate::use_cases::agents::lookup::{AgentReach, owned_agent};

/// Where an agent's runs are read from, and who reads them.
pub(in crate::use_cases::agents::runs) struct RunReader<'a> {
    /// What the caller holds.
    pub(in crate::use_cases::agents::runs) authorities: &'a dyn TenantAuthorities,
    /// Loads identity ownership before allowing execution reads.
    pub(in crate::use_cases::agents::runs) agents: &'a dyn AgentStore,
}

/// Refuses `ctx` reading the runs of `agent_id` unless they own the agent
/// or may view agents.
///
/// # Errors
///
/// - `AppError::Unauthenticated` when the caller's session or key no longer
///   counts.
/// - `AppError::NotFound` when the tenant has no such agent, or the caller
///   neither owns it nor may view agents, so that an agent of someone
///   else's answers as one that does not exist.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::agents::runs) async fn ensure_may_read_runs(
    reader: &RunReader<'_>,
    ctx: &CallerContext,
    agent_id: &AgentId,
) -> Result<(), AppError> {
    let authority = reader.authorities.authority(ctx).await?;
    let control = AgentControl::new(&authority);
    let reach = AgentReach::Acting(AgentAction::View);
    owned_agent(reader.agents, &ctx.tenant(), agent_id, &control, reach).await?;
    Ok(())
}

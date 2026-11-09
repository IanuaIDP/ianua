//! Reading an agent, and what it holds, is for its owner, or someone allowed
//! to view agents: its delegations show what it can reach, and whose
//! authority it carries.

use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::AgentAction;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::AgentId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::agents::AgentStore;
use crate::use_cases::agents::lookup::{AgentReach, owned_agent};

/// The tenant's agent `agent_id`, once `ctx` may view it.
///
/// # Errors
///
/// - `AppError::Unauthenticated` when the caller's session or key no longer
///   counts.
/// - `AppError::NotFound` when the tenant has no such agent, or the caller
///   neither owns it nor may view agents, so that an agent of someone
///   else's answers as one that does not exist.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::agents) async fn viewed_agent(
    agents: &dyn AgentStore,
    authorities: &dyn TenantAuthorities,
    ctx: &CallerContext,
    agent_id: &AgentId,
) -> Result<AgentIdentity<ResolvedTenant>, AppError> {
    let authority = authorities.authority(ctx).await?;
    let control = AgentControl::new(&authority);
    let reach = AgentReach::Acting(AgentAction::View);
    owned_agent(agents, &ctx.tenant(), agent_id, &control, reach).await
}

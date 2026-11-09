//! Who may watch an agent: read what it did and the evidence ianua kept.
//!
//! An agent's record shows what it read and for whom, so it is as private
//! as the agent. Its owner may read it, and so may someone allowed to view
//! agents. An agent of another tenant, or one the person may not watch,
//! reads as missing.

use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::AgentAction;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::AgentId;

use crate::error::AppError;
use crate::ports::agents::AgentStore;
use crate::tenancy::ScopedTenant;
use crate::use_cases::agents::lookup::{AgentReach, owned_agent};

/// The agent `agent_id` names, once the person `authority` speaks for owns
/// it or may view agents.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such agent, or the person
///   neither owns it nor may view agents, so that an agent of someone
///   else's answers as one that does not exist.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::agents) async fn watched_agent(
    agents: &dyn AgentStore,
    authority: &TenantAuthority,
    tenant: &ScopedTenant,
    agent_id: &AgentId,
) -> Result<AgentIdentity<ResolvedTenant>, AppError> {
    let control = AgentControl::new(authority);
    let reach = AgentReach::Acting(AgentAction::View);
    owned_agent(agents, tenant, agent_id, &control, reach).await
}

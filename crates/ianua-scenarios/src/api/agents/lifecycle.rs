//! Making an agent, reading it, and changing its standing: suspending and
//! resuming it, stopping every agent at once, and the kill switch.

use super::of_agent;
use crate::api::{Request, TenantPath};
use crate::net::Call;
use crate::wire::agents::identity::{Agent, Contained, CreatedAgent, NewAgent, SuspendedAll};

/// `POST …/agents`: a new agent, owned by whoever makes it.
#[must_use]
pub fn create(tenant: &TenantPath, agent: &NewAgent) -> Request<CreatedAgent> {
    Request::of(Call::post(tenant.at("/agents")).json(agent))
}

/// `GET …/agents/{id}`.
#[must_use]
pub fn get(tenant: &TenantPath, agent_id: &str) -> Request<Agent> {
    Request::of(Call::get(of_agent(tenant, agent_id, "")))
}

/// `POST …/agents/{id}/suspend`: stops every delegation working until the
/// agent is resumed.
#[must_use]
pub fn suspend(tenant: &TenantPath, agent_id: &str) -> Request<()> {
    Request::of(Call::post(of_agent(tenant, agent_id, "/suspend")))
}

/// `POST …/agents/{id}/resume`: a suspended agent's delegations work
/// again; a revoked agent stays revoked.
#[must_use]
pub fn resume(tenant: &TenantPath, agent_id: &str) -> Request<()> {
    Request::of(Call::post(of_agent(tenant, agent_id, "/resume")))
}

/// `POST …/agents/{id}/require-reattestation`: the agent may not act until
/// it proves what it is again.
#[must_use]
pub fn require_reattestation(tenant: &TenantPath, agent_id: &str) -> Request<()> {
    Request::of(Call::post(of_agent(
        tenant,
        agent_id,
        "/require-reattestation",
    )))
}

/// `POST …/agents/{id}/contain`: the kill switch, revoking the agent, its
/// keys and every delegation it holds or handed on, for good.
#[must_use]
pub fn contain(tenant: &TenantPath, agent_id: &str) -> Request<Contained> {
    Request::of(Call::post(of_agent(tenant, agent_id, "/contain")))
}

/// `POST …/agents/suspend-all`: every active agent in the tenant stopped
/// at once, each to be resumed by hand.
#[must_use]
pub fn suspend_all(tenant: &TenantPath) -> Request<SuspendedAll> {
    Request::of(Call::post(tenant.at("/agents/suspend-all")))
}

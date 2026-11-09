//! Platform-run agents: starting a run, reading it and resuming it.

use super::of_agent;
use crate::api::{Request, TenantPath};
use crate::net::Call;
use crate::wire::agents::runs::{Run, StartRun};

/// `POST …/agents/{id}/runs`: accepted at once, driven by a worker.
#[must_use]
pub fn start(tenant: &TenantPath, agent_id: &str, run: &StartRun) -> Request<Run> {
    Request::of(Call::post(of_agent(tenant, agent_id, "/runs")).json(run))
}

/// `POST …/agents/{id}/runs/{run}/resume`: hands a paused run back to a
/// worker.
#[must_use]
pub fn resume(tenant: &TenantPath, agent_id: &str, run_id: &str) -> Request<Run> {
    Request::of(Call::post(of_agent(
        tenant,
        agent_id,
        &format!("/runs/{run_id}/resume"),
    )))
}

/// `GET …/agents/{id}/runs/{run}`.
#[must_use]
pub fn get(tenant: &TenantPath, agent_id: &str, run_id: &str) -> Request<Run> {
    Request::of(Call::get(of_agent(
        tenant,
        agent_id,
        &format!("/runs/{run_id}"),
    )))
}

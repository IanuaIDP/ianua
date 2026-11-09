//! An agent bootstrapping its key from a platform attestation.

use super::of_agent;
use crate::api::{Request, TenantPath};
use crate::net::Call;
use crate::wire::agents::attestation::{Bootstrap, Challenge};
use crate::wire::agents::identity::Credential;

/// `POST …/agents/{id}/bootstrap/challenge`: a single-use nonce to bind.
#[must_use]
pub fn challenge(tenant: &TenantPath, agent_id: &str) -> Request<Challenge> {
    Request::of(Call::post(of_agent(
        tenant,
        agent_id,
        "/bootstrap/challenge",
    )))
}

/// `POST …/agents/{id}/bootstrap`: the key, enrolled once the attestation
/// holds.
#[must_use]
pub fn bootstrap(
    tenant: &TenantPath,
    agent_id: &str,
    bootstrap: &Bootstrap,
) -> Request<Credential> {
    Request::of(Call::post(of_agent(tenant, agent_id, "/bootstrap")).json(bootstrap))
}

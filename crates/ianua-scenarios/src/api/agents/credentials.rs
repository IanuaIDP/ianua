//! An agent's keys: reading them and revoking one.

use super::of_agent;
use crate::api::{Request, TenantPath};
use crate::net::Call;
use crate::wire::agents::identity::Credential;

/// `GET …/agents/{id}/credentials`.
#[must_use]
pub fn list(tenant: &TenantPath, agent_id: &str) -> Request<Vec<Credential>> {
    Request::of(Call::get(of_agent(tenant, agent_id, "/credentials")))
}

/// `DELETE …/agents/{id}/credentials/{credential}`: the key verifies
/// nothing again, and every token it minted is refused.
#[must_use]
pub fn revoke(tenant: &TenantPath, agent_id: &str, credential_id: &str) -> Request<()> {
    let path = of_agent(tenant, agent_id, &format!("/credentials/{credential_id}"));
    Request::of(Call::delete(path))
}

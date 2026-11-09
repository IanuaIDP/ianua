//! An agent asking for a task token of its own.

use super::of_agent;
use crate::api::{Request, TenantPath};
use crate::net::Call;
use crate::wire::agents::authority::Granted;
use crate::wire::agents::token::TokenRequest;

/// `POST …/agents/{id}/token`: the assertion its key signed, exchanged for
/// a token capped to what it was granted.
#[must_use]
pub fn exchange(tenant: &TenantPath, agent_id: &str, request: &TokenRequest) -> Request<Granted> {
    Request::of(Call::post(of_agent(tenant, agent_id, "/token")).json(request))
}

/// The same exchange with a body written by hand, such as one naming a
/// field the API does not know.
#[must_use]
pub(crate) fn exchange_raw(
    tenant: &TenantPath,
    agent_id: &str,
    body: &serde_json::Value,
) -> Request<Granted> {
    Request::of(Call::post(of_agent(tenant, agent_id, "/token")).json(body))
}

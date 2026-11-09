//! The message relay, which an agent calls with its task token as the
//! bearer: it checks, reshapes, signs and records every message.

use crate::api::{Request, TenantPath};
use crate::net::Call;

/// `POST …/agents/messages/{topic}`: one message, in the agent's own area.
#[must_use]
pub fn publish(tenant: &TenantPath, topic: &str, message: &serde_json::Value) -> Request<()> {
    Request::of(Call::post(tenant.at(&format!("/agents/messages/{topic}"))).json(message))
}

//! A person granting an agent authority, reading what it holds, and the
//! agent passing part of it on.

use super::{ASSERTION_HEADER, of_agent};
use crate::api::{Request, TenantPath};
use crate::net::Call;
use crate::wire::agents::authority::{
    Attenuation, Delegation, Grant, Granted, ResourceDecision, ResourceGrant, ResourceRight,
};

/// `POST …/agents/{id}/grant`: a person hands the agent part of what they
/// hold.
#[must_use]
pub fn grant(tenant: &TenantPath, agent_id: &str, grant: &Grant) -> Request<Granted> {
    Request::of(Call::post(of_agent(tenant, agent_id, "/grant")).json(grant))
}

/// The same grant with a body written by hand, such as one naming a field
/// the API does not know.
#[must_use]
pub fn grant_raw(
    tenant: &TenantPath,
    agent_id: &str,
    body: &serde_json::Value,
) -> Request<Granted> {
    Request::of(Call::post(of_agent(tenant, agent_id, "/grant")).json(body))
}

/// `GET …/agents/{id}/delegations`: what the agent holds, with each
/// budget's use.
#[must_use]
pub fn list(tenant: &TenantPath, agent_id: &str) -> Request<Vec<Delegation>> {
    Request::of(Call::get(of_agent(tenant, agent_id, "/delegations")))
}

/// `DELETE …/agents/{id}/delegations/{delegation}`: the delegation and
/// everything passed on from it stop working on the next request.
#[must_use]
pub fn revoke(tenant: &TenantPath, agent_id: &str, delegation_id: &str) -> Request<()> {
    let path = of_agent(tenant, agent_id, &format!("/delegations/{delegation_id}"));
    Request::of(Call::delete(path))
}

/// `POST …/agents/{id}/delegations/{delegation}/attenuate`, signed in by
/// `assertion`: the agent holding the delegation passes part of it on.
#[must_use]
pub fn attenuate(
    tenant: &TenantPath,
    holder: Holder<'_>,
    assertion: &str,
    attenuation: &Attenuation,
) -> Request<Granted> {
    let rest = format!("/delegations/{}/attenuate", holder.delegation_id);
    let call = Call::post(of_agent(tenant, holder.agent_id, &rest))
        .json(attenuation)
        .header(ASSERTION_HEADER, assertion);
    Request::of(call)
}

/// `PUT …/resource-grants`: the resource graph records that the grant's
/// subject holds its relation on its object.
#[must_use]
pub fn grant_relation(tenant: &TenantPath, grant: &ResourceGrant) -> Request<()> {
    Request::of(Call::put(tenant.at("/resource-grants")).json(grant))
}

/// `POST …/agents/{id}/delegations/{delegation}/resources`: one relation
/// on one object added to a task the agent holds, the rest of it kept.
#[must_use]
pub fn add_resource(
    tenant: &TenantPath,
    holder: Holder<'_>,
    right: &ResourceRight,
) -> Request<Delegation> {
    let rest = format!("/delegations/{}/resources", holder.delegation_id);
    Request::of(Call::post(of_agent(tenant, holder.agent_id, &rest)).json(right))
}

/// `POST …/agents/{id}/authorize-resource`: whether the agent may use the
/// relation on the object, asked as a dry run.
#[must_use]
pub fn authorize_resource(
    tenant: &TenantPath,
    agent_id: &str,
    right: &ResourceRight,
) -> Request<ResourceDecision> {
    Request::of(Call::post(of_agent(tenant, agent_id, "/authorize-resource")).json(right))
}

/// The agent holding a delegation, and which delegation.
#[derive(Debug, Clone, Copy)]
pub struct Holder<'a> {
    /// Workload presenting its assertion to pass on the held authority.
    pub agent_id: &'a str,
    /// The delegation it holds.
    pub delegation_id: &'a str,
}

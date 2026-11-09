//! Delegation handlers: authority people hand to agents, passing part of it
//! on, the resources it covers, what it adds up to, and the relationship
//! graph resource authority comes from.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::agents::delegation::{RenewRequest, RevokeRequest};
use ianua_assembly::agents::AgentState;

use crate::dto::agents::capabilities::ResourceCapabilityDto;
use crate::dto::agents::delegation::{
    AttenuateDelegationBody, BlastRadiusResponse, DelegationResponse,
    EffectiveCapabilitiesResponse, GrantDelegationBody, GrantDelegationResponse, ResourceGrantBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::agents::AttenuatingCaller;
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::agents::{AgentDelegationPath, AgentPath};
use crate::response::{Created, NoContent};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/grant",
    tag = "Agents",
    request_body = GrantDelegationBody,
    responses(
        (status = 201, description = "Created", body = GrantDelegationResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden: more than the caller holds", body = ErrorBody),
        (status = 404, description = "Agent not found", body = ErrorBody),
        (status = 409, description = "Agent not active, or sender_constrained was asked for but the agent has no single active credential to bind", body = ErrorBody),
        (status = 422, description = "Validation error, or a field the body does not know", body = ErrorBody)
    )
)]
/// Grant a delegation
///
/// Delegates a slice of the caller's own authority to the agent: the
/// granted capabilities can never exceed what the caller holds. The grant
/// is bound by a lifetime, a maximum sub-delegation depth, and optionally a
/// task, an intent, a budget, a resource scope, the apps it reaches, an
/// approval gate and a sender constraint; under a `template_id` it must fit
/// that approved template. Returns the new delegation and its task token;
/// `403` if it asks for more than the caller holds, `404` if the agent does
/// not exist, `409` if the agent is not active or `sender_constrained` was
/// asked for but the agent has no single active credential to bind. Records
/// `agents.delegation_granted`. Requires `Agents(Delegate)`.
pub(crate) async fn grant_delegation(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
    Json(body): Json<GrantDelegationBody>,
) -> Result<Created<GrantDelegationResponse>, ApiError> {
    let granted = agents
        .delegation
        .grant
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.agent())?,
        )
        .await?;
    Ok(Created(GrantDelegationResponse::from(granted)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/delegations/{delegation_id}/attenuate",
    tag = "Agents",
    request_body = AttenuateDelegationBody,
    params(
        ("ianua-agent-assertion" = Option<String>, Header, description = "The assertion the holding agent signed, when the agent itself passes it on")
    ),
    responses(
        (status = 201, description = "Created", body = GrantDelegationResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden: more than the parent grants, deeper or longer than it allows, a wider limit or a budget past what it has left, or the assertion refused", body = ErrorBody),
        (status = 404, description = "Delegation or agent not found", body = ErrorBody),
        (status = 409, description = "The receiving agent is not active, or the parent is sender-constrained and the receiving agent has no single active credential to bind", body = ErrorBody),
        (status = 422, description = "Validation error, or a field the body does not know", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Sub-delegate a delegation
///
/// Narrows one of the agent's delegations into a child for another agent:
/// the child can never exceed the parent, its depth is one greater, and it
/// cannot outlive it. It may set its own budget, paths, apps, approval rule
/// and key binding, each inside the parent's; its budget shares the
/// parent's with the children already passed on. A sender-constrained
/// parent stays sender-constrained on the child, and an approval rule stays
/// too. Mints a task token for the receiving agent.
///
/// Passed on by a person with a say over the holding agent, signed in as
/// any tenant caller, or by the holding agent itself, signing in with an
/// assertion its own key signed, sent in the `Ianua-Agent-Assertion`
/// header. Rate limited per address.
///
/// `403` on escalation, exceeded depth or a refused assertion, `404` if the
/// delegation or the receiving agent is missing, `409` if the receiving
/// agent is not active or (under a sender-constrained parent) has no active
/// credential to bind. Records `agents.delegation_granted`.
pub(crate) async fn attenuate_delegation(
    State(agents): State<AgentState>,
    caller: AttenuatingCaller,
    Path(path): Path<AgentDelegationPath>,
    Json(body): Json<AttenuateDelegationBody>,
) -> Result<Created<GrantDelegationResponse>, ApiError> {
    let granted = agents
        .delegation
        .attenuate
        .execute(
            &caller.by,
            &caller.auditor,
            body.into_request(path.agent(), path.delegation())?,
        )
        .await?;
    Ok(Created(GrantDelegationResponse::from(granted)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/delegations/{delegation_id}/resources",
    tag = "Agents",
    request_body = ResourceCapabilityDto,
    responses(
        (status = 200, description = "Success", body = DelegationResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden: more than the caller holds, or for a sub-delegation more than its parent grants", body = ErrorBody),
        (status = 404, description = "Delegation or agent not found", body = ErrorBody),
        (status = 422, description = "Validation error, or the delegation is revoked", body = ErrorBody)
    )
)]
/// Grant a resource to a delegation
///
/// Adds one `{relation, resource}` to a granted delegation's resources,
/// without granting the whole delegation again. The caller must hold the
/// resource themselves (the same rule as granting or passing on), and for
/// a sub-delegation the resource must also be within what its parent
/// grants. Granting one already held changes nothing. Records
/// `agents.delegation_resource_granted`. Requires `Agents(Delegate)`.
pub(crate) async fn grant_delegation_resource(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentDelegationPath>,
    Json(body): Json<ResourceCapabilityDto>,
) -> Result<Json<DelegationResponse>, ApiError> {
    let delegation = agents
        .delegation
        .grant_resource
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.granted_onto(path.agent(), path.delegation())?,
        )
        .await?;
    Ok(Json(DelegationResponse::from(delegation)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/delegations/{delegation_id}/resources",
    tag = "Agents",
    request_body = ResourceCapabilityDto,
    responses(
        (status = 200, description = "Success", body = DelegationResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Delegation or agent not found", body = ErrorBody),
        (status = 422, description = "Validation error, or the delegation is revoked", body = ErrorBody)
    )
)]
/// Revoke a resource from a delegation
///
/// Removes one `{relation, resource}` from a delegation, leaving the rest
/// of what it grants, and the delegation itself, untouched. Revoking one
/// not held changes nothing. Records `agents.delegation_resource_revoked`.
/// Requires the agent's owner or `Agents(Delegate)`.
pub(crate) async fn revoke_delegation_resource(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentDelegationPath>,
    Json(body): Json<ResourceCapabilityDto>,
) -> Result<Json<DelegationResponse>, ApiError> {
    let delegation = agents
        .delegation
        .revoke_resource
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.revoked_from(path.agent(), path.delegation())?,
        )
        .await?;
    Ok(Json(DelegationResponse::from(delegation)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/delegations",
    tag = "Agents",
    responses(
        (status = 200, description = "Success", body = Vec<DelegationResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// List an agent's delegations
///
/// Returns the delegations the agent holds, each with its delegator (and
/// their name), what it grants, its expiry, its parent for a
/// sub-delegation, how much of its budget is used, and whether it was
/// revoked. Requires the agent's owner or `Agents(View)`.
pub(crate) async fn list_delegations(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
) -> Result<Json<Vec<DelegationResponse>>, ApiError> {
    let delegations = agents
        .delegation
        .list
        .execute(&tenant.caller, path.agent())
        .await?;
    Ok(Json(
        delegations
            .into_iter()
            .map(DelegationResponse::from)
            .collect(),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/me/delegations",
    tag = "Agents",
    responses(
        (status = 200, description = "Success", body = Vec<DelegationResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List the delegations I granted
///
/// Returns the delegations the caller granted to agents in this tenant, in
/// the shape an agent's list answers: the agents they act through, what
/// each may do, until when, and whether it was revoked. Every person may
/// read their own.
pub(crate) async fn list_my_delegations(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<DelegationResponse>>, ApiError> {
    let delegations = agents
        .delegation
        .list_granted
        .execute(&tenant.caller, ())
        .await?;
    Ok(Json(
        delegations
            .into_iter()
            .map(DelegationResponse::from)
            .collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/delegations/{delegation_id}/renew",
    tag = "Agents",
    responses(
        (status = 200, description = "Renewed", body = DelegationResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden: not its delegator, or no longer holding what it grants", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Not granted by a person at the top of its chain, or revoked or expired", body = ErrorBody)
    )
)]
/// Renew a delegation
///
/// Gives a delegation its lifetime again, counted from now, so an agent
/// working on keeps its authority without a new grant. Only the person who
/// granted it renews it, and only while they still hold everything it
/// grants, to an agent that may still receive authority. Only a delegation
/// a person granted at the top of its chain is renewed; one expired or
/// revoked is granted anew instead (`422`). Records
/// `agents.delegation_renewed` with when it now expires.
pub(crate) async fn renew_delegation(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentDelegationPath>,
) -> Result<Json<DelegationResponse>, ApiError> {
    let delegation = agents
        .delegation
        .renew
        .execute(
            &tenant.caller,
            &tenant.auditor,
            RenewRequest {
                agent_id: path.agent(),
                delegation_id: path.delegation(),
            },
        )
        .await?;
    Ok(Json(DelegationResponse::from(delegation)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/blast-radius",
    tag = "Agents",
    responses(
        (status = 200, description = "Success", body = BlastRadiusResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Get an agent's blast radius
///
/// Previews what containing the agent would cut: every delegation it holds
/// and every delegation descended from those, the exact set the kill-switch
/// revokes, with how many delegations and distinct agents that is. Requires
/// the agent's owner or `Agents(View)`.
pub(crate) async fn get_blast_radius(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
) -> Result<Json<BlastRadiusResponse>, ApiError> {
    let delegations = agents
        .delegation
        .blast_radius
        .execute(&tenant.caller, path.agent())
        .await?;
    Ok(Json(BlastRadiusResponse::of(path.agent(), delegations)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/delegations/{delegation_id}",
    tag = "Agents",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Revoke a delegation
///
/// Revokes a delegation and every delegation descended from it: a
/// delegation is only valid while each one above it is, so the whole
/// subtree goes at once. `404` if the delegation is not the agent's.
/// Records `agents.delegation_revoked`. Requires the agent's owner or
/// `Agents(Delegate)`.
pub(crate) async fn revoke_delegation(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentDelegationPath>,
) -> Result<NoContent, ApiError> {
    agents
        .delegation
        .revoke
        .execute(
            &tenant.caller,
            &tenant.auditor,
            RevokeRequest {
                agent_id: path.agent(),
                delegation_id: path.delegation(),
            },
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/effective-capabilities",
    tag = "Agents",
    responses(
        (status = 200, description = "Success", body = EffectiveCapabilitiesResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Get an agent's effective capabilities
///
/// Returns the union of what the agent's live delegations grant: the
/// authority the proxy would enforce right now. Revoked or expired
/// delegations add nothing. `404` if the agent does not exist. Requires the
/// agent's owner or `Agents(View)`.
pub(crate) async fn effective_capabilities(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
) -> Result<Json<EffectiveCapabilitiesResponse>, ApiError> {
    let effective = agents
        .delegation
        .effective_capabilities
        .execute(&tenant.caller, path.agent())
        .await?;
    Ok(Json(EffectiveCapabilitiesResponse::of(
        path.agent(),
        &effective,
    )))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/resource-grants",
    tag = "Agents",
    request_body = ResourceGrantBody,
    responses(
        (status = 204, description = "Granted"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Grant a resource relation to a principal
///
/// Records that `subject` holds `relation` on `resource` in the
/// relationship graph. The graph is where resource authority comes from:
/// delegation reads it to decide whether a caller may hand a resource
/// capability to an agent, so nothing can be delegated over a resource
/// until it is granted here.
///
/// Authority is passed on, never made up: a caller may grant only a
/// relation they hold themselves. `Agents(Manage)` is the root that can
/// seed a relation nobody holds yet. Granting one already held changes
/// nothing. Records `agents.resource_relation_granted`. Requires
/// `Agents(Delegate)`.
pub(crate) async fn grant_resource_relation(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Json(body): Json<ResourceGrantBody>,
) -> Result<NoContent, ApiError> {
    agents
        .delegation
        .grant_relation
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/resource-grants",
    tag = "Agents",
    request_body = ResourceGrantBody,
    responses(
        (status = 204, description = "Revoked"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Revoke a resource relation from a principal
///
/// Removes the grant. Held to the same rule as granting: taking away a
/// relation you could not have given is still a change to authority you do
/// not hold. Removing a grant that does not exist succeeds. Records
/// `agents.resource_relation_revoked`. Requires `Agents(Delegate)`.
pub(crate) async fn revoke_resource_relation(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Json(body): Json<ResourceGrantBody>,
) -> Result<NoContent, ApiError> {
    agents
        .delegation
        .revoke_relation
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(NoContent)
}

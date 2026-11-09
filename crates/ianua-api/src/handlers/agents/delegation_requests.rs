//! Delegation request handlers: an agent asking a person for a delegation,
//! signed in as itself, and people granting, refusing and reading what
//! agents asked.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::agents::delegation::{
    ApproveRequestRequest, DenyRequestRequest, RequestsOf,
};
use ianua_assembly::agents::AgentState;

use crate::dto::agents::delegation::{
    DelegationRequestResponse, DelegationResponse, RequestDelegationBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::agents::AskingAgentCaller;
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::agents::{AgentDelegationRequestPath, AgentPath};
use crate::response::Created;

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/delegation-requests",
    tag = "Agents",
    request_body = RequestDelegationBody,
    params(
        ("ianua-agent-assertion" = String, Header, description = "An assertion the agent's own key signed, made for the deployment's token audience")
    ),
    responses(
        (status = 201, description = "Asked: the person is told", body = DelegationRequestResponse),
        (status = 401, description = "No assertion, or no such tenant", body = ErrorBody),
        (status = 403, description = "The assertion does not sign the agent in, or it may not act", body = ErrorBody),
        (status = 404, description = "The person asked is not one of the tenant's", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests open, or made this hour", body = ErrorBody)
    )
)]
/// Ask a person for a delegation (agent)
///
/// An agent that needs more than it holds asks a person for it, signed in
/// as itself with an assertion its own key signed in the
/// `Ianua-Agent-Assertion` header: what it needs (`granted` and the limits
/// asked for), of whom (`asked_of`, a tenant user or an organization
/// member), and why (`reason`). Asking grants nothing: the person sees the
/// request and grants or refuses it, within a day. An agent keeps only a
/// few requests open and makes only so many an hour (`429`). No session.
/// Rate limited per address. Records `agents.delegation_requested`.
pub(crate) async fn request_delegation(
    State(agents): State<AgentState>,
    agent: AskingAgentCaller,
    Json(body): Json<RequestDelegationBody>,
) -> Result<Created<DelegationRequestResponse>, ApiError> {
    let request = agents
        .requests
        .request
        .execute(&agent.asking, &agent.auditor, body.try_into()?)
        .await?;
    Ok(Created(DelegationRequestResponse::from(&request)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/delegation-requests",
    tag = "Agents",
    responses(
        (status = 200, description = "Success", body = Vec<DelegationRequestResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Agent not found", body = ErrorBody)
    )
)]
/// List an agent's delegation requests
///
/// Returns everything the agent asked of anyone, newest first, answered
/// or not. Requires the agent's owner or `Agents(View)`.
pub(crate) async fn list_agent_delegation_requests(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
) -> Result<Json<Vec<DelegationRequestResponse>>, ApiError> {
    let requests = agents
        .requests
        .list
        .execute(&tenant.caller, RequestsOf::Agent(path.agent()))
        .await?;
    Ok(Json(
        requests
            .iter()
            .map(DelegationRequestResponse::from)
            .collect(),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/me/delegation-requests",
    tag = "Agents",
    responses(
        (status = 200, description = "Success", body = Vec<DelegationRequestResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List the delegation requests asked of me
///
/// Returns what agents asked of the caller, newest first, answered or not,
/// so they can grant or refuse each. Every person may read their own.
pub(crate) async fn list_my_delegation_requests(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<DelegationRequestResponse>>, ApiError> {
    let requests = agents
        .requests
        .list
        .execute(&tenant.caller, RequestsOf::AskedOfCaller)
        .await?;
    Ok(Json(
        requests
            .iter()
            .map(DelegationRequestResponse::from)
            .collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/delegation-requests/{request_id}/approve",
    tag = "Agents",
    responses(
        (status = 201, description = "Granted: the delegation it became", body = DelegationResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Not the person asked, or more than they hold", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Answered already or lapsed", body = ErrorBody)
    )
)]
/// Grant a delegation request
///
/// The person an agent asked grants what it asked for, as a delegation
/// from them, checked like any grant: they must own the agent or be
/// allowed to delegate to agents, and it is held to what they hold now,
/// never to what the agent asked for. The agent takes its task token from
/// the delegation through the token exchange. Records
/// `agents.delegation_request_approved` and the grant.
pub(crate) async fn approve_delegation_request(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentDelegationRequestPath>,
) -> Result<Created<DelegationResponse>, ApiError> {
    let delegation = agents
        .requests
        .approve
        .execute(
            &tenant.caller,
            &tenant.auditor,
            ApproveRequestRequest {
                agent_id: path.agent(),
                request_id: path.request(),
            },
        )
        .await?;
    Ok(Created(DelegationResponse::from(delegation)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/delegation-requests/{request_id}/deny",
    tag = "Agents",
    responses(
        (status = 200, description = "Refused", body = DelegationRequestResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Neither the person asked nor allowed to manage agents", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Answered already or lapsed", body = ErrorBody)
    )
)]
/// Refuse a delegation request
///
/// Refuses what an agent asked for. The person asked refuses it, and so
/// may someone allowed to manage agents, to stop an agent pestering
/// people. A refused request grants nothing and is never answered again.
/// Records `agents.delegation_request_denied`.
pub(crate) async fn deny_delegation_request(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentDelegationRequestPath>,
) -> Result<Json<DelegationRequestResponse>, ApiError> {
    let request = agents
        .requests
        .deny
        .execute(
            &tenant.caller,
            &tenant.auditor,
            DenyRequestRequest {
                agent_id: path.agent(),
                request_id: path.request(),
            },
        )
        .await?;
    Ok(Json(DelegationRequestResponse::from(&request)))
}

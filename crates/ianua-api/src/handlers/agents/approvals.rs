//! Agent approval handlers: actions held for a person, the person
//! approving or denying them, and the gateway's sealed questions about
//! them on the internal listener.

use axum::body::Bytes;
use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::agents::approvals::{
    ApproveActionRequest, DenyActionRequest, GetFactsRequest, ListPendingRequest, RelayRequest,
};
use ianua_assembly::agents::AgentState;

use crate::dto::agents::approvals::{
    ApprovalFactsResponse, ApprovalQueryParams, ApprovalResponse, RelayedApprovalAnswer,
    RequestApprovalBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::agents::StepUpCode;
use crate::extractors::authentication::GatewayRelay;
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::agents::{AgentApprovalPath, AgentPath};
use crate::extractors::query::Query;
use crate::response::Created;

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/approvals",
    tag = "Agents",
    request_body = RequestApprovalBody,
    responses(
        (status = 201, description = "Created: a pending approval", body = ApprovalResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Agent or delegation not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Plan limit reached", body = ErrorBody)
    )
)]
/// Open a person's approval for a held action
///
/// Records a pending approval for an agent's call under one of its
/// delegations, naming the exact call (`method` and `target`), and lets the
/// people who decide know. The call proceeds only once approved. The people
/// behind the delegation may not approve it. Records
/// `agents.approval_requested`. Requires the agent's owner or
/// `Agents(Update)`.
pub(crate) async fn request_approval(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
    Json(body): Json<RequestApprovalBody>,
) -> Result<Created<ApprovalResponse>, ApiError> {
    let approval = agents
        .approvals
        .request
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.agent())?,
        )
        .await?;
    Ok(Created(ApprovalResponse::from(&approval)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/approvals",
    tag = "Agents",
    params(ApprovalQueryParams),
    responses(
        (status = 200, description = "Success", body = Vec<ApprovalResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Unknown status filter", body = ErrorBody)
    )
)]
/// List every agent's approvals
///
/// Returns the approval requests of every agent in the tenant, in the shape
/// an agent's own list answers. `?status=pending` is the tenant's approval
/// inbox; leaving it out returns the full history. Decide each through its
/// agent's `.../approvals/{approval_id}/approve` or `/deny`. Requires
/// `Agents(View)`.
pub(crate) async fn list_tenant_approvals(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Query(query): Query<ApprovalQueryParams>,
) -> Result<Json<Vec<ApprovalResponse>>, ApiError> {
    let approvals = agents
        .approvals
        .list_tenant
        .execute(&tenant.caller, query.status()?)
        .await?;
    Ok(Json(approvals.iter().map(ApprovalResponse::from).collect()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/approvals",
    tag = "Agents",
    params(ApprovalQueryParams),
    responses(
        (status = 200, description = "Success", body = Vec<ApprovalResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Agent not found", body = ErrorBody),
        (status = 422, description = "Unknown status filter", body = ErrorBody)
    )
)]
/// List an agent's approvals
///
/// Returns the agent's approval requests, newest first. `?status=` narrows
/// to one lifecycle state; leaving it out returns the full history,
/// resolved requests included: an approval's value as a record outlives
/// its decision window. Each entry names who asked and, once decided, who
/// decided and when. Requires the agent's owner or `Agents(View)`.
pub(crate) async fn list_approvals(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
    Query(query): Query<ApprovalQueryParams>,
) -> Result<Json<Vec<ApprovalResponse>>, ApiError> {
    let approvals = agents
        .approvals
        .list
        .execute(
            &tenant.caller,
            ListPendingRequest {
                agent_id: path.agent(),
                status: query.status()?,
            },
        )
        .await?;
    Ok(Json(approvals.iter().map(ApprovalResponse::from).collect()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/approvals/{approval_id}/approve",
    tag = "Agents",
    responses(
        (status = 200, description = "Approved", body = ApprovalResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or a fresh second-factor code is needed", body = ErrorBody),
        (status = 404, description = "Approval not found", body = ErrorBody),
        (status = 422, description = "Not pending, or the caller may not approve it", body = ErrorBody),
        (status = 429, description = "Too many approvals", body = ErrorBody)
    )
)]
/// Approve a held action
///
/// A person authorizes the held agent action. A delete, configuration,
/// financial or admin action, or one whose class is unknown, needs two
/// different people, each sending a fresh second-factor code as
/// `{"mfa_code": "..."}`: the first approval is recorded and the action
/// keeps waiting; the second grants it. The agent's owner and the people
/// behind its delegation may not approve, and the approver must be cleared
/// for the data the action has touched. `403` with a step-up error when the
/// code is missing, `403` for a wrong code or an approver with no second
/// factor, `404` if the approval does not exist, `422` if it is no longer
/// pending or the caller may not approve it, and `429` past the hourly
/// approvals one person may give. Records `agents.approval_signed` or
/// `agents.approval_granted`. Requires `Agents(Approve)`.
pub(crate) async fn approve_action(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentApprovalPath>,
    StepUpCode(mfa_code): StepUpCode,
) -> Result<Json<ApprovalResponse>, ApiError> {
    let approval = agents
        .approvals
        .approve
        .execute(
            &tenant.caller,
            &tenant.auditor,
            ApproveActionRequest {
                agent_id: path.agent(),
                approval_id: path.approval(),
                mfa_code,
            },
        )
        .await?;
    Ok(Json(ApprovalResponse::from(&approval)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/approvals/{approval_id}/facts",
    tag = "Agents",
    responses(
        (status = 200, description = "Success", body = ApprovalFactsResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Approval not found", body = ErrorBody)
    )
)]
/// Facts about a held action
///
/// What ianua itself computed about the action, before what the agent
/// says: the exact call and the registered tool's method, path, action
/// class and data class; the most sensitive data the agent has touched;
/// whom it acts for; how often it was refused, drifted or met another
/// agent lately; and the open channels into it. The agent's own summary
/// comes last as `agent_claim`, with invisible characters stripped.
/// Requires the agent's owner or `Agents(Approve)`.
pub(crate) async fn approval_facts(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentApprovalPath>,
) -> Result<Json<ApprovalFactsResponse>, ApiError> {
    let facts = agents
        .approvals
        .facts
        .execute(
            &tenant.caller,
            GetFactsRequest {
                agent_id: path.agent(),
                approval_id: path.approval(),
            },
        )
        .await?;
    Ok(Json(ApprovalFactsResponse::from(&facts)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/approvals/{approval_id}/deny",
    tag = "Agents",
    responses(
        (status = 200, description = "Denied", body = ApprovalResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Approval not found", body = ErrorBody),
        (status = 422, description = "Not pending", body = ErrorBody)
    )
)]
/// Deny a held action
///
/// A person refuses the held agent action; a run that raised it drops the
/// call and goes on without it. `404` if the approval does not exist,
/// `422` if it is no longer pending. Records `agents.approval_denied`.
/// Requires `Agents(Approve)`.
pub(crate) async fn deny_action(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentApprovalPath>,
) -> Result<Json<ApprovalResponse>, ApiError> {
    let approval = agents
        .approvals
        .deny
        .execute(
            &tenant.caller,
            &tenant.auditor,
            DenyActionRequest {
                agent_id: path.agent(),
                approval_id: path.approval(),
            },
        )
        .await?;
    Ok(Json(ApprovalResponse::from(&approval)))
}

#[utoipa::path(
    post,
    path = "/internal/agent-approvals",
    tag = "Agents",
    request_body(content = String, description = "The sealed question, exactly as the gateway sealed it", content_type = "application/json"),
    responses(
        (status = 200, description = "The answer, or a refusal, for the gateway to act on, sealed for the question it answers",
            headers(("x-ianua-seal" = String, description = "The API's seal over the answer, bound to the question's nonce; absent when the question did not open")))
    )
)]
/// Answer the gateway's question about an approval (gateway only)
///
/// The gateway never writes approvals. When an agent's action needs a
/// person's approval it asks here, sealed, either to hold the action (find
/// the request a person decides for exactly that action, or open one,
/// unless the delegation already has too many open) or to spend the
/// approval a person gave, once. Opening a request records
/// `agents.approval_requested`.
///
/// Served only on the internal listener, which no ingress routes to. The
/// question must carry the gateway's seal, under the key of this channel
/// alone, a recent timestamp and a nonce not seen before. Every answer is
/// `200` with a typed result; anything that fails, an unsealed, stale or
/// repeated question included, is answered `refused`, and the gateway
/// refuses the action.
///
/// The answer goes back sealed in `x-ianua-seal`, under the same channel's
/// key and bound to the question's nonce; a question that did not open gets
/// its refusal unsealed. The gateway takes no answer without a seal for its
/// own question, so nobody else on the internal network can admit an
/// agent's action, nor replay an earlier answer.
pub(crate) async fn relay_question(
    State(agents): State<AgentState>,
    relayed: GatewayRelay,
    body: Bytes,
) -> RelayedApprovalAnswer {
    let request = RelayRequest {
        body: body.to_vec(),
        seal: relayed.seal,
    };
    agents
        .approvals
        .relay
        .execute(&(), &relayed.auditor, request)
        .await
        .into()
}

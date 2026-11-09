//! Agent lifecycle handlers: creating, reading, changing and stopping agent
//! identities, and an agent bootstrapping itself from a platform
//! attestation.

use axum::extract::{Path, State};
use ianua_app::ports::agents::AgentSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::agents::lifecycle::ListAgentsRequest;
use ianua_assembly::agents::AgentState;

use crate::dto::agents::credentials::CredentialResponse;
use crate::dto::agents::lifecycle::{
    AgentResponse, BootstrapAgentBody, ContainAgentResponse, CreateAgentBody, CreateAgentResponse,
    SuspendAllAgentsResponse, UpdateAgentBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::agents::AgentEndpoint;
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::agents::AgentPath;
use crate::extractors::sort::SortQuery;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents",
    tag = "Agents",
    request_body = CreateAgentBody,
    responses(
        (status = 201, description = "Created", body = CreateAgentResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 409, description = "Another agent of the tenant has the name", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Plan limit reached", body = ErrorBody)
    )
)]
/// Create an agent identity
///
/// Registers an AI-agent principal for this tenant in `Active` status,
/// owned by the caller. Supply a display `name` and an optional
/// `description`. Optionally configures the attestation trust policy at
/// creation through `trusted_methods` (`spiffe`, `aws`, `gcp`, `tpm`),
/// `re_attest_every` (seconds) and `allowed_origins`, the first two given
/// together. An agent that will sign in with a durable key brings the
/// public half of a pair it made in `key`; its first credential is enrolled
/// from it. Creation is held to the tenant plan's agent limit. Returns the
/// new agent's `id` and that credential; `409` when another agent of the
/// tenant already has the name, `422` for an invalid name, policy or key
/// and `429` once the plan's limit is reached. Records
/// `agents.agent_created`. Requires `Agents(Create)`.
pub(crate) async fn create_agent(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Json(body): Json<CreateAgentBody>,
) -> Result<Created<CreateAgentResponse>, ApiError> {
    let created = agents
        .lifecycle
        .create
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(CreateAgentResponse::from(created)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}",
    tag = "Agents",
    responses(
        (status = 200, description = "Success", body = AgentResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Get an agent
///
/// Returns one agent by `id`: its display name, description, owner,
/// lifecycle `status` (`Active`, `Suspended`, `Revoked`) and attestation
/// policy. Requires the agent's owner or `Agents(View)`; anyone else gets
/// `404`, the same as for an agent this tenant does not have.
pub(crate) async fn get_agent(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
) -> Result<Json<AgentResponse>, ApiError> {
    let agent = agents
        .lifecycle
        .get
        .execute(&tenant.caller, path.agent())
        .await?;
    Ok(Json(AgentResponse::from(agent)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents",
    tag = "Agents",
    params(SortQuery<AgentSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<AgentResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List agents
///
/// Returns this tenant's agent identities, sortable and paginated. Each
/// entry carries the agent's name, description, owner and lifecycle
/// `status`. Requires `Agents(View)`.
pub(crate) async fn list_agents(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    SortQuery(sort): SortQuery<AgentSortField>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<AgentResponse>>, ApiError> {
    let page = agents
        .lifecycle
        .list
        .execute(
            &tenant.caller,
            ListAgentsRequest {
                sort,
                page: pagination,
            },
        )
        .await?;
    Ok(Json(PageResponse::from_page(page, AgentResponse::from)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}",
    tag = "Agents",
    request_body = UpdateAgentBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "The agent changed since it was read, or another agent of the tenant has the name", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Update an agent
///
/// Changes an agent's display `name` and `description` (leaving the
/// description out clears it); its owner and status are unchanged.
/// `trusted_methods` (`spiffe`, `aws`, `gcp`, `tpm`) and `re_attest_every`
/// (seconds) name the attestation trust policy together: leave both out to
/// keep it, send both as `null` to clear it, or send both with values to
/// replace it. Accepts `PUT` and `PATCH`. `404` if the agent does not
/// exist, `409` when another agent of the tenant already has the new name
/// or the agent changed meanwhile, `422` for an invalid name or policy, or
/// when the two fields disagree on which of those three this is. Records
/// `agents.agent_updated`. Requires the agent's owner or `Agents(Update)`.
pub(crate) async fn update_agent(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
    Json(body): Json<UpdateAgentBody>,
) -> Result<NoContent, ApiError> {
    agents
        .lifecycle
        .update
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.agent())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/suspend",
    tag = "Agents",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Invalid transition", body = ErrorBody)
    )
)]
/// Suspend an agent
///
/// Disables an agent for now: while it is suspended none of its delegations
/// work and any task token it holds is refused at the proxy. Undone by
/// resuming it. `404` if the agent does not exist, `422` if it was revoked.
/// Records `agents.agent_suspended`. Requires the agent's owner or
/// `Agents(Update)`.
pub(crate) async fn suspend_agent(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
) -> Result<NoContent, ApiError> {
    agents
        .lifecycle
        .suspend
        .execute(&tenant.caller, &tenant.auditor, path.agent())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/resume",
    tag = "Agents",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Invalid transition", body = ErrorBody)
    )
)]
/// Resume an agent
///
/// Reactivates a suspended agent so its delegations work again. `404` if
/// the agent does not exist, `422` if it was revoked (revocation is
/// final). Records `agents.agent_resumed`. Requires the agent's owner or
/// `Agents(Update)`.
pub(crate) async fn resume_agent(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
) -> Result<NoContent, ApiError> {
    agents
        .lifecycle
        .resume
        .execute(&tenant.caller, &tenant.auditor, path.agent())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/revoke",
    tag = "Agents",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Invalid transition", body = ErrorBody)
    )
)]
/// Revoke an agent
///
/// Revokes an agent for good: it can never be reactivated and all its
/// authority is withdrawn. `404` if the agent does not exist, `422` if it
/// was revoked already. Records `agents.agent_revoked`. Requires the
/// agent's owner or `Agents(Delete)`.
pub(crate) async fn revoke_agent(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
) -> Result<NoContent, ApiError> {
    agents
        .lifecycle
        .revoke
        .execute(&tenant.caller, &tenant.auditor, path.agent())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}",
    tag = "Agents",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Not revoked yet", body = ErrorBody)
    )
)]
/// Delete an agent
///
/// Removes an agent and its credential and approval history for good. The
/// agent must be revoked first. Records `agents.agent_deleted`. Requires
/// the agent's owner or `Agents(Delete)`.
pub(crate) async fn delete_agent(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
) -> Result<NoContent, ApiError> {
    agents
        .lifecycle
        .delete
        .execute(&tenant.caller, &tenant.auditor, path.agent())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/contain",
    tag = "Agents",
    responses(
        (status = 200, description = "Contained", body = ContainAgentResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Contain an agent (kill-switch)
///
/// Emergency stop: revokes the agent, its keys, and its whole delegation
/// blast radius in one action, every delegation it holds and every
/// delegation descended from those. The proxy refuses the revoked tokens at
/// once, and every agent it delegated to is cut off with it. Containing an
/// agent with no live delegations revokes none. Returns how many
/// delegations were revoked. Records `agents.agent_contained`. Requires the
/// agent's owner or `Agents(Delete)`.
pub(crate) async fn contain_agent(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
) -> Result<Json<ContainAgentResponse>, ApiError> {
    let revoked_count = agents
        .lifecycle
        .contain
        .execute(&tenant.caller, &tenant.auditor, path.agent())
        .await?;
    Ok(Json(ContainAgentResponse { revoked_count }))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/suspend-all",
    tag = "Agents",
    responses(
        (status = 200, description = "Suspended", body = SuspendAllAgentsResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// Suspend every agent (tenant-wide stop)
///
/// Emergency stop for the whole tenant: suspends every active agent at
/// once. The proxy refuses their tokens from the next request and their
/// runs halt before their next step. Unlike containment it can be undone,
/// by resuming each agent once it is known to be safe. Returns how many
/// were suspended. Every agent stops or none does. Records
/// `agents.all_agents_suspended` once, with the count. Requires
/// `Agents(Update)`.
pub(crate) async fn suspend_all_agents(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
) -> Result<Json<SuspendAllAgentsResponse>, ApiError> {
    let suspended_count = agents
        .lifecycle
        .suspend_all
        .execute(&tenant.caller, &tenant.auditor, ())
        .await?;
    Ok(Json(SuspendAllAgentsResponse { suspended_count }))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/bootstrap",
    tag = "Agents",
    request_body = BootstrapAgentBody,
    responses(
        (status = 201, description = "Created: a short-lived credential", body = CredentialResponse),
        (status = 403, description = "Attestation refused or not trusted", body = ErrorBody),
        (status = 404, description = "Agent not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Bootstrap an agent from a platform attestation (secret-zero)
///
/// The agent proves what it is with a platform `attestation` (a SPIFFE SVID,
/// a signed AWS `sts:GetCallerIdentity` request, a GCP instance identity
/// token, a TPM quote) bound to a challenge from
/// `POST .../bootstrap/challenge` and to the key it enrols; the platform
/// verifies it against the agent's attestation policy and enrols the public
/// key the workload made (`algorithm`, `public_key`) as a short-lived
/// identity credential. No
/// standing secret, and the private key never leaves the workload. No
/// session: the agent signs in by the attestation, and every failure is
/// `403`. Rate limited per address. Records `agents.agent_bootstrapped`.
pub(crate) async fn bootstrap_agent(
    State(agents): State<AgentState>,
    agent: AgentEndpoint,
    Path(path): Path<AgentPath>,
    Json(body): Json<BootstrapAgentBody>,
) -> Result<Created<CredentialResponse>, ApiError> {
    let credential = agents
        .lifecycle
        .bootstrap
        .execute(
            &agent.tenant,
            &agent.auditor,
            body.into_request(path.agent())?,
        )
        .await?;
    Ok(Created(CredentialResponse::from(&credential)))
}

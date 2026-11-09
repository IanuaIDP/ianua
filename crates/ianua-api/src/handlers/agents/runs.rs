//! Agent run handlers: starting a governed run, reading it, stopping it, and
//! deciding the call a paused run holds.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::agents::runs::{
    CancelRequest, DenyRequest, GetRequest, ListTenantRequest, PauseRequest, ResumeRequest,
};
use ianua_assembly::agents::AgentState;

use crate::dto::agents::runs::{
    ApproveRunBody, ReplyToRunCallBody, ReviseRunCallBody, RevisedRunCallResponse, RunAgentBody,
    RunDecidedResponse, RunQueryParams, RunResponse, RunSummaryResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::listing::PageQuery;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::agents::{AgentPath, AgentRunPath};
use crate::extractors::query::Query;
use crate::response::{Accepted, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/runs",
    tag = "Agents",
    request_body = RunAgentBody,
    responses(
        (status = 202, description = "Run accepted and started", body = RunResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Agent or model provider not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Plan limit reached", body = ErrorBody)
    )
)]
/// Run an agent toward a goal
///
/// Starts a governed run and answers at once with the `running` run; a
/// worker drives the loop from there, calling only the tools the run was
/// granted whose action is inside the run's `purpose`: a tool outside it is
/// refused whatever the model asks for. `spend_limit_micros` caps what its
/// model calls may cost; the run stops as `over_budget` once it is spent.
/// `ask_past_micros` pauses it once it spent that much, recording
/// `agents.run_held_at_spend`, until whoever may resume it lets it go on.
/// Poll the run to watch it, pause it to look closer, and cancel it to
/// stop early. Records `agents.run_started`. Requires the agent's owner or
/// `Agents(Delegate)`.
pub(crate) async fn create_run(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
    Json(body): Json<RunAgentBody>,
) -> Result<Accepted<RunResponse>, ApiError> {
    let run = agents
        .runs
        .start
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.agent())?,
        )
        .await?;
    Ok(Accepted(RunResponse::from(run)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/runs",
    tag = "Agents",
    params(RunQueryParams, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<RunSummaryResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Agent not found", body = ErrorBody),
        (status = 422, description = "Invalid status, cursor or page limit", body = ErrorBody)
    )
)]
/// List an agent's runs
///
/// Returns one page of run summaries, newest first, including token use and
/// spend. `?status=` narrows to one lifecycle state. Pass `next_cursor` as
/// `?after=` for another page. Read an individual run for its steps and answer.
///
/// `?status=awaiting_approval` is the run-approval inbox: the runs paused
/// on a tool call waiting for a person, each carrying the run's id, its
/// purpose, and the `pending_tool`, `pending_arguments` and
/// `pending_at_step` held for the decision. Decide with
/// `POST .../runs/{run_id}/approve` or `/deny`.
///
/// Requires the agent's owner or `Agents(View)`.
pub(crate) async fn list_runs(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
    PageQuery { query, page }: PageQuery<RunQueryParams>,
) -> Result<Json<PageResponse<RunSummaryResponse>>, ApiError> {
    let runs = agents
        .runs
        .list
        .execute(&tenant.caller, query.listing(path.agent(), page)?)
        .await?;
    Ok(Json(PageResponse::from_page(
        runs,
        RunSummaryResponse::from,
    )))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/runs/{run_id}",
    tag = "Agents",
    responses(
        (status = 200, description = "Success", body = RunResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Get a run
///
/// Returns one run with its full step trace: the record of what the agent
/// did. Requires the agent's owner or `Agents(View)`, and clearance for
/// the data the run has read.
pub(crate) async fn get_run(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentRunPath>,
) -> Result<Json<RunResponse>, ApiError> {
    let run = agents
        .runs
        .get
        .execute(
            &tenant.caller,
            GetRequest {
                agent_id: path.agent(),
                run_id: path.run(),
            },
        )
        .await?;
    Ok(Json(RunResponse::from(run)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/runs/{run_id}/cancel",
    tag = "Agents",
    responses(
        (status = 200, description = "Cancellation requested", body = RunResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Cancel a run
///
/// Asks a run in flight to stop; the loop notices between steps, records
/// the stop, and lands in `cancelled`. Approvals a paused run waited on are
/// withdrawn. Cancelling a finished run changes nothing. Returns the run
/// as it stood when asked. Records `agents.run_cancel_requested`. Requires
/// the agent's owner or `Agents(Delegate)`.
pub(crate) async fn cancel_run(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentRunPath>,
) -> Result<Json<RunResponse>, ApiError> {
    let run = agents
        .runs
        .cancel
        .execute(
            &tenant.caller,
            &tenant.auditor,
            CancelRequest {
                agent_id: path.agent(),
                run_id: path.run(),
            },
        )
        .await?;
    Ok(Json(RunResponse::from(run)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/runs/{run_id}/approve",
    tag = "Agents",
    request_body = ApproveRunBody,
    responses(
        (status = 200, description = "Approved; resumed once fully approved", body = RunDecidedResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or a fresh second-factor code is needed", body = ErrorBody),
        (status = 404, description = "Run not found, or no open approval for that call", body = ErrorBody),
        (status = 409, description = "The held call changed since it was looked at", body = ErrorBody),
        (status = 422, description = "Not awaiting approval, or the caller may not approve it", body = ErrorBody),
        (status = 429, description = "Too many approvals", body = ErrorBody)
    )
)]
/// Approve a paused run
///
/// Approves the tool call a run paused on (`awaiting_approval`) through the
/// approval request the run raised for it: the same decision as approving
/// that request in the inbox. A low-risk call resumes at once. A delete,
/// configuration, financial or admin call needs two different people, each
/// sending a fresh second-factor code as `mfa_code`; the run resumes on the
/// second.
///
/// The body names the call approved (`tool`, `arguments`, `at_step`, as the
/// run shows them). A decision naming a call the run raised no open
/// approval for is refused with `404`, and one landing after the run moved
/// on with `409`, rather than applied to whatever is there now. `422` if
/// the run is not awaiting approval or the caller may not approve it, such
/// as the person who started it. Answers where the run stands now; read
/// the run for its steps. Requires `Agents(Approve)`.
pub(crate) async fn approve_run(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentRunPath>,
    Json(body): Json<ApproveRunBody>,
) -> Result<Json<RunDecidedResponse>, ApiError> {
    let decided = agents
        .runs
        .approve
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.agent(), path.run())?,
        )
        .await?;
    Ok(Json(RunDecidedResponse::from(decided)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/runs/{run_id}/deny",
    tag = "Agents",
    responses(
        (status = 200, description = "Denied and resumed", body = RunDecidedResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Not awaiting approval", body = ErrorBody)
    )
)]
/// Deny a paused run's tool call
///
/// Refuses the tool call a run paused on and resumes it; the refusal is
/// recorded and handed back to the model, which goes on without the call.
/// `422` if the run is not awaiting approval. Answers where the run stands
/// now. Records `agents.approval_denied`. Requires `Agents(Approve)`.
pub(crate) async fn deny_run(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentRunPath>,
) -> Result<Json<RunDecidedResponse>, ApiError> {
    let decided = agents
        .runs
        .deny
        .execute(
            &tenant.caller,
            &tenant.auditor,
            DenyRequest {
                agent_id: path.agent(),
                run_id: path.run(),
            },
        )
        .await?;
    Ok(Json(RunDecidedResponse::from(decided)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/runs",
    tag = "Agents",
    params(RunQueryParams, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<RunSummaryResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Invalid status, cursor or page limit", body = ErrorBody)
    )
)]
/// List every agent's runs
///
/// Returns one page of run summaries across the tenant, newest first, in
/// the shape an agent's own list answers. `?status=` narrows to one lifecycle
/// state: `?status=awaiting_approval` is the tenant's run-approval inbox.
/// Requires `Agents(View)`.
pub(crate) async fn list_tenant_runs(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Query(query): Query<RunQueryParams>,
    Paging(page): Paging,
) -> Result<Json<PageResponse<RunSummaryResponse>>, ApiError> {
    let runs = agents
        .runs
        .list_tenant
        .execute(
            &tenant.caller,
            ListTenantRequest {
                status: query.status()?,
                page,
            },
        )
        .await?;
    Ok(Json(PageResponse::from_page(
        runs,
        RunSummaryResponse::from,
    )))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/runs/{run_id}/pause",
    tag = "Agents",
    responses(
        (status = 200, description = "Paused", body = RunResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "The run took a step since it was read; try again", body = ErrorBody),
        (status = 422, description = "Not running", body = ErrorBody)
    )
)]
/// Pause a run
///
/// Holds a running run before its next step, so a person can look at what
/// it did so far. A paused run takes no step and makes no call until it is
/// resumed; cancelling it still works. `422` if the run is not running,
/// such as one waiting on an approval or one that ended. Records
/// `agents.run_paused`. Requires whoever started the run, the agent's
/// owner or `Agents(Update)`.
pub(crate) async fn pause_run(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentRunPath>,
) -> Result<Json<RunResponse>, ApiError> {
    let run = agents
        .steering
        .pause
        .execute(
            &tenant.caller,
            &tenant.auditor,
            PauseRequest {
                agent_id: path.agent(),
                run_id: path.run(),
            },
        )
        .await?;
    Ok(Json(RunResponse::from(run)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/runs/{run_id}/resume",
    tag = "Agents",
    responses(
        (status = 200, description = "Resumed", body = RunResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "The run changed since it was read; try again", body = ErrorBody),
        (status = 422, description = "Not paused", body = ErrorBody)
    )
)]
/// Resume a paused run
///
/// Hands a paused run back to a worker, which takes its next step. `422`
/// if the run is not paused. Records `agents.run_resumed`. Requires
/// whoever started the run, the agent's owner or `Agents(Update)`.
pub(crate) async fn resume_run(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentRunPath>,
) -> Result<Json<RunResponse>, ApiError> {
    let run = agents
        .steering
        .resume
        .execute(
            &tenant.caller,
            &tenant.auditor,
            ResumeRequest {
                agent_id: path.agent(),
                run_id: path.run(),
            },
        )
        .await?;
    Ok(Json(RunResponse::from(run)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/runs/{run_id}/call",
    tag = "Agents",
    request_body = ReviseRunCallBody,
    responses(
        (status = 200, description = "Changed; waiting on a new approval", body = RevisedRunCallResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Run not found, or no open approval for its call", body = ErrorBody),
        (status = 409, description = "The run moved on, or the change is not one the tool takes", body = ErrorBody),
        (status = 422, description = "Not awaiting approval, or invalid arguments", body = ErrorBody)
    )
)]
/// Change the call a run holds
///
/// Replaces the `arguments` of the tool call a run is paused on
/// (`awaiting_approval`), such as pointing a payment at the staging ledger
/// instead. The approval request raised for the old call is withdrawn and
/// a new one is raised for the changed call, which waits for its approvers
/// like any other. The change keeps the tool and its class of action:
/// another tool or class is `409`. Answers the run and the new approval
/// request. Records `agents.held_call_revised`. Requires `Agents(Approve)`
/// and clearance for the data the run has read.
pub(crate) async fn revise_run_call(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentRunPath>,
    Json(body): Json<ReviseRunCallBody>,
) -> Result<Json<RevisedRunCallResponse>, ApiError> {
    let revised = agents
        .steering
        .revise_call
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.agent(), path.run())?,
        )
        .await?;
    Ok(Json(RevisedRunCallResponse::from(revised)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/runs/{run_id}/reply",
    tag = "Agents",
    request_body = ReplyToRunCallBody,
    responses(
        (status = 200, description = "Answered and resumed", body = RunDecidedResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Run not found, or no open approval for its call", body = ErrorBody),
        (status = 409, description = "The run holds another call now", body = ErrorBody),
        (status = 422, description = "Not awaiting approval, or an invalid reply", body = ErrorBody)
    )
)]
/// Answer a run's held call in words
///
/// Instead of letting the call a run is paused on run, tells the agent
/// something, such as "use the staging ledger instead". The call is never
/// made: its approval request is denied, the `reply` is recorded as the
/// run's next step (`replied`) for the model to read, and the run goes on.
/// Takes the same right as denying the call. Records
/// `agents.approval_denied`. Requires `Agents(Approve)`.
pub(crate) async fn reply_to_run_call(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentRunPath>,
    Json(body): Json<ReplyToRunCallBody>,
) -> Result<Json<RunDecidedResponse>, ApiError> {
    let decided = agents
        .steering
        .reply
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.agent(), path.run())?,
        )
        .await?;
    Ok(Json(RunDecidedResponse::from(decided)))
}

//! Agent intent handlers: compiling a stated purpose into the scope it
//! implies, and lowering a stopped agent's data mark.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::agents::AgentState;

use crate::dto::agents::intent::{CompileIntentBody, CompileIntentResponse, ResetExposureBody};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::agents::AgentPath;
use crate::response::NoContent;

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/compile-intent",
    tag = "Agents",
    request_body = CompileIntentBody,
    responses(
        (status = 200, description = "Narrowed scope and intent digest", body = CompileIntentResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Agent not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Compile an intent into a narrowed scope (dry-run)
///
/// Turns a natural-language `intent` and a `requested` scope into the
/// narrowed capability set the intent implies for this agent, with a digest
/// for drift monitoring. It only narrows: the result never exceeds
/// `requested`. Nothing is granted. Requires `Agents(View)`.
pub(crate) async fn compile_intent(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
    Json(body): Json<CompileIntentBody>,
) -> Result<Json<CompileIntentResponse>, ApiError> {
    let outcome = agents
        .intent
        .compile
        .execute(&tenant.caller, body.into_request(path.agent())?)
        .await?;
    Ok(Json(CompileIntentResponse::from(outcome)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/exposure/reset",
    tag = "Agents",
    request_body = ResetExposureBody,
    responses(
        (status = 204, description = "Lowered"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Agent not found", body = ErrorBody),
        (status = 409, description = "The agent is still active", body = ErrorBody),
        (status = 422, description = "Not lower than the current mark", body = ErrorBody)
    )
)]
/// Lower a stopped agent's data mark
///
/// An agent's mark only rises while it runs, because its context holds
/// what it read. Once it is suspended, a person who has looked may lower it
/// so the agent can return to less sensitive work. Refused (`409`) while
/// the agent is active. Records `agents.exposure_reset` with the reason
/// given. Requires the agent's owner or `Agents(Delegate)`.
pub(crate) async fn reset_exposure(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
    Json(body): Json<ResetExposureBody>,
) -> Result<NoContent, ApiError> {
    agents
        .intent
        .reset_exposure
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.agent())?,
        )
        .await?;
    Ok(NoContent)
}

//! Agent evidence handlers: what the audit trail holds about an agent, as a
//! timeline and as records in the tenant's hash chain.

use axum::extract::{Path, State};
use ianua_app::ports::audit::AuditLogSortField;
use ianua_app::use_case::Query as _;
use ianua_assembly::agents::AgentState;

use crate::dto::agents::evidence::{
    ActivityQueryParams, AgentActivityEntryResponse, EvidencePageResponse, EvidenceParams,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::agents::ActivityPage;
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::pagination::PaginationParams;
use crate::extractors::paths::agents::AgentPath;
use crate::extractors::query::Query;
use crate::extractors::sort::SortQuery;
use crate::response::PageResponse;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/activity",
    tag = "Agents",
    params(ActivityQueryParams, SortQuery<AuditLogSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<AgentActivityEntryResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// An agent's activity timeline
///
/// Returns the audit records the agent produced: what it did, for whom, and
/// whether each action was allowed or refused. Filterable by `event_type`
/// and a time window (`since`, `before`, RFC 3339), sortable and paged by
/// cursor (`after`, `limit` 20 when left out). Requires the agent's owner or
/// `Agents(View)`.
pub(crate) async fn agent_activity(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
    ActivityPage {
        sort,
        query: params,
        page: asked,
    }: ActivityPage,
) -> Result<Json<PageResponse<AgentActivityEntryResponse>>, ApiError> {
    let page = agents
        .evidence
        .activity
        .execute(&tenant.caller, params.listing(path.agent(), sort, asked)?)
        .await?;
    Ok(Json(PageResponse::from_page(
        page,
        AgentActivityEntryResponse::from,
    )))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/evidence",
    tag = "Agents",
    params(EvidenceParams),
    responses(
        (status = 200, description = "Success", body = EvidencePageResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// An agent's evidence
///
/// What ianua recorded about the agent, oldest first, each record with its
/// place (`seq`) and hash in the tenant's chain, and the scheduled sweep's
/// last verdict on the whole chain (`not_verified_yet` before the first
/// sweep). Requires the agent's owner or `Agents(View)`.
pub(crate) async fn agent_evidence(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
    Query(params): Query<EvidenceParams>,
) -> Result<Json<EvidencePageResponse>, ApiError> {
    let page = agents
        .evidence
        .evidence
        .execute(&tenant.caller, params.for_agent(path.agent()))
        .await?;
    Ok(Json(EvidencePageResponse::from(page)))
}

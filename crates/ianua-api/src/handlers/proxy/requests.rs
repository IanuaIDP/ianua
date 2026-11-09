//! Request record handlers: searching the requests the gateway decided, to
//! read why one was refused, by which check and under which rule.

use axum::extract::State;
use ianua_app::ports::proxy::RequestRecordSortField;
use ianua_app::use_case::Query as _;
use ianua_assembly::proxy::ProxyState;

use crate::dto::proxy::requests::{RequestRecordResponse, RequestSearchParams};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::listing::ListingQuery;
use crate::extractors::pagination::PaginationParams;
use crate::extractors::sort::SortQuery;
use crate::response::PageResponse;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/gateway/requests",
    tag = "Gateway",
    params(RequestSearchParams, SortQuery<RequestRecordSortField>, PaginationParams),
    responses(
        (status = 200, description = "The matching request records", body = PageResponse<RequestRecordResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Search the gateway's request records
///
/// Finds the requests the gateway decided for this tenant, newest first by
/// default, sortable by `occurred_at`, `status` or `duration_ms` and paged
/// by cursor (`after`, `limit` 20 by default, at most 100). Narrow by `decision`
/// (`allowed` or `refused`), by what refused (`gateway_check`, `stage_id`
/// or `stage_kind`, one of them), by the policy `rule` and by text in the
/// `reason`, by `route_id`, by who asked (`user_id`, `agent_id` or
/// `consumer_id`, one of them) and by time (`since`, `before`, RFC 3339).
///
/// Each record says who asked, what they asked for, what was decided with
/// the status returned, and for a refusal its reason, the check or stage
/// that made it and the named rule it was made under. A record never holds
/// a token or a credential. Read-only. Requires the right to read the
/// audit log: a record says who called what.
pub(crate) async fn search_requests(
    State(proxy): State<ProxyState>,
    tenant: TenantCaller,
    ListingQuery {
        query: params,
        sort,
        page,
    }: ListingQuery<RequestSearchParams, RequestRecordSortField>,
) -> Result<Json<PageResponse<RequestRecordResponse>>, ApiError> {
    let found = proxy
        .search_requests
        .execute(&tenant.caller, params.search(sort, page)?)
        .await?;
    Ok(Json(PageResponse::from_page(
        found,
        RequestRecordResponse::from,
    )))
}

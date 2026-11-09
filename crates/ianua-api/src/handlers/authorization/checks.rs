//! Access check handlers: a tenant's app asks whether someone may do an
//! action, alone or in a batch, and every decision is recorded and
//! searchable.

use axum::extract::State;
use ianua_app::use_case::Query as _;
use ianua_app::use_cases::authorization::checks::SearchDecisionsRequest;
use ianua_assembly::authorization::AuthorizationState;

use crate::dto::authorization::checks::{
    AccessDecisionResponse, BatchAccessDecisionResponse, BatchCheckAccessBody, CheckAccessBody,
    DecisionRecordResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::authorization::DecisionQuery;
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::query::Query;
use crate::response::PageResponse;

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/check",
    tag = "Authorization",
    request_body = CheckAccessBody,
    responses(
        (status = 200, description = "The answer", body = AccessDecisionResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Check access
///
/// Answers the tenant's app whether `subject` may do `action` on
/// `resource_type`, or on the one object keyed `object_key`. The answer
/// comes from the tenant's records: the app permissions the subject holds
/// through roles and groups, widened by the type's action ladder, and for
/// one object the relations held on it or on an object above it. Anything
/// the records do not show is `denied`, with the reason. Every answer is
/// recorded; one that cannot be recorded is not given.
///
/// Requires `Roles(View)`: an answer tells who holds what. An app calls it
/// with a tenant API key holding that right.
pub(crate) async fn check_access(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Json(body): Json<CheckAccessBody>,
) -> Result<Json<AccessDecisionResponse>, ApiError> {
    let decisions = authorization
        .checks
        .access
        .execute(&tenant.caller, body.try_into()?)
        .await?;
    Ok(Json(AccessDecisionResponse::only(&decisions)?))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/check/batch",
    tag = "Authorization",
    request_body = BatchCheckAccessBody,
    responses(
        (status = 200, description = "The answers, in the order asked", body = BatchAccessDecisionResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Check access in a batch
///
/// Answers up to 100 questions about one subject in one call, in the order
/// asked, each as `POST …/authorization/check` would. An empty batch, or
/// one over the limit, is `422`. Every answer is recorded.
///
/// Requires `Roles(View)`.
pub(crate) async fn check_access_batch(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Json(body): Json<BatchCheckAccessBody>,
) -> Result<Json<BatchAccessDecisionResponse>, ApiError> {
    let decisions = authorization
        .checks
        .access
        .execute(&tenant.caller, body.try_into()?)
        .await?;
    Ok(Json(BatchAccessDecisionResponse::from(
        decisions.as_slice(),
    )))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/decisions",
    tag = "Authorization",
    params(DecisionQuery, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<DecisionRecordResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Search authorization decisions
///
/// One page of the tenant's recorded decisions, newest first: the access
/// checks its apps asked, and the requests its policy decided at the
/// gateway, each with what decided it (the answer's reason, or the policy
/// version and the rule that matched). Narrow by subject, verdict, policy
/// version, rule and time; every part given must hold.
///
/// Requires `AuditLog(View)`.
pub(crate) async fn search_decisions(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Query(query): Query<DecisionQuery>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<DecisionRecordResponse>>, ApiError> {
    let page = authorization
        .checks
        .search_decisions
        .execute(
            &tenant.caller,
            SearchDecisionsRequest {
                filter: query.filter()?,
                page: pagination,
            },
        )
        .await?;
    Ok(Json(PageResponse::from_page(page, |record| {
        DecisionRecordResponse::from(&record)
    })))
}

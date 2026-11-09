//! Access review handlers: asking named reviewers whether each holder of a
//! role or member of a group keeps it, their decisions, and completing or
//! calling off the review.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::authorization::access_reviews::{ItemsRequest, ListRequest};
use ianua_assembly::authorization::AuthorizationState;

use crate::dto::authorization::access_reviews::{
    AccessReviewResponse, DecideAccessReviewBody, ReviewItemResponse, StartAccessReviewBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::authorization::AccessReviewQuery;
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::authorization::AccessReviewPath;
use crate::extractors::query::Query;
use crate::response::{Created, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/access-reviews",
    tag = "Authorization",
    request_body = StartAccessReviewBody,
    responses(
        (status = 201, description = "Started", body = AccessReviewResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Nobody holds what it covers", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Start an access review
///
/// Lists everyone who holds the role, or is in the group, now, and asks
/// the named reviewers whether each keeps it by `due`. A review with no
/// reviewer, more than 20, one named twice, or a due date already passed
/// is `422`; an unknown role, group or reviewer is `404`; a scope nobody
/// holds is `409`. Records `authorization.access_review_started`.
///
/// Requires `Roles(Assign)`.
pub(crate) async fn start_access_review(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Json(body): Json<StartAccessReviewBody>,
) -> Result<Created<AccessReviewResponse>, ApiError> {
    let review = authorization
        .access_reviews
        .start
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(AccessReviewResponse::from(&review)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/access-reviews",
    tag = "Authorization",
    params(AccessReviewQuery, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<AccessReviewResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// List access reviews
///
/// One page of the tenant's reviews, newest first: every one, or only the
/// `open` ones.
///
/// Requires `Roles(View)`.
pub(crate) async fn list_access_reviews(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Query(query): Query<AccessReviewQuery>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<AccessReviewResponse>>, ApiError> {
    let page = authorization
        .access_reviews
        .list
        .execute(
            &tenant.caller,
            ListRequest {
                filter: query.filter(),
                page: pagination,
            },
        )
        .await?;
    Ok(Json(PageResponse::from_page(page, |review| {
        AccessReviewResponse::from(&review)
    })))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/access-reviews/{id}",
    tag = "Authorization",
    responses(
        (status = 200, description = "Success", body = AccessReviewResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Get an access review
///
/// The review header with holder, pending and explicit removal counts.
/// Read its holders separately through the paginated `items` endpoint.
/// Its reviewers may read it; anyone else needs `Roles(View)`.
pub(crate) async fn get_access_review(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<AccessReviewPath>,
) -> Result<Json<AccessReviewResponse>, ApiError> {
    let review = authorization
        .access_reviews
        .get
        .execute(&tenant.caller, path.review())
        .await?;
    Ok(Json(AccessReviewResponse::from(&review)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/access-reviews/{id}/items",
    tag = "Authorization",
    params(PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<ReviewItemResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// List an access review's holders
///
/// One page in immutable snapshot position order. The review's reviewers
/// may read it; anyone else needs `Roles(View)`. Unreadable reviews are `404`.
pub(crate) async fn list_access_review_items(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<AccessReviewPath>,
    Paging(page): Paging,
) -> Result<Json<PageResponse<ReviewItemResponse>>, ApiError> {
    let page = authorization
        .access_reviews
        .items
        .execute(
            &tenant.caller,
            ItemsRequest {
                id: path.review(),
                page,
            },
        )
        .await?;
    Ok(Json(PageResponse::from_page(page, |item| {
        ReviewItemResponse::from(&item)
    })))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/access-reviews/{id}/decisions",
    tag = "Authorization",
    request_body = DecideAccessReviewBody,
    responses(
        (status = 200, description = "The review with the decision", body = AccessReviewResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Closed or past due", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Decide on a holder
///
/// Records the caller's choice, `keep` or `remove`, for one holder the
/// review lists. A later choice replaces an earlier one until the review
/// completes. Only the review's reviewers decide, and nobody decides on
/// their own account (`403`). A holder the review does not list is `404`;
/// a closed or overdue review is `409`. Records
/// `authorization.access_review_decided`.
pub(crate) async fn decide_access_review(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<AccessReviewPath>,
    Json(body): Json<DecideAccessReviewBody>,
) -> Result<Json<AccessReviewResponse>, ApiError> {
    let review = authorization
        .access_reviews
        .decide
        .execute(&tenant.caller, &tenant.auditor, body.request(path.review()))
        .await?;
    Ok(Json(AccessReviewResponse::from(&review)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/access-reviews/{id}/complete",
    tag = "Authorization",
    responses(
        (status = 200, description = "Completed", body = AccessReviewResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "No longer open", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Complete an access review
///
/// Closes the review and takes away the access of every holder it says
/// goes. Before the due date every holder must be decided (`409`
/// otherwise); after it, undecided holders are settled as the review's
/// `unanswered` says. Removals that would leave the tenant without an
/// administrator are `409`. A reviewer, or someone holding
/// `Roles(Assign)`, completes it. Records `authorization.access_review_completed` and each
/// removal.
pub(crate) async fn complete_access_review(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<AccessReviewPath>,
) -> Result<Json<AccessReviewResponse>, ApiError> {
    let review = authorization
        .access_reviews
        .complete
        .execute(&tenant.caller, &tenant.auditor, path.review())
        .await?;
    Ok(Json(AccessReviewResponse::from(&review)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/access-reviews/{id}/cancel",
    tag = "Authorization",
    responses(
        (status = 200, description = "Called off", body = AccessReviewResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "No longer open", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Call off an access review
///
/// Closes an open review without changing anyone's access. Records
/// `authorization.access_review_cancelled`.
///
/// Requires `Roles(Assign)`.
pub(crate) async fn cancel_access_review(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<AccessReviewPath>,
) -> Result<Json<AccessReviewResponse>, ApiError> {
    let review = authorization
        .access_reviews
        .cancel
        .execute(&tenant.caller, &tenant.auditor, path.review())
        .await?;
    Ok(Json(AccessReviewResponse::from(&review)))
}

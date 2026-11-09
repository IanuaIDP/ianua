//! Access request handlers: asking for a role or a place in a group for a
//! while, the answer from someone who could give it, withdrawing, and the
//! tenant's limit on how long one may ask for.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::authorization::access_requests::ListRequest;
use ianua_assembly::authorization::AuthorizationState;

use crate::dto::authorization::access_requests::{
    AccessRequestPolicyResponse, AccessRequestResponse, ChangeAccessRequestPolicyBody,
    RequestAccessBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::authorization::AccessRequestQuery;
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::authorization::AccessRequestPath;
use crate::extractors::query::Query;
use crate::response::{Created, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/access-requests",
    tag = "Authorization",
    request_body = RequestAccessBody,
    responses(
        (status = 201, description = "Asked", body = AccessRequestResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 404, description = "No such role or group", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Ask for access
///
/// Asks, for the caller, for a role or a place in a group for
/// `length_seconds`, with a reason. The request is always for the person
/// asking, never someone named in the body. Asking gives nothing: the
/// access comes only once someone who could give it by hand approves, and
/// lasts `length_seconds` from then. A length past the tenant's limit is
/// `422`. A request nobody answers within a week runs out. Records
/// `authorization.access_requested`.
///
/// Any signed-in person of the tenant may ask.
pub(crate) async fn request_access(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Json(body): Json<RequestAccessBody>,
) -> Result<Created<AccessRequestResponse>, ApiError> {
    let request = authorization
        .access_requests
        .request
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(AccessRequestResponse::from(&request)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/access-requests",
    tag = "Authorization",
    params(AccessRequestQuery, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<AccessRequestResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// List access requests
///
/// One page of the tenant's access requests, newest first: every one,
/// only those still `pending`, or only those one account asked
/// (`asked_by_kind` and `asked_by_id`). Anyone may list their own; listing
/// others' requires `Roles(View)`.
pub(crate) async fn list_access_requests(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Query(query): Query<AccessRequestQuery>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<AccessRequestResponse>>, ApiError> {
    let page = authorization
        .access_requests
        .list
        .execute(
            &tenant.caller,
            ListRequest {
                filter: query.filter()?,
                page: pagination,
            },
        )
        .await?;
    Ok(Json(PageResponse::from_page(page, |request| {
        AccessRequestResponse::from(&request)
    })))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/access-requests/{id}/approve",
    tag = "Authorization",
    responses(
        (status = 200, description = "Approved and given", body = AccessRequestResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Already answered or withdrawn", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Approve an access request
///
/// Gives the asker the role or the place in the group until the length
/// asked for has passed, counted from now. Nobody approves their own
/// request, and only someone who could give the access by hand approves
/// it (`403` otherwise). A request that ran out, or an approval that would
/// break a separation-of-duties rule, is `409`. Records
/// `authorization.access_request_approved` and the role or membership
/// given.
pub(crate) async fn approve_access_request(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<AccessRequestPath>,
) -> Result<Json<AccessRequestResponse>, ApiError> {
    let request = authorization
        .access_requests
        .approve
        .execute(&tenant.caller, &tenant.auditor, path.request())
        .await?;
    Ok(Json(AccessRequestResponse::from(&request)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/access-requests/{id}/deny",
    tag = "Authorization",
    responses(
        (status = 200, description = "Denied", body = AccessRequestResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Already answered or withdrawn", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Deny an access request
///
/// Refuses the request. The same people who could approve it may deny it;
/// nobody answers their own. Records `authorization.access_request_denied`.
pub(crate) async fn deny_access_request(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<AccessRequestPath>,
) -> Result<Json<AccessRequestResponse>, ApiError> {
    let request = authorization
        .access_requests
        .deny
        .execute(&tenant.caller, &tenant.auditor, path.request())
        .await?;
    Ok(Json(AccessRequestResponse::from(&request)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/access-requests/{id}/cancel",
    tag = "Authorization",
    responses(
        (status = 200, description = "Withdrawn", body = AccessRequestResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Already answered, withdrawn or run out", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Withdraw an access request
///
/// Takes back a request still waiting for an answer. Only the person who
/// asked withdraws it (`403` otherwise). Records
/// `authorization.access_request_cancelled`.
pub(crate) async fn cancel_access_request(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<AccessRequestPath>,
) -> Result<Json<AccessRequestResponse>, ApiError> {
    let request = authorization
        .access_requests
        .cancel
        .execute(&tenant.caller, &tenant.auditor, path.request())
        .await?;
    Ok(Json(AccessRequestResponse::from(&request)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/access-request-policy",
    tag = "Authorization",
    responses(
        (status = 200, description = "Success", body = AccessRequestPolicyResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Get the access request limit
///
/// The longest the tenant lets its people ask for access, or 30 days when
/// it never set a limit. Anyone who may ask may read it, so a form can
/// offer only lengths that will be accepted.
pub(crate) async fn get_access_request_policy(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
) -> Result<Json<AccessRequestPolicyResponse>, ApiError> {
    let policy = authorization
        .access_requests
        .get_policy
        .execute(&tenant.caller, ())
        .await?;
    Ok(Json(AccessRequestPolicyResponse::from(&policy)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/access-request-policy",
    tag = "Authorization",
    request_body = ChangeAccessRequestPolicyBody,
    responses(
        (status = 200, description = "The new limit", body = AccessRequestPolicyResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Change the access request limit
///
/// Holds the tenant's requests to at most `longest_seconds` from now on.
/// Requests already made keep the length they asked for. More than 30
/// days is `422`. Setting the limit already set records nothing; a change
/// records `authorization.access_request_policy_changed`.
///
/// Requires `Roles(Update)`.
pub(crate) async fn change_access_request_policy(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Json(body): Json<ChangeAccessRequestPolicyBody>,
) -> Result<Json<AccessRequestPolicyResponse>, ApiError> {
    let policy = authorization
        .access_requests
        .change_policy
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Json(AccessRequestPolicyResponse::from(&policy)))
}

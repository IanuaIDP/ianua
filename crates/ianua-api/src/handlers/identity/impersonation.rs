//! Support impersonation handlers: a tenant admin asking to act as a user,
//! the person's answer, ending it, the listing, and checking the caller the
//! admin then acts through.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::identity::IdentityState;

use crate::dto::identity::impersonation::{
    ActingAsResponse, ImpersonationBody, ImpersonationListParams, ImpersonationRequestedResponse,
    ImpersonationResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::identity::{ImpersonationPath, UserPath};
use crate::extractors::query::Query;
use crate::response::{Created, NoContent};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}/impersonations",
    tag = "Users",
    request_body = ImpersonationBody,
    responses(
        (status = 201, description = "Asked; started at once where the admin decides", body = ImpersonationRequestedResponse),
        (status = 401, description = "Unauthenticated, or not a tenant user's own session", body = ErrorBody),
        (status = 403, description = "The caller may not act as this user, holds less, or names themselves", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "The user may not sign in now", body = ErrorBody),
        (status = 422, description = "Validation error, or a window outside 5 to 60 minutes", body = ErrorBody)
    )
)]
/// Ask to act as a user for support
///
/// A tenant admin asks to act as one of the tenant's people for a short
/// while, with a reason, to see what they see and put it right. Where the
/// tenant has the person approve, they are mailed and it waits for them;
/// where the admin decides, it starts at once. The admin needs full control
/// of users and must hold what the person holds. Records
/// `identity.support_impersonation_requested`. Requires a tenant user's own
/// session.
pub(crate) async fn request_impersonation(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
    Json(body): Json<ImpersonationBody>,
) -> Result<Created<ImpersonationRequestedResponse>, ApiError> {
    let id = identity
        .impersonation
        .request
        .execute(&tenant.caller, &tenant.auditor, body.request(path.user())?)
        .await?;
    Ok(Created(id.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/impersonations",
    tag = "Users",
    params(ImpersonationListParams),
    responses(
        (status = 200, description = "Impersonations, newest first", body = Vec<ImpersonationResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Listing every one without full control of users", body = ErrorBody)
    )
)]
/// List support impersonations
///
/// `scope=mine` (the default) lists those naming the caller, as the admin
/// or as the person, so the person can approve, decline or end one.
/// `scope=all` lists every one in the tenant and needs full control of
/// users. Read-only.
pub(crate) async fn list_impersonations(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Query(params): Query<ImpersonationListParams>,
) -> Result<Json<Vec<ImpersonationResponse>>, ApiError> {
    let impersonations = identity
        .impersonation
        .list
        .execute(&tenant.caller, params.into())
        .await?;
    Ok(Json(ImpersonationResponse::listing(&impersonations)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/impersonations/{id}/approve",
    tag = "Users",
    responses(
        (status = 204, description = "Approved; the admin may act until the window ends"),
        (status = 401, description = "Unauthenticated, or not a tenant user's own session", body = ErrorBody),
        (status = 403, description = "It names someone else to act as", body = ErrorBody),
        (status = 404, description = "No such request involving the caller", body = ErrorBody),
        (status = 409, description = "It waited longer than a day", body = ErrorBody),
        (status = 422, description = "It no longer waits for an answer", body = ErrorBody)
    )
)]
/// Approve a request to act as me
///
/// The person it names lets the admin act as them, from now until the
/// window ends. Records `identity.support_impersonation_started`. Requires
/// the person's own session.
pub(crate) async fn approve_impersonation(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<ImpersonationPath>,
) -> Result<NoContent, ApiError> {
    identity
        .impersonation
        .approve
        .execute(&tenant.caller, &tenant.auditor, path.impersonation())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/impersonations/{id}/decline",
    tag = "Users",
    responses(
        (status = 204, description = "Declined"),
        (status = 401, description = "Unauthenticated, or not a tenant user's own session", body = ErrorBody),
        (status = 403, description = "It names someone else to act as", body = ErrorBody),
        (status = 404, description = "No such request involving the caller", body = ErrorBody),
        (status = 422, description = "It no longer waits for an answer", body = ErrorBody)
    )
)]
/// Decline a request to act as me
///
/// The person it names turns the admin down. Records
/// `identity.support_impersonation_declined`. Requires the person's own
/// session.
pub(crate) async fn decline_impersonation(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<ImpersonationPath>,
) -> Result<NoContent, ApiError> {
    identity
        .impersonation
        .decline
        .execute(&tenant.caller, &tenant.auditor, path.impersonation())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/impersonations/{id}/end",
    tag = "Users",
    responses(
        (status = 204, description = "Ended; the admin's next use of it is refused"),
        (status = 401, description = "Unauthenticated, or not a tenant user's own session", body = ErrorBody),
        (status = 404, description = "No such impersonation involving the caller", body = ErrorBody),
        (status = 422, description = "It was already declined or ended", body = ErrorBody)
    )
)]
/// End a support impersonation
///
/// The admin, or the person they act as, ends it early. The admin's next
/// request through it is refused at once. Records
/// `identity.support_impersonation_ended`. Requires the admin's or the
/// person's own session.
pub(crate) async fn end_impersonation(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<ImpersonationPath>,
) -> Result<NoContent, ApiError> {
    identity
        .impersonation
        .end
        .execute(&tenant.caller, &tenant.auditor, path.impersonation())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/impersonations/{id}/act-as",
    tag = "Users",
    responses(
        (status = 200, description = "The admin may act as the person now", body = ActingAsResponse),
        (status = 401, description = "Unauthenticated, or not a tenant user's own session", body = ErrorBody),
        (status = 403, description = "Not its admin, not active, its window is over, or the account may not sign in now", body = ErrorBody),
        (status = 404, description = "No such impersonation involving the caller", body = ErrorBody)
    )
)]
/// Act as the person
///
/// Checks the admin may act through the impersonation now and says how:
/// every later request made as the person carries the admin's own bearer
/// and the `ianua-support-impersonation` header naming it. Each such
/// request is checked again and recorded as the admin's, done as the
/// person. Call this without the header. Requires the admin's own session.
pub(crate) async fn act_as(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<ImpersonationPath>,
) -> Result<Json<ActingAsResponse>, ApiError> {
    let id = path.impersonation();
    let acting = identity
        .impersonation
        .act_as
        .execute(&tenant.caller, id)
        .await?;
    Ok(Json(ActingAsResponse::new(id, &acting)))
}

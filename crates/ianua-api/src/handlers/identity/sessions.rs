//! A user's sessions and sign-in history: the person's own, and another
//! user's for an admin.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::identity::users::{ListSignInsRequest, RevokeSessionRequest};
use ianua_app::use_cases::identity::whose::Whose;
use ianua_assembly::identity::IdentityState;

use crate::dto::audit::AuditLogEntryResponse;
use crate::dto::identity::sessions::{SessionResponse, SignedOutResponse};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::identity::{MySessionPath, UserPath, UserSessionPath};
use crate::response::{NoContent, PageResponse};

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/me/sessions",
    tag = "Users",
    responses(
        (status = 200, description = "My live sessions", body = Vec<SessionResponse>),
        (status = 401, description = "Unauthenticated, or not a tenant user's own session", body = ErrorBody)
    )
)]
/// List my sessions
///
/// The signed-in person's live sessions on every device, the one this
/// request came with marked `current`. Read-only. Requires a tenant user's
/// own session.
pub(crate) async fn list_my_sessions(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<SessionResponse>>, ApiError> {
    let sessions = identity
        .sessions
        .list
        .execute(&tenant.caller, Whose::Own)
        .await?;
    Ok(Json(SessionResponse::listing(&sessions, &tenant.caller)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/me/sessions/{session_id}",
    tag = "Users",
    responses(
        (status = 204, description = "The session ended"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 404, description = "None of my sessions", body = ErrorBody),
        (status = 422, description = "It already ended", body = ErrorBody)
    )
)]
/// End one of my sessions
///
/// Signs the person out on one device, such as a browser they left signed
/// in elsewhere. Records `authentication.session_revoked`. Requires a tenant
/// user's own session.
pub(crate) async fn revoke_my_session(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<MySessionPath>,
) -> Result<NoContent, ApiError> {
    let request = RevokeSessionRequest {
        whose: Whose::Own,
        session_id: path.session(),
    };
    identity
        .sessions
        .revoke
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/me/sessions/sign-out-others",
    tag = "Users",
    responses(
        (status = 200, description = "How many sessions ended", body = SignedOutResponse),
        (status = 401, description = "Unauthenticated, or not a tenant user's own session", body = ErrorBody)
    )
)]
/// Sign out everywhere else
///
/// Ends every session the person holds except the one this request came
/// with. Records `authentication.session_revoked` for each. Requires a
/// tenant user's own session.
pub(crate) async fn sign_out_other_sessions(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
) -> Result<Json<SignedOutResponse>, ApiError> {
    let ended = identity
        .sessions
        .sign_out_others
        .execute(&tenant.caller, &tenant.auditor, ())
        .await?;
    Ok(Json(ended.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/me/sign-ins",
    tag = "Users",
    params(PaginationParams),
    responses(
        (status = 200, description = "My sign-ins, newest first", body = PageResponse<AuditLogEntryResponse>),
        (status = 401, description = "Unauthenticated, or not a tenant user's own session", body = ErrorBody)
    )
)]
/// My sign-in history
///
/// The person's own sign-ins and failed attempts, newest first, as the
/// tenant's audit trail recorded them. Read-only. Requires a tenant user's
/// own session.
pub(crate) async fn list_my_sign_ins(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<AuditLogEntryResponse>>, ApiError> {
    let request = ListSignInsRequest {
        whose: Whose::Own,
        page: pagination,
    };
    let log = identity
        .sessions
        .sign_ins
        .execute(&tenant.caller, request)
        .await?;
    Ok(Json(PageResponse::from_page(
        log,
        AuditLogEntryResponse::from,
    )))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}/sessions",
    tag = "Users",
    responses(
        (status = 200, description = "The user's live sessions", body = Vec<SessionResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// List a user's sessions
///
/// The user's live sessions on every device. A person reads their own with
/// their session; anyone else needs the right to view users. Read-only.
pub(crate) async fn list_user_sessions(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
) -> Result<Json<Vec<SessionResponse>>, ApiError> {
    let sessions = identity
        .sessions
        .list
        .execute(&tenant.caller, path.whose(&tenant.caller))
        .await?;
    Ok(Json(SessionResponse::listing(&sessions, &tenant.caller)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}/sessions/{session_id}",
    tag = "Users",
    responses(
        (status = 204, description = "The session ended"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the user holds more than the caller", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "It already ended", body = ErrorBody)
    )
)]
/// End a user's session
///
/// Signs the user out on one device. Records
/// `authentication.session_revoked`. A person ends their own with their
/// session; anyone else needs the right to shut users out, and to hold at
/// least everything the user holds.
pub(crate) async fn revoke_user_session(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserSessionPath>,
) -> Result<NoContent, ApiError> {
    let request = RevokeSessionRequest {
        whose: path.whose(&tenant.caller),
        session_id: path.session(),
    };
    identity
        .sessions
        .revoke
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}/sign-ins",
    tag = "Users",
    params(PaginationParams),
    responses(
        (status = 200, description = "The user's sign-ins, newest first", body = PageResponse<AuditLogEntryResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// A user's sign-in history
///
/// The user's sign-ins and failed attempts, newest first, as the tenant's
/// audit trail recorded them. A person reads their own with their session;
/// anyone else needs the right to view users. Read-only.
pub(crate) async fn list_user_sign_ins(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<AuditLogEntryResponse>>, ApiError> {
    let request = ListSignInsRequest {
        whose: path.whose(&tenant.caller),
        page: pagination,
    };
    let log = identity
        .sessions
        .sign_ins
        .execute(&tenant.caller, request)
        .await?;
    Ok(Json(PageResponse::from_page(
        log,
        AuditLogEntryResponse::from,
    )))
}

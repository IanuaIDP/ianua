//! Link handlers: an account's links to identity providers, listed,
//! confirmed again by their holder, or taken off by their holder or an
//! admin.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::federation::links::{Of, UnlinkAccountRequest, UnlinkFrom};
use ianua_assembly::federation::FederationState;

use crate::dto::federation::links::{LinkListResponse, ReconfirmLinkBody};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::federation::{ConnectionLinkPath, ConnectionPath, FederatedUserPath};
use crate::response::NoContent;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/links",
    tag = "Federation",
    responses(
        (status = 200, description = "Success", body = LinkListResponse),
        (status = 401, description = "Unauthenticated, or not a tenant user's own session", body = ErrorBody)
    )
)]
/// List my linked identities
///
/// The identity providers linked to the signed-in person's own account,
/// oldest first: the connection, the id the provider knows them by, and
/// when the link was made and last confirmed. Requires a tenant user's own
/// session. Records nothing.
pub(crate) async fn list_my_links(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
) -> Result<Json<LinkListResponse>, ApiError> {
    let links = federation
        .links
        .list
        .execute(&tenant.caller, Of::OwnAccount)
        .await?;
    Ok(Json(links.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/users/{user_id}/links",
    tag = "Federation",
    responses(
        (status = 200, description = "Success", body = LinkListResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List a user's linked identities
///
/// The identity providers linked to another user's account, oldest first,
/// for an admin who may view users. Records nothing.
pub(crate) async fn list_user_links(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    Path(path): Path<FederatedUserPath>,
) -> Result<Json<LinkListResponse>, ApiError> {
    let links = federation
        .links
        .list
        .execute(&tenant.caller, Of::User(path.user()))
        .await?;
    Ok(Json(links.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/connections/{id}/link/reconfirm",
    tag = "Federation",
    request_body = ReconfirmLinkBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "What was typed again does not prove who they are, or a second factor is needed", body = ErrorBody),
        (status = 404, description = "The account is not linked through this connection", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Locked after too many wrong codes", body = ErrorBody)
    )
)]
/// Confirm my link to an identity provider again
///
/// After a provider's signing key changed, a link waits for its holder to
/// confirm it before the provider signs them in again. The signed-in
/// person proves who they are once more, the way they sign in: their
/// `password` (with a `code` from their second factor when they have one),
/// a sign-in link mailed to them (`mailbox`), or a `passkey` answer. The
/// `proof` is `{"method": "password" | "mailbox" | "passkey", ...}`.
///
/// Returns `404` if their account is not linked through the connection.
/// Records `federation.link_reconfirmed`. Requires a tenant user's own
/// session.
pub(crate) async fn reconfirm_link(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    Path(path): Path<ConnectionPath>,
    Json(body): Json<ReconfirmLinkBody>,
) -> Result<NoContent, ApiError> {
    federation
        .links
        .reconfirm
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.through(path.connection())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/connections/{id}/link",
    tag = "Federation",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 404, description = "The account is not linked through this connection", body = ErrorBody)
    )
)]
/// Unlink my account from an identity provider
///
/// Takes the provider the connection reaches off the signed-in person's
/// own account, so it no longer signs them in; it only takes a way in
/// away. Returns `404` if the connection does not exist or their account
/// is not linked through it. Records `federation.account_unlinked`.
/// Requires a tenant user's own session.
pub(crate) async fn unlink_own_account(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    Path(path): Path<ConnectionPath>,
) -> Result<NoContent, ApiError> {
    federation
        .links
        .unlink
        .execute(
            &tenant.caller,
            &tenant.auditor,
            UnlinkAccountRequest {
                connection_id: path.connection(),
                from: UnlinkFrom::OwnAccount,
            },
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/connections/{id}/links/{user_id}",
    tag = "Federation",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such user, or not linked through this connection", body = ErrorBody)
    )
)]
/// Unlink a user's account from an identity provider
///
/// An admin takes the provider the connection reaches off another user's
/// account, so it no longer signs them in. Refused (`403`) when the admin
/// may not change that account's sign-in. Returns `404` if the connection
/// or the user does not exist, or the user is not linked through it.
/// Records `federation.account_unlinked`, so the person can be told.
pub(crate) async fn unlink_user_account(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    Path(path): Path<ConnectionLinkPath>,
) -> Result<NoContent, ApiError> {
    federation
        .links
        .unlink
        .execute(
            &tenant.caller,
            &tenant.auditor,
            UnlinkAccountRequest {
                connection_id: path.connection(),
                from: UnlinkFrom::User(path.user()),
            },
        )
        .await?;
    Ok(NoContent)
}

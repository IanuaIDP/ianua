//! Account channel handlers: setting up the one address a service sends
//! every event of an account to.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::workflows::WorkflowState;

use crate::dto::workflows::accounts::channels::{
    ChannelResponse, ChannelTokenResponse, SetChannelKeyBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::workflows::AccountPath;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/accounts/{account_id}/event-channel",
    tag = "Workflows",
    responses(
        (status = 200, description = "Success", body = ChannelResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such account, or no channel yet", body = ErrorBody)
    )
)]
/// Show an account's event channel
///
/// The `address` to give a service whose events reach one address per
/// account, how the channel gets ready (`setup`) and where it is
/// (`status`). No channel exists until a workflow starting on that
/// service's events is published. Nothing secret is returned. Requires
/// owning the account or the right to connect accounts.
pub(crate) async fn show_channel(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<AccountPath>,
) -> Result<Json<ChannelResponse>, ApiError> {
    let view = workflows
        .show_channel
        .execute(&tenant.caller, path.account())
        .await?;
    Ok(Json(ChannelResponse::from(view)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/accounts/{account_id}/event-channel/key",
    tag = "Workflows",
    request_body = SetChannelKeyBody,
    responses(
        (status = 200, description = "Kept", body = ChannelResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Not the account's owner", body = ErrorBody),
        (status = 404, description = "No such account, or no channel yet", body = ErrorBody),
        (status = 409, description = "This service's channel takes no key", body = ErrorBody),
        (status = 422, description = "The key is too short or too long", body = ErrorBody)
    )
)]
/// Paste in an event channel's key
///
/// Keeps the key the service signs its deliveries with, sealed, and puts
/// the channel live. Pasting again replaces it. The key is never returned.
/// Records `workflows.channel_ready`. Only the account's owner may do it.
pub(crate) async fn set_channel_key(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<AccountPath>,
    Json(body): Json<SetChannelKeyBody>,
) -> Result<Json<ChannelResponse>, ApiError> {
    let view = workflows
        .set_channel_key
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.request(path.account())?,
        )
        .await?;
    Ok(Json(ChannelResponse::from(view)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/accounts/{account_id}/event-channel/token",
    tag = "Workflows",
    responses(
        (status = 200, description = "The token", body = ChannelTokenResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Not the account's owner", body = ErrorBody),
        (status = 404, description = "No such account, or no channel yet", body = ErrorBody),
        (status = 409, description = "No token is waiting", body = ErrorBody)
    )
)]
/// Read an event channel's token
///
/// Returns the token the service sent the address, to paste back at the
/// service. A `POST` because reading it is on the record: records
/// `workflows.channel_token_shown`. Only the account's owner may do it.
pub(crate) async fn show_channel_token(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<AccountPath>,
) -> Result<Json<ChannelTokenResponse>, ApiError> {
    let token = workflows
        .show_channel_token
        .execute(&tenant.caller, &tenant.auditor, path.account())
        .await?;
    Ok(Json(ChannelTokenResponse::from(token)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/accounts/{account_id}/event-channel/confirm",
    tag = "Workflows",
    responses(
        (status = 200, description = "Live", body = ChannelResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Not the account's owner", body = ErrorBody),
        (status = 404, description = "No such account, or no channel yet", body = ErrorBody),
        (status = 422, description = "No token is waiting", body = ErrorBody)
    )
)]
/// Confirm an event channel's token was pasted back
///
/// Puts the channel live once its owner has pasted the token back at the
/// service. Until then the address reads nothing. Records
/// `workflows.channel_ready`. Only the account's owner may do it.
pub(crate) async fn confirm_channel(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<AccountPath>,
) -> Result<Json<ChannelResponse>, ApiError> {
    let view = workflows
        .confirm_channel
        .execute(&tenant.caller, &tenant.auditor, path.account())
        .await?;
    Ok(Json(ChannelResponse::from(view)))
}

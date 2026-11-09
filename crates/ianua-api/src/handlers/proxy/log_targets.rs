//! Log target handlers: the places a tenant ships its request records to,
//! such as its SIEM, an object store or Datadog.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::proxy::ProxyState;

use crate::dto::proxy::log_targets::{ChangeLogTargetBody, CreateLogTargetBody, LogTargetResponse};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::proxy::LogTargetPath;
use crate::response::{Created, NoContent};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/gateway/log-targets",
    tag = "Gateway",
    request_body = CreateLogTargetBody,
    responses(
        (status = 201, description = "Created", body = LogTargetResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the plan's limit is reached", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 409, description = "Another target has the name", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Create a log shipping target
///
/// Names a place the tenant's request records are shipped to: an HTTPS
/// collector, an object store bucket or a Datadog site, which records
/// (`all`, `denied_only` or a sample) and in which `format`. A bucket and
/// Datadog need a `credential`; it is sealed at once and never shown again.
/// The target starts `Active`.
///
/// `422` for an address that is not public HTTPS or a destination missing
/// the credential it needs, `409` for a name the tenant already uses.
/// Records `proxy.log_target_created`, without the credential. Requires the
/// right to change the tenant's routing.
pub(crate) async fn create_log_target(
    State(proxy): State<ProxyState>,
    tenant: TenantCaller,
    Json(body): Json<CreateLogTargetBody>,
) -> Result<Created<LogTargetResponse>, ApiError> {
    let target = proxy
        .log_targets
        .create
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(target.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/gateway/log-targets",
    tag = "Gateway",
    responses(
        (status = 200, description = "Success", body = Vec<LogTargetResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List the log shipping targets
///
/// Every place the tenant ships request records to, with what it ships and
/// whether it is `Active` or `Paused`. A credential is never shown, only
/// whether one is set. Read-only. Requires the right to view the tenant's
/// routing.
pub(crate) async fn list_log_targets(
    State(proxy): State<ProxyState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<LogTargetResponse>>, ApiError> {
    let targets = proxy.log_targets.list.execute(&tenant.caller, ()).await?;
    Ok(Json(targets.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/gateway/log-targets/{id}",
    tag = "Gateway",
    responses(
        (status = 200, description = "Success", body = LogTargetResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such target", body = ErrorBody)
    )
)]
/// Get a log shipping target
///
/// One target by `id`, without its credential. `404` if the tenant has no
/// such target. Read-only. Requires the right to view the tenant's routing.
pub(crate) async fn get_log_target(
    State(proxy): State<ProxyState>,
    tenant: TenantCaller,
    Path(path): Path<LogTargetPath>,
) -> Result<Json<LogTargetResponse>, ApiError> {
    let target = proxy
        .log_targets
        .get
        .execute(&tenant.caller, path.target())
        .await?;
    Ok(Json(target.into()))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/gateway/log-targets/{id}",
    tag = "Gateway",
    request_body = ChangeLogTargetBody,
    responses(
        (status = 200, description = "The target as changed", body = LogTargetResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such target", body = ErrorBody),
        (status = 409, description = "Another target has the name", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Change a log shipping target
///
/// Sets where, what and how the target ships, given whole, and optionally
/// its `name`. The `credential` left out keeps the one it has, `null`
/// removes it and a value replaces it, sealed at once. Whether it is
/// paused does not change. Answers the target as changed, without its
/// credential. Records `proxy.log_target_changed`. Requires the right to
/// change the tenant's routing.
pub(crate) async fn change_log_target(
    State(proxy): State<ProxyState>,
    tenant: TenantCaller,
    Path(path): Path<LogTargetPath>,
    Json(body): Json<ChangeLogTargetBody>,
) -> Result<Json<LogTargetResponse>, ApiError> {
    let target = proxy
        .log_targets
        .change
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.target())?,
        )
        .await?;
    Ok(Json(target.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/gateway/log-targets/{id}/pause",
    tag = "Gateway",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such target", body = ErrorBody),
        (status = 422, description = "The target is already paused", body = ErrorBody)
    )
)]
/// Pause a log shipping target
///
/// Stops sending records to the target until it is resumed; its settings
/// are kept. Records the gateway decides meanwhile are not sent later.
/// **State.** `Active -> Paused`. Records `proxy.log_target_paused`.
/// Requires the right to change the tenant's routing.
pub(crate) async fn pause_log_target(
    State(proxy): State<ProxyState>,
    tenant: TenantCaller,
    Path(path): Path<LogTargetPath>,
) -> Result<NoContent, ApiError> {
    proxy
        .log_targets
        .pause
        .execute(&tenant.caller, &tenant.auditor, path.target())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/gateway/log-targets/{id}/resume",
    tag = "Gateway",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such target", body = ErrorBody),
        (status = 422, description = "The target is not paused", body = ErrorBody)
    )
)]
/// Resume a log shipping target
///
/// Sends records to the target again, from the next batch on. **State.**
/// `Paused -> Active`. Records `proxy.log_target_resumed`. Requires the
/// right to change the tenant's routing.
pub(crate) async fn resume_log_target(
    State(proxy): State<ProxyState>,
    tenant: TenantCaller,
    Path(path): Path<LogTargetPath>,
) -> Result<NoContent, ApiError> {
    proxy
        .log_targets
        .resume
        .execute(&tenant.caller, &tenant.auditor, path.target())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/gateway/log-targets/{id}",
    tag = "Gateway",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such target", body = ErrorBody)
    )
)]
/// Delete a log shipping target
///
/// Stops shipping to it and forgets it, sealed credential and all. Records
/// `proxy.log_target_deleted`. Requires the right to change the tenant's
/// routing.
pub(crate) async fn delete_log_target(
    State(proxy): State<ProxyState>,
    tenant: TenantCaller,
    Path(path): Path<LogTargetPath>,
) -> Result<NoContent, ApiError> {
    proxy
        .log_targets
        .delete
        .execute(&tenant.caller, &tenant.auditor, path.target())
        .await?;
    Ok(NoContent)
}

//! Audit stream handlers: sending a tenant's audit records to the SIEM it
//! runs, and changing, pausing, resuming and removing such a stream.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::tenant::TenantState;

use crate::dto::tenant::audit_streams::{
    AuditStreamBody, AuditStreamCreatedResponse, AuditStreamResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::tenant::AuditStreamPath;
use crate::response::{Created, NoContent};

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/audit-streams",
    tag = "Tenants",
    responses(
        (status = 200, description = "The tenant's audit streams", body = Vec<AuditStreamResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// List the tenant's audit streams
///
/// Every stream of this tenant's audit records to a SIEM: its name, where
/// it sends (kind, address, index, site or host, and the name of any
/// header, never a credential), which event types it sends (`null` for
/// all), and whether it is `active`, `failing` (since when, how many sends
/// in a row) or `paused` (why, since when). Read-only.
///
/// Requires the right to view the tenant's compliance settings.
pub(crate) async fn list_audit_streams(
    State(tenant): State<TenantState>,
    caller: TenantCaller,
) -> Result<Json<Vec<AuditStreamResponse>>, ApiError> {
    let streams = tenant
        .audit_streams
        .list
        .execute(&caller.caller, ())
        .await?;
    Ok(Json(
        streams.iter().map(AuditStreamResponse::from).collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/audit-streams",
    tag = "Tenants",
    request_body = AuditStreamBody,
    responses(
        (status = 201, description = "Stream added", body = AuditStreamCreatedResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "As many streams as the tenant may keep", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Add an audit stream
///
/// Sends new tenant audit records to Splunk HEC, Datadog, syslog over TLS, or
/// any public HTTPS endpoint, each by `destination.kind`. `events` narrows
/// it to some event types. Addresses must be public; the credential
/// (collector token, API key, header value) is sealed at once and never
/// shown again.
///
/// A stream copies every record out of the platform, so the body carries
/// `proof`, the caller's own sign-in typed again: a change made with an
/// API key, or with a proof that does not hold, is `403`, and a proof
/// missing the code of the caller's second factor asks for it. The plan's
/// audit stream limit is `403`. Records `tenant.audit_stream_created`,
/// naming the kind of destination only.
///
/// Requires the right to change the tenant's compliance settings.
pub(crate) async fn create_audit_stream(
    State(tenant): State<TenantState>,
    caller: TenantCaller,
    Json(body): Json<AuditStreamBody>,
) -> Result<Created<AuditStreamCreatedResponse>, ApiError> {
    let id = tenant
        .audit_streams
        .create
        .execute(&caller.caller, &caller.auditor, body.into_create()?)
        .await?;
    Ok(Created(AuditStreamCreatedResponse { id }))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/audit-streams/{stream_id}",
    tag = "Tenants",
    request_body = AuditStreamBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Change an audit stream
///
/// Replaces the stream's name, destination and events whole, with the
/// destination's credential typed again. Like adding one, the body carries
/// `proof`, the caller's own sign-in typed again. Records
/// `tenant.audit_stream_changed`.
///
/// Requires the right to change the tenant's compliance settings.
pub(crate) async fn reconfigure_audit_stream(
    State(tenant): State<TenantState>,
    caller: TenantCaller,
    Path(path): Path<AuditStreamPath>,
    Json(body): Json<AuditStreamBody>,
) -> Result<NoContent, ApiError> {
    tenant
        .audit_streams
        .reconfigure
        .execute(
            &caller.caller,
            &caller.auditor,
            body.into_reconfigure(path.stream())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/audit-streams/{stream_id}/pause",
    tag = "Tenants",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Already paused", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Pause an audit stream
///
/// Stops sending records through the stream until it is resumed; records
/// made meanwhile are not sent later. A stream already paused is `409`.
/// Records `tenant.audit_stream_paused`.
///
/// Requires the right to change the tenant's compliance settings.
pub(crate) async fn pause_audit_stream(
    State(tenant): State<TenantState>,
    caller: TenantCaller,
    Path(path): Path<AuditStreamPath>,
) -> Result<NoContent, ApiError> {
    tenant
        .audit_streams
        .pause
        .execute(&caller.caller, &caller.auditor, path.stream())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/audit-streams/{stream_id}/resume",
    tag = "Tenants",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Not paused", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Resume an audit stream
///
/// Starts sending through a paused stream again, whether an administrator
/// paused it or its destination refused too many sends in a row. A stream
/// not paused is `409`. Records `tenant.audit_stream_resumed`.
///
/// Requires the right to change the tenant's compliance settings.
pub(crate) async fn resume_audit_stream(
    State(tenant): State<TenantState>,
    caller: TenantCaller,
    Path(path): Path<AuditStreamPath>,
) -> Result<NoContent, ApiError> {
    tenant
        .audit_streams
        .resume
        .execute(&caller.caller, &caller.auditor, path.stream())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/audit-streams/{stream_id}",
    tag = "Tenants",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Remove an audit stream
///
/// Stops the stream for good and forgets its destination and credential.
/// Records `tenant.audit_stream_removed`.
///
/// Requires the right to change the tenant's compliance settings.
pub(crate) async fn remove_audit_stream(
    State(tenant): State<TenantState>,
    caller: TenantCaller,
    Path(path): Path<AuditStreamPath>,
) -> Result<NoContent, ApiError> {
    tenant
        .audit_streams
        .remove
        .execute(&caller.caller, &caller.auditor, path.stream())
        .await?;
    Ok(NoContent)
}

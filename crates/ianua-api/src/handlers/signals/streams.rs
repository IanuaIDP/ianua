//! Signal stream handlers: registering a receiver of the tenant's security
//! signals, changing it, its lifecycle and status, the receiver confirming
//! its endpoint, and the transmitter's configuration.

use axum::extract::{Path, State};
use ianua_app::ports::signals::StreamSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::signals::streams::{ListRequest, RegisterRequest, StreamFilter};
use ianua_assembly::signals::SignalState;

use crate::dto::signals::{
    ConfirmEndpointBody, RegisterStreamBody, RegisterStreamResponse, StreamFilterParams,
    StreamResponse, StreamStatusResponse, TransmitterConfigurationResponse, UpdateStreamBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::listing::ListingQuery;
use crate::extractors::pagination::PaginationParams;
use crate::extractors::paths::signals::StreamPath;
use crate::extractors::public_tenant::PublicTenant;
use crate::extractors::signals::StreamReceiver;
use crate::extractors::sort::SortQuery;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/streams",
    tag = "Signals",
    request_body = RegisterStreamBody,
    responses(
        (status = 201, description = "Created", body = RegisterStreamResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Register a signal stream
///
/// Registers a receiver of tenant CAEP/RISC tokens with a public-HTTPS `endpoint`,
/// `delivery_method` (`Push` or `Poll`) and at least one `signal_types` entry.
/// Optionally the `authorization_header` each push carries (kept sealed,
/// never shown again) and the `default_subjects` the stream starts with
/// (`ALL`, the default, or `NONE` until subjects are added). Created in
/// `Active` status with its endpoint `Pending`: ianua sends the endpoint a
/// challenge as a verification event, and the stream delivers nothing
/// until the receiver echoes it to the confirm endpoint. Returns `id` and one-time
/// `receiver_key`, a bearer for polling, verification requests and subject changes
/// on this stream only. Records `signals.stream_registered`.
///
/// `422` for an endpoint that is not public HTTPS, no signal type, or a
/// header value that is not 1 to 4096 visible characters. Requires the
/// right to manage signal streams.
pub(crate) async fn register_stream(
    State(signals): State<SignalState>,
    tenant: TenantCaller,
    Json(body): Json<RegisterStreamBody>,
) -> Result<Created<RegisterStreamResponse>, ApiError> {
    let request = RegisterRequest::try_from(body)?;
    let registered = signals
        .register
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Created(RegisterStreamResponse::from(registered)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/streams",
    tag = "Signals",
    params(StreamFilterParams, SortQuery<StreamSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<StreamResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// List signal streams
///
/// Returns this tenant's signal stream receivers, optionally only those in
/// one `status` (`Active`, `Paused` or `Disabled`), sortable and paginated.
/// Each entry carries the endpoint and whether it is verified, the delivery
/// method, the signal types and the lifecycle status. Read-only. Requires
/// the right to view signal streams.
pub(crate) async fn list_streams(
    State(signals): State<SignalState>,
    tenant: TenantCaller,
    ListingQuery {
        query: filter,
        sort,
        page: pagination,
    }: ListingQuery<StreamFilterParams, StreamSortField>,
) -> Result<Json<PageResponse<StreamResponse>>, ApiError> {
    let request = ListRequest {
        filter: StreamFilter {
            status: filter.status,
        },
        sort,
        page: pagination,
    };
    let page = signals.list.execute(&tenant.caller, request).await?;
    Ok(Json(PageResponse::from_page(page, StreamResponse::from)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/streams/{id}",
    tag = "Signals",
    responses(
        (status = 200, description = "Success", body = StreamResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Get a signal stream
///
/// Returns a single stream by `id`, with whether its endpoint is verified
/// but never the challenge the endpoint was sent. `404` if it does not
/// exist under this tenant. Read-only. Requires the right to view signal
/// streams.
pub(crate) async fn get_stream(
    State(signals): State<SignalState>,
    tenant: TenantCaller,
    Path(path): Path<StreamPath>,
) -> Result<Json<StreamResponse>, ApiError> {
    let stream = signals.get.execute(&tenant.caller, path.stream()).await?;
    Ok(Json(StreamResponse::from(stream)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/streams/{id}/status",
    tag = "Signals",
    responses(
        (status = 200, description = "Success", body = StreamStatusResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Get a signal stream's status
///
/// Returns whether the stream is `enabled`, `paused` or `disabled`, in the
/// Shared Signals framework's words. Pause, resume and disable change it.
/// `404` if the stream does not exist. Read-only. Requires the right to
/// view signal streams.
pub(crate) async fn get_stream_status(
    State(signals): State<SignalState>,
    tenant: TenantCaller,
    Path(path): Path<StreamPath>,
) -> Result<Json<StreamStatusResponse>, ApiError> {
    let status = signals
        .get_status
        .execute(&tenant.caller, path.stream())
        .await?;
    Ok(Json(StreamStatusResponse::of(path.stream(), status)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/.well-known/ssf-configuration",
    tag = "Signals",
    responses(
        (status = 200, description = "Transmitter metadata", body = TransmitterConfigurationResponse),
        (status = 403, description = "The workspace is not available", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// Shared Signals transmitter configuration
///
/// Serves the transmitter metadata the Shared Signals framework asks for,
/// so a receiver can discover the tenant's transmitter: the `issuer` its
/// tokens carry, the `jwks_uri` their keys are published at, push and poll
/// delivery, the endpoint streams are registered at, and the status,
/// subject and verification endpoints. Those are per stream: each names
/// `{stream_id}` where the receiver puts its stream's id, and the receiver
/// calls them with the key it was handed at registration as its bearer.
/// Public: no authentication. Records nothing.
pub(crate) async fn transmitter_configuration(
    State(signals): State<SignalState>,
    tenant: PublicTenant,
) -> Result<Json<TransmitterConfigurationResponse>, ApiError> {
    let configuration = signals.configuration.execute(&tenant.tenant, ()).await?;
    Ok(Json(TransmitterConfigurationResponse::of(
        configuration,
        &tenant.issuer(&signals.app_base_url),
    )))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/streams/{id}",
    tag = "Signals",
    request_body = UpdateStreamBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Update a signal stream
///
/// Partial update: send `endpoint`, `delivery_method`, `signal_types`
/// and/or `authorization_header` (`null` for none) to change just those;
/// leave any out to keep it. This
/// edits configuration only, never `status` (pause, resume and disable do
/// that). A new endpoint is `Pending` again and is sent a fresh challenge.
/// Records one `signals.stream_updated`; a body that changes nothing
/// records nothing. `404` if the stream does not exist, `422` for an
/// endpoint that is not public HTTPS or an empty list of signal types.
/// Requires the right to manage signal streams.
pub(crate) async fn update_stream(
    State(signals): State<SignalState>,
    tenant: TenantCaller,
    Path(path): Path<StreamPath>,
    Json(body): Json<UpdateStreamBody>,
) -> Result<NoContent, ApiError> {
    signals
        .update
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.update_of(path.stream())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/streams/{id}/pause",
    tag = "Signals",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Not active", body = ErrorBody)
    )
)]
/// Pause a signal stream
///
/// Pauses an `Active` stream. Signals raised while it is paused are
/// dropped, not queued. Records `signals.stream_paused`. `404` if the
/// stream does not exist, `422` if it is not `Active`. Requires the right
/// to manage signal streams.
pub(crate) async fn pause_stream(
    State(signals): State<SignalState>,
    tenant: TenantCaller,
    Path(path): Path<StreamPath>,
) -> Result<NoContent, ApiError> {
    signals
        .pause
        .execute(&tenant.caller, &tenant.auditor, path.stream())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/streams/{id}/resume",
    tag = "Signals",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Not paused", body = ErrorBody)
    )
)]
/// Resume a signal stream
///
/// Resumes a `Paused` stream. Signals raised from now on are delivered;
/// none from the pause are. Records `signals.stream_resumed`. `404` if the
/// stream does not exist, `422` if it is not `Paused` (a disabled stream
/// stays disabled). Requires the right to manage signal streams.
pub(crate) async fn resume_stream(
    State(signals): State<SignalState>,
    tenant: TenantCaller,
    Path(path): Path<StreamPath>,
) -> Result<NoContent, ApiError> {
    signals
        .resume
        .execute(&tenant.caller, &tenant.auditor, path.stream())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/streams/{id}/disable",
    tag = "Signals",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Already disabled", body = ErrorBody)
    )
)]
/// Disable a signal stream
///
/// Disables a stream for good: the receiver gets nothing more through it,
/// and unlike a pause it cannot be resumed. Delete it to remove it
/// entirely. Records `signals.stream_disabled`. `404` if the stream does
/// not exist, `422` if it is already disabled. Requires the right to manage
/// signal streams.
pub(crate) async fn disable_stream(
    State(signals): State<SignalState>,
    tenant: TenantCaller,
    Path(path): Path<StreamPath>,
) -> Result<NoContent, ApiError> {
    signals
        .disable
        .execute(&tenant.caller, &tenant.auditor, path.stream())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/streams/{id}",
    tag = "Signals",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Not disabled", body = ErrorBody)
    )
)]
/// Delete a signal stream
///
/// Removes a signal stream receiver for good. It must be disabled first, so
/// a stream that may still deliver is never deleted (`409`). Records
/// `signals.stream_deleted`. `404` if it does not exist. Requires the right
/// to manage signal streams.
pub(crate) async fn delete_stream(
    State(signals): State<SignalState>,
    tenant: TenantCaller,
    Path(path): Path<StreamPath>,
) -> Result<NoContent, ApiError> {
    signals
        .delete
        .execute(&tenant.caller, &tenant.auditor, path.stream())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/streams/{id}/confirm",
    tag = "Signals",
    request_body = ConfirmEndpointBody,
    responses(
        (status = 204, description = "Endpoint verified"),
        (status = 401, description = "No such tenant or stream, or the tenant is closed", body = ErrorBody),
        (status = 403, description = "Not the challenge the endpoint was sent", body = ErrorBody),
        (status = 422, description = "Already verified, or not a challenge", body = ErrorBody)
    )
)]
/// Confirm a signal stream's endpoint
///
/// Called by the receiver, not by a person of the tenant: it holds no
/// session, only the `challenge` ianua sent its endpoint when the endpoint
/// was set, which it echoes here. When the echo matches, the endpoint is
/// verified and the stream starts delivering to it. The domain has no event
/// for a verified endpoint, so nothing is recorded.
///
/// `401` when no open tenant has the path's name or the tenant has no such
/// stream, answered alike so a caller learns nothing of which tenants
/// exist; `403` when the echo is not the challenge the endpoint was sent
/// (the endpoint stays pending); `422` when the endpoint is already
/// verified. Needs no credential.
pub(crate) async fn confirm_endpoint(
    State(signals): State<SignalState>,
    receiver: StreamReceiver,
    Path(path): Path<StreamPath>,
    Json(body): Json<ConfirmEndpointBody>,
) -> Result<NoContent, ApiError> {
    signals
        .confirm_endpoint
        .execute(
            &receiver.tenant,
            &receiver.auditor,
            body.echo_for(path.stream())?,
        )
        .await?;
    Ok(NoContent)
}

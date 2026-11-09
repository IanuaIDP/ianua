//! Consumer handlers: a tenant's machine identities, their credentials,
//! clearance and lifecycle.

use axum::extract::{Path, State};
use ianua_app::ports::consumers::ConsumerSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::consumers::{CreateRequest, ListRequest};
use ianua_assembly::consumers::ConsumerState;

use crate::dto::consumers::{
    ChangeClearanceBody, ChangeCredentialExpiryBody, ChangeQuotaBody, ConsumerResponse,
    CreateConsumerBody, CreateConsumerResponse, DescribeConsumerBody, RenameConsumerBody,
    RotateCredentialBody, RotatedCredentialResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::consumers::ConsumerPath;
use crate::extractors::sort::SortQuery;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/consumers",
    tag = "Consumers",
    request_body = CreateConsumerBody,
    responses(
        (status = 201, description = "Created", body = CreateConsumerResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Create a consumer
///
/// Registers an `Active` machine caller with a `name`, optional `description`,
/// `clearance` (default `Internal`), `credential_kind` (`api_key`, `client_cert`
/// or `jwt_bearer`), optional `expires_at` and request `quota`.
/// Returns its `id` and records `consumers.consumer_created`.
///
/// The platform generates `api_key` and returns it once, storing only its prefix
/// and keyed digest. Certificate and token consumers receive `api_key: null`.
///
/// Access starts empty and comes from role assignments, as for a person.
///
/// `422` for an invalid name or credential. `403` when the caller may not
/// create consumers, clears it for more than they may see themselves, names
/// the tenant's own token issuer, or the plan's consumer limit is reached.
/// Requires the right to create consumers.
pub(crate) async fn create_consumer(
    State(consumers): State<ConsumerState>,
    tenant: TenantCaller,
    Json(body): Json<CreateConsumerBody>,
) -> Result<Created<CreateConsumerResponse>, ApiError> {
    let request = CreateRequest::try_from(body)?;
    let created = consumers
        .create
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Created(CreateConsumerResponse::from(created)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/consumers/{id}",
    tag = "Consumers",
    responses(
        (status = 200, description = "Success", body = ConsumerResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Get a consumer
///
/// Returns a single consumer by `id`: name, description, credential hint,
/// clearance and lifecycle `status`. `404` if it does not exist under this
/// tenant. Read-only. Requires the right to view consumers.
pub(crate) async fn get_consumer(
    State(consumers): State<ConsumerState>,
    tenant: TenantCaller,
    Path(path): Path<ConsumerPath>,
) -> Result<Json<ConsumerResponse>, ApiError> {
    let consumer = consumers
        .get
        .execute(&tenant.caller, path.consumer())
        .await?;
    Ok(Json(ConsumerResponse::from(consumer)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/consumers",
    tag = "Consumers",
    params(SortQuery<ConsumerSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<ConsumerResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List consumers
///
/// Returns this tenant's consumers, sortable and paginated. Each entry
/// carries the name, credential hint, clearance and lifecycle `status`
/// (`Active` or `Disabled`). Read-only. Requires the right to view
/// consumers.
pub(crate) async fn list_consumers(
    State(consumers): State<ConsumerState>,
    tenant: TenantCaller,
    SortQuery(sort): SortQuery<ConsumerSortField>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<ConsumerResponse>>, ApiError> {
    let request = ListRequest {
        sort,
        page: pagination,
    };
    let page = consumers.list.execute(&tenant.caller, request).await?;
    Ok(Json(PageResponse::from_page(page, ConsumerResponse::from)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/consumers/{id}",
    tag = "Consumers",
    request_body = RenameConsumerBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Rename a consumer
///
/// Gives the consumer a new display `name`. Its credential, clearance and
/// status stay as they were. Records `consumers.consumer_renamed` with both
/// names. `404` if the consumer does not exist, `422` for an invalid name.
/// Requires the right to update consumers.
pub(crate) async fn rename_consumer(
    State(consumers): State<ConsumerState>,
    tenant: TenantCaller,
    Path(path): Path<ConsumerPath>,
    Json(body): Json<RenameConsumerBody>,
) -> Result<NoContent, ApiError> {
    consumers
        .rename
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.renaming(path.consumer())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/consumers/{id}/clearance",
    tag = "Consumers",
    request_body = ChangeClearanceBody,
    responses(
        (status = 200, description = "Success", body = ConsumerResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Change a consumer's clearance
///
/// Sets the most sensitive data the consumer may receive and answers the
/// consumer as saved. Raising it lets the consumer subscribe to topics it
/// could not reach before, so nobody clears a consumer for more than they
/// may see themselves (`403`). A change records
/// `consumers.clearance_changed`; setting the clearance it already has
/// records nothing. `404` if the consumer does not exist. Requires the full
/// right over consumers.
pub(crate) async fn change_clearance(
    State(consumers): State<ConsumerState>,
    tenant: TenantCaller,
    Path(path): Path<ConsumerPath>,
    Json(body): Json<ChangeClearanceBody>,
) -> Result<Json<ConsumerResponse>, ApiError> {
    let consumer = consumers
        .change_clearance
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.change_of(path.consumer()),
        )
        .await?;
    Ok(Json(ConsumerResponse::from(consumer)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/consumers/{id}/disable",
    tag = "Consumers",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Already disabled", body = ErrorBody)
    )
)]
/// Disable a consumer
///
/// Disables an `Active` consumer: every request presenting its credential
/// is denied until it is enabled again. Use this to revoke a machine
/// identity for a while without deleting it. Records
/// `consumers.consumer_disabled`. `404` if the consumer does not exist,
/// `422` if it is already disabled. Requires the right to update consumers.
pub(crate) async fn disable_consumer(
    State(consumers): State<ConsumerState>,
    tenant: TenantCaller,
    Path(path): Path<ConsumerPath>,
) -> Result<NoContent, ApiError> {
    consumers
        .disable
        .execute(&tenant.caller, &tenant.auditor, path.consumer())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/consumers/{id}/enable",
    tag = "Consumers",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Already active", body = ErrorBody)
    )
)]
/// Enable a consumer
///
/// Enables a `Disabled` consumer again, so its credential is accepted.
/// Records `consumers.consumer_enabled`. `404` if the consumer does not
/// exist, `422` if it is already active. Requires the right to update
/// consumers.
pub(crate) async fn enable_consumer(
    State(consumers): State<ConsumerState>,
    tenant: TenantCaller,
    Path(path): Path<ConsumerPath>,
) -> Result<NoContent, ApiError> {
    consumers
        .enable
        .execute(&tenant.caller, &tenant.auditor, path.consumer())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/consumers/{id}/rotate",
    tag = "Consumers",
    request_body = RotateCredentialBody,
    responses(
        (status = 200, description = "Rotated: the new API key, shown once", body = RotatedCredentialResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Rotate a consumer credential
///
/// Replaces the consumer's credential with a new one (`api_key`,
/// `client_cert` or `jwt_bearer`), working until `expires_at` or for good.
/// The old one stops working at once, or keeps working beside the new one
/// for `overlap_seconds` (at most seven days) so callers can move over; a
/// credential kept from an earlier rotation is dropped. Whoever sets the
/// credential can sign in as the consumer, so the caller must hold
/// everything the consumer holds (`403` otherwise). Records
/// `consumers.credential_rotated`. `404` if the consumer does not exist,
/// `422` for an invalid credential, an expiry already passed or an overlap
/// too long. Requires the right to update consumers.
///
/// A new API key is made by the platform and answered once as `api_key`;
/// only its prefix and a keyed digest are kept. Rotating to a certificate
/// or a token issuer answers `api_key: null`.
pub(crate) async fn rotate_credential(
    State(consumers): State<ConsumerState>,
    tenant: TenantCaller,
    Path(path): Path<ConsumerPath>,
    Json(body): Json<RotateCredentialBody>,
) -> Result<Json<RotatedCredentialResponse>, ApiError> {
    let rotated = consumers
        .rotate
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.rotation_of(path.consumer())?,
        )
        .await?;
    Ok(Json(RotatedCredentialResponse::from(rotated)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/consumers/{id}/end-overlap",
    tag = "Consumers",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "No overlap to end", body = ErrorBody)
    )
)]
/// End a credential overlap
///
/// Stops the credential the last rotation replaced from working now,
/// before its overlap runs out: every caller has moved over, or the old
/// credential leaked. Records `consumers.credential_overlap_ended`. `404`
/// if the consumer does not exist, `422` when no old credential is still
/// working. Requires the right to update consumers.
pub(crate) async fn end_credential_overlap(
    State(consumers): State<ConsumerState>,
    tenant: TenantCaller,
    Path(path): Path<ConsumerPath>,
) -> Result<NoContent, ApiError> {
    consumers
        .end_overlap
        .execute(&tenant.caller, &tenant.auditor, path.consumer())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/consumers/{id}/expiry",
    tag = "Consumers",
    request_body = ChangeCredentialExpiryBody,
    responses(
        (status = 200, description = "Success", body = ConsumerResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Change a credential's expiry
///
/// Sets when the consumer's current credential stops working
/// (`expires_at`), or that it never does (`null`), and answers the consumer
/// as saved. Records `consumers.credential_expiry_changed`. `404` if the
/// consumer does not exist, `422` for an instant already passed. Requires
/// the right to update consumers.
pub(crate) async fn change_credential_expiry(
    State(consumers): State<ConsumerState>,
    tenant: TenantCaller,
    Path(path): Path<ConsumerPath>,
    Json(body): Json<ChangeCredentialExpiryBody>,
) -> Result<Json<ConsumerResponse>, ApiError> {
    let consumer = consumers
        .change_expiry
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.change_of(path.consumer()),
        )
        .await?;
    Ok(Json(ConsumerResponse::from(consumer)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/consumers/{id}/quota",
    tag = "Consumers",
    request_body = ChangeQuotaBody,
    responses(
        (status = 200, description = "Success", body = ConsumerResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Change a consumer's quota
///
/// Sets the consumer's own request allowance (`quota`: `requests` per
/// `minute`, `hour`, `day` or `month`), or removes it (`null`), and answers
/// the consumer as saved. The gateway counts the consumer's requests in the
/// current calendar period and refuses the ones past it with `429`; route
/// rate limits apply either way. Requests already counted in the current
/// period count against the new quota. A change records
/// `consumers.quota_changed`; the quota it already has records nothing.
/// `404` if the consumer does not exist, `422` for an allowance of zero or
/// above a billion. Requires the full right over consumers.
pub(crate) async fn change_quota(
    State(consumers): State<ConsumerState>,
    tenant: TenantCaller,
    Path(path): Path<ConsumerPath>,
    Json(body): Json<ChangeQuotaBody>,
) -> Result<Json<ConsumerResponse>, ApiError> {
    let consumer = consumers
        .change_quota
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.change_of(path.consumer())?,
        )
        .await?;
    Ok(Json(ConsumerResponse::from(consumer)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/consumers/{id}/description",
    tag = "Consumers",
    request_body = DescribeConsumerBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Describe a consumer
///
/// Gives the consumer a new `description`, or clears it (`null`). A change
/// records `consumers.description_changed`; the description it already has
/// records nothing. `404` if the consumer does not exist, `422` for an
/// invalid description. Requires the right to update consumers.
pub(crate) async fn describe_consumer(
    State(consumers): State<ConsumerState>,
    tenant: TenantCaller,
    Path(path): Path<ConsumerPath>,
    Json(body): Json<DescribeConsumerBody>,
) -> Result<NoContent, ApiError> {
    consumers
        .describe
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.description_of(path.consumer())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/consumers/{id}",
    tag = "Consumers",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or still active", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Delete a consumer
///
/// Removes a consumer for good. It must be `Disabled` first: an active
/// consumer cannot be deleted, since that would cut live machine traffic
/// unannounced (`403`). Records `consumers.consumer_deleted`. `404` if the
/// consumer does not exist. Requires the right to delete consumers.
pub(crate) async fn delete_consumer(
    State(consumers): State<ConsumerState>,
    tenant: TenantCaller,
    Path(path): Path<ConsumerPath>,
) -> Result<NoContent, ApiError> {
    consumers
        .delete
        .execute(&tenant.caller, &tenant.auditor, path.consumer())
        .await?;
    Ok(NoContent)
}

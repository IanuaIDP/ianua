//! Connection handlers: a tenant's connections to SAML and OIDC identity
//! providers, added, read, changed, switched and removed.

use axum::extract::{Path, State};
use ianua_app::ports::federation::ConnectionSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::federation::FederationState;

use crate::dto::federation::connections::{
    ConnectionFilterParams, ConnectionResponse, CreateConnectionBody, CreateConnectionResponse,
    UpdateConnectionBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::listing::ListingQuery;
use crate::extractors::pagination::PaginationParams;
use crate::extractors::paths::federation::ConnectionPath;
use crate::extractors::sort::SortQuery;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/connections",
    tag = "Federation",
    request_body = CreateConnectionBody,
    responses(
        (status = 201, description = "Created", body = CreateConnectionResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the plan's connection limit is reached", body = ErrorBody),
        (status = 422, description = "Validation error, or the provider's metadata cannot be read", body = ErrorBody)
    )
)]
/// Create a federation connection
///
/// Registers an `Active` external identity provider named `provider_name`, with `config`:
///
/// - `{"Saml": {...}}`: the `entity_id`, `sso_url`, `certificate` and
///   `name_id_format`, with an optional `slo_url` for single logout, a
///   `next_certificate` while the provider rolls its key over, and
///   `sign_requests` to sign the sign-in requests sent to it;
/// - `{"SamlMetadata": {"url": ...}}` or `{"SamlMetadata": {"document": ...}}`:
///   the same settings from publicly fetched or pasted metadata;
/// - `{"Oidc": {...}}`: the issuer, client id, client secret (in
///   `encrypted_client_secret`, sealed before it is stored) and scopes.
///
/// `allowed_domains` are the email domains the provider may sign in; a
/// connection with none signs in nobody. Each must be tenant-verified. The plan's connection limit applies. Records
/// `federation.connection_created`. Returns the new connection's `id`.
pub(crate) async fn create_connection(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    Json(body): Json<CreateConnectionBody>,
) -> Result<Created<CreateConnectionResponse>, ApiError> {
    let id = federation
        .connections
        .create
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(CreateConnectionResponse { id }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/connections",
    tag = "Federation",
    params(ConnectionFilterParams, SortQuery<ConnectionSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<ConnectionResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List federation connections
///
/// Returns this tenant's identity provider connections, optionally filtered
/// by `status` (`Active` / `Disabled`), sortable and paginated. Each entry
/// carries its `protocol` (`Saml` / `Oidc`), `status`, provisioning, allowed
/// domains, trust, group mapping and SAML settings. Records nothing.
pub(crate) async fn list_connections(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    ListingQuery {
        query: filter,
        sort,
        page: pagination,
    }: ListingQuery<ConnectionFilterParams, ConnectionSortField>,
) -> Result<Json<PageResponse<ConnectionResponse>>, ApiError> {
    let page = federation
        .connections
        .list
        .execute(&tenant.caller, filter.listing(sort, pagination))
        .await?;
    Ok(Json(PageResponse::from_page(
        page,
        ConnectionResponse::from,
    )))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/connections/{id}",
    tag = "Federation",
    responses(
        (status = 200, description = "Success", body = ConnectionResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such connection", body = ErrorBody)
    )
)]
/// Get a federation connection
///
/// Returns a single connection by `id`, as the listing shows it. Returns
/// `404` if the connection does not exist under this tenant. Records
/// nothing.
pub(crate) async fn get_connection(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    Path(path): Path<ConnectionPath>,
) -> Result<Json<ConnectionResponse>, ApiError> {
    let connection = federation
        .connections
        .get
        .execute(&tenant.caller, path.connection())
        .await?;
    Ok(Json(ConnectionResponse::from(connection)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/connections/{id}",
    tag = "Federation",
    request_body = UpdateConnectionBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such connection, or no such role", body = ErrorBody),
        (status = 409, description = "The config names another provider, the hint is not an allowed domain, or a domain is not verified", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Update a connection's settings
///
/// Partial update: send any of `provider_name`, `config`,
/// `allowed_domains`, `provisioning` (`{"enabled": bool,
/// "default_role_id": ...}`), `domain_hint` (`null` clears it),
/// `attribute_mapping` (claim to `display_name`, `locale` or `timezone`),
/// `email_trust` (`Unverified` / `Authoritative`) and `assurance_trust`
/// (`Untrusted` / `Trusted`); omit a field to leave it. A new `config` must
/// name the same provider. Anything that lets the provider speak for more
/// people or be believed more needs the full federation right.
///
/// No status change: use the activate and disable endpoints for that.
/// Records `federation.connection_updated`.
pub(crate) async fn update_connection(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    Path(path): Path<ConnectionPath>,
    Json(body): Json<UpdateConnectionBody>,
) -> Result<NoContent, ApiError> {
    federation
        .connections
        .update
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.change_of(path.connection())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/connections/{id}/activate",
    tag = "Federation",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such connection", body = ErrorBody),
        (status = 422, description = "Already active", body = ErrorBody)
    )
)]
/// Activate a connection
///
/// Enables a `Disabled` connection again so people can sign in through it.
/// `Disabled -> Active`. Returns `404` if the connection does not exist,
/// or `422` if it is already `Active`. Records
/// `federation.connection_activated`.
pub(crate) async fn activate_connection(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    Path(path): Path<ConnectionPath>,
) -> Result<NoContent, ApiError> {
    federation
        .connections
        .activate
        .execute(&tenant.caller, &tenant.auditor, path.connection())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/connections/{id}/disable",
    tag = "Federation",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such connection", body = ErrorBody),
        (status = 422, description = "Already disabled", body = ErrorBody)
    )
)]
/// Disable a connection
///
/// Turns a connection off: nobody signs in through it until it is enabled
/// again. `Active -> Disabled`. Returns `404` if the connection does not
/// exist, or `422` if it is already `Disabled`. Records
/// `federation.connection_disabled`.
pub(crate) async fn disable_connection(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    Path(path): Path<ConnectionPath>,
) -> Result<NoContent, ApiError> {
    federation
        .connections
        .disable
        .execute(&tenant.caller, &tenant.auditor, path.connection())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/connections/{id}",
    tag = "Federation",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such connection", body = ErrorBody)
    )
)]
/// Delete a connection
///
/// Permanently removes a federation connection. Returns `404` if it does
/// not exist. Records `federation.connection_deleted`.
pub(crate) async fn delete_connection(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    Path(path): Path<ConnectionPath>,
) -> Result<NoContent, ApiError> {
    federation
        .connections
        .delete
        .execute(&tenant.caller, &tenant.auditor, path.connection())
        .await?;
    Ok(NoContent)
}

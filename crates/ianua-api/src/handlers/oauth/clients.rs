//! OAuth client handlers: registering, listing, changing, revoking a
//! tenant's clients and rotating their secrets, and a person seeing and
//! withdrawing the consent they gave apps.

use axum::extract::{Path, State};
use ianua_app::ports::oauth::OAuthClientSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::oauth::OAuthState;

use crate::dto::oauth::clients::{
    AuthorizedAppResponse, ClientFilterParams, ClientResponse, CreateClientBody,
    CreateClientResponse, RotateSecretBody, RotatedSecretResponse, UpdateClientBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::listing::ListingQuery;
use crate::extractors::pagination::PaginationParams;
use crate::extractors::paths::oauth::ClientPath;
use crate::extractors::sort::SortQuery;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/clients",
    tag = "OAuth",
    request_body = CreateClientBody,
    responses(
        (status = 201, description = "Created", body = CreateClientResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the plan's client limit is reached", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Register an OAuth client
///
/// Creates an `Active` tenant OAuth2 client with a `name`, allowed `redirect_uris`
/// (HTTPS, native-app loopback or private-use scheme), `post_logout_redirect_uris`,
/// the `grant_types` it may use (`AuthorizationCode`, `ClientCredentials`,
/// `RefreshToken`, `DeviceCode`, `TokenExchange`), its `scopes`, and how it
/// proves itself (`token_endpoint_auth_method`: `client_secret_basic` by
/// default, `client_secret_post`, `private_key_jwt` with `jwks` or
/// `jwks_uri`, `tls_client_auth` with `tls_client_auth_subject_dn`, or
/// `none` for a public client). `settings` sets token lifetimes, the
/// consent page's links, first-party consent, JWT access tokens, sign-out
/// channels and token binding.
///
/// Generates `client_id` and, where used, `client_secret`, shown once and kept hashed.
/// Checked against the tenant plan's OAuth client
/// limit. Records `oauth.client_created`.
pub(crate) async fn create_client(
    State(oauth): State<OAuthState>,
    tenant: TenantCaller,
    Json(body): Json<CreateClientBody>,
) -> Result<Created<CreateClientResponse>, ApiError> {
    let result = oauth
        .clients
        .create
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(CreateClientResponse::from(result)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/clients",
    tag = "OAuth",
    params(ClientFilterParams, SortQuery<OAuthClientSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<ClientResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List OAuth clients
///
/// Returns this tenant's OAuth clients, optionally filtered by `status`
/// (`Active` / `Revoked`), sortable and paginated. Each entry carries what
/// the client is registered with; the client secret is never included.
/// Records nothing.
pub(crate) async fn list_clients(
    State(oauth): State<OAuthState>,
    tenant: TenantCaller,
    ListingQuery {
        query: filter,
        sort,
        page: pagination,
    }: ListingQuery<ClientFilterParams, OAuthClientSortField>,
) -> Result<Json<PageResponse<ClientResponse>>, ApiError> {
    let page = oauth
        .clients
        .list
        .execute(&tenant.caller, filter.listing(sort, pagination))
        .await?;
    Ok(Json(PageResponse::from_page(page, ClientResponse::from)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/clients/{id}",
    tag = "OAuth",
    responses(
        (status = 200, description = "Success", body = ClientResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such client", body = ErrorBody)
    )
)]
/// Get an OAuth client
///
/// Returns a single client by `id`, with everything it is registered with
/// but its secret. Returns `404` if the client does not exist under this
/// tenant. Records nothing.
pub(crate) async fn get_client(
    State(oauth): State<OAuthState>,
    tenant: TenantCaller,
    Path(path): Path<ClientPath>,
) -> Result<Json<ClientResponse>, ApiError> {
    let client = oauth
        .clients
        .get
        .execute(&tenant.caller, path.client())
        .await?;
    Ok(Json(ClientResponse::from(client)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/clients/{id}",
    tag = "OAuth",
    request_body = UpdateClientBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such client", body = ErrorBody),
        (status = 409, description = "The client is revoked", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Update an OAuth client
///
/// Partial update: send `name`, `redirect_uris`,
/// `post_logout_redirect_uris`, `scopes` and any of `settings` to change
/// just those; omit any to leave it. The three page links, and the two
/// sign-out channels, are each replaced together when one of them is sent.
/// This does not change `status` (use revoke) or the secret (use
/// rotate-secret). Returns `404` if the client does not exist. Records
/// `oauth.client_updated`.
pub(crate) async fn update_client(
    State(oauth): State<OAuthState>,
    tenant: TenantCaller,
    Path(path): Path<ClientPath>,
    Json(body): Json<UpdateClientBody>,
) -> Result<NoContent, ApiError> {
    oauth
        .clients
        .update
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.change_of(path.client())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/clients/{id}/rotate-secret",
    tag = "OAuth",
    request_body = RotateSecretBody,
    responses(
        (status = 200, description = "The new secret, shown once", body = RotatedSecretResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such client", body = ErrorBody),
        (status = 409, description = "The client is revoked, or holds no secret", body = ErrorBody),
        (status = 422, description = "The overlap is longer than thirty days", body = ErrorBody)
    )
)]
/// Rotate an OAuth client's secret
///
/// Replaces the client's secret with a new one, returned once. The old
/// secret keeps working for `overlap_seconds` (at most thirty days), so
/// the app's servers can move to the new one without an outage; `0` or
/// left out ends it at once. Records `oauth.client_secret_rotated`.
pub(crate) async fn rotate_client_secret(
    State(oauth): State<OAuthState>,
    tenant: TenantCaller,
    Path(path): Path<ClientPath>,
    Json(body): Json<RotateSecretBody>,
) -> Result<Json<RotatedSecretResponse>, ApiError> {
    let secret = oauth
        .clients
        .rotate_secret
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.rotation_of(path.client())?,
        )
        .await?;
    Ok(Json(RotatedSecretResponse::from(secret)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/clients/{id}/revoke",
    tag = "OAuth",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such client", body = ErrorBody),
        (status = 409, description = "Already revoked", body = ErrorBody)
    )
)]
/// Revoke an OAuth client
///
/// Permanently revokes a client so it can no longer obtain tokens, and the
/// access tokens it holds stop resolving at once.
///
/// `Active -> Revoked` (terminal: a revoked client cannot be reactivated;
/// register a new one). Returns `404` if the client does not exist.
/// Records `oauth.client_revoked`.
pub(crate) async fn revoke_client(
    State(oauth): State<OAuthState>,
    tenant: TenantCaller,
    Path(path): Path<ClientPath>,
) -> Result<NoContent, ApiError> {
    oauth
        .clients
        .revoke
        .execute(&tenant.caller, &tenant.auditor, path.client())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/clients/{id}/consent",
    tag = "OAuth",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 404, description = "No such client, or no consent given to it", body = ErrorBody)
    )
)]
/// Withdraw my consent from an OAuth client
///
/// Withdraws every scope the signed-in person gave the client, and revokes
/// the access and refresh tokens it holds for them; its next authorization
/// request asks the person again. The `id` is the one "my apps" lists.
/// Returns `404` if the client does not exist or the person gave it no
/// consent. Records `oauth.consent_revoked`. Requires a tenant user's own
/// session.
pub(crate) async fn revoke_client_consent(
    State(oauth): State<OAuthState>,
    tenant: TenantCaller,
    Path(path): Path<ClientPath>,
) -> Result<NoContent, ApiError> {
    oauth
        .clients
        .revoke_consent
        .execute(&tenant.caller, &tenant.auditor, path.client())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/my-apps",
    tag = "OAuth",
    responses(
        (status = 200, description = "The apps the person authorized", body = Vec<AuthorizedAppResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody)
    )
)]
/// List the apps I authorized
///
/// The apps the signed-in person gave consent to, each with its name, its
/// page links, the scopes they gave and when. Withdraw one with `DELETE
/// .../oauth/clients/{id}/consent`. Records nothing. Requires a tenant
/// user's own session.
pub(crate) async fn list_my_apps(
    State(oauth): State<OAuthState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<AuthorizedAppResponse>>, ApiError> {
    let apps = oauth
        .clients
        .list_my_apps
        .execute(&tenant.caller, ())
        .await?;
    Ok(Json(
        apps.into_iter().map(AuthorizedAppResponse::from).collect(),
    ))
}

//! API key handlers: making, listing, changing and revoking a tenant's API
//! keys.

use axum::extract::{Path, State};
use ianua_app::ports::oauth::ApiKeySortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::oauth::api_keys::ListRequest;
use ianua_assembly::oauth::OAuthState;

use crate::dto::oauth::api_keys::{
    ApiKeyResponse, CreateApiKeyBody, CreateApiKeyResponse, UpdateApiKeyBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::oauth::{ApiKeyPath, OAuthTenantPath};
use crate::extractors::sort::SortQuery;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/api-keys",
    tag = "OAuth",
    request_body = CreateApiKeyBody,
    responses(
        (status = 201, description = "Created", body = CreateApiKeyResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the plan's key limit is reached", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Create an API key
///
/// Generates a new API key for this tenant under a display `name` with the
/// given `scopes`. The raw key is returned once; only its hash is stored,
/// so copy it immediately. With `expires_at` the key stops working at that
/// moment, signing in no one from then on, like a wrong key; without it the
/// key never ends. A key made with a key ends no later than that key.
/// Checked against the tenant plan's API key limit. Returns `422` for an
/// invalid name or an end that is not ahead of now. Records
/// `oauth.api_key_created`. Requires `ApiKeys(Create)`.
pub(crate) async fn create_api_key(
    State(oauth): State<OAuthState>,
    tenant: TenantCaller,
    Path(path): Path<OAuthTenantPath>,
    Json(body): Json<CreateApiKeyBody>,
) -> Result<Created<CreateApiKeyResponse>, ApiError> {
    let result = oauth
        .api_keys
        .create
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.request_in(path.tenant_slug()?)?,
        )
        .await?;
    Ok(Created(CreateApiKeyResponse::from(result)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/api-keys",
    tag = "OAuth",
    params(SortQuery<ApiKeySortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<ApiKeyResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List API keys
///
/// Returns this tenant's API keys, sortable and paginated. Each entry
/// carries the display `name`, `created_at`, and `last_used_at` and
/// `last_used_ip` (both `null` for a key never used); the raw key is never
/// included, and revoked keys are deleted rather than listed. Records
/// nothing. Requires `ApiKeys(View)`.
pub(crate) async fn list_api_keys(
    State(oauth): State<OAuthState>,
    tenant: TenantCaller,
    SortQuery(sort): SortQuery<ApiKeySortField>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<ApiKeyResponse>>, ApiError> {
    let page = oauth
        .api_keys
        .list
        .execute(
            &tenant.caller,
            ListRequest {
                sort,
                page: pagination,
            },
        )
        .await?;
    Ok(Json(PageResponse::from_page(page, ApiKeyResponse::from)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/api-keys/{id}",
    tag = "OAuth",
    responses(
        (status = 200, description = "Success", body = ApiKeyResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such key", body = ErrorBody)
    )
)]
/// Get an API key
///
/// Returns a single API key by `id`: its `name`, `created_at`, and when and
/// from which address it was last used (`last_used_at`, `last_used_ip`,
/// both `null` for a key never used), never the raw key. Returns `404` if the key does not exist under this tenant
/// (revoked keys are deleted). Records nothing. Requires `ApiKeys(View)`.
pub(crate) async fn get_api_key(
    State(oauth): State<OAuthState>,
    tenant: TenantCaller,
    Path(path): Path<ApiKeyPath>,
) -> Result<Json<ApiKeyResponse>, ApiError> {
    let key = oauth
        .api_keys
        .get
        .execute(&tenant.caller, path.api_key())
        .await?;
    Ok(Json(ApiKeyResponse::from(key)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/api-keys/{id}",
    tag = "OAuth",
    request_body = UpdateApiKeyBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such key", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Update an API key
///
/// Partial update: send `name` and/or `scopes` to change just those; omit
/// either to leave it. This edits metadata only: it does not rotate the
/// key. Returns `404` if the key does not exist. Records
/// `oauth.api_key_updated`. Requires `ApiKeys(Update)`.
pub(crate) async fn update_api_key(
    State(oauth): State<OAuthState>,
    tenant: TenantCaller,
    Path(path): Path<ApiKeyPath>,
    Json(body): Json<UpdateApiKeyBody>,
) -> Result<NoContent, ApiError> {
    oauth
        .api_keys
        .update
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.change_of(path.api_key())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/api-keys/{id}/revoke",
    tag = "OAuth",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such key", body = ErrorBody)
    )
)]
/// Revoke an API key
///
/// Permanently revokes an API key by deleting it, so it no longer
/// authenticates and no longer appears in the list. Returns `404` if the
/// key does not exist, including a second revoke of the same key. Records
/// `oauth.api_key_revoked`. Requires `ApiKeys(Revoke)`.
pub(crate) async fn revoke_api_key(
    State(oauth): State<OAuthState>,
    tenant: TenantCaller,
    Path(path): Path<ApiKeyPath>,
) -> Result<NoContent, ApiError> {
    oauth
        .api_keys
        .revoke
        .execute(&tenant.caller, &tenant.auditor, path.api_key())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/api-keys/{id}/pause",
    tag = "OAuth",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such key", body = ErrorBody),
        (status = 409, description = "The key is paused already", body = ErrorBody)
    )
)]
/// Pause an API key
///
/// Stops an API key signing in, at once, until it is resumed; nothing
/// about it is lost. `409` if it is paused already. Records
/// `oauth.api_key_paused`. Requires `ApiKeys(Revoke)`.
pub(crate) async fn pause_api_key(
    State(oauth): State<OAuthState>,
    tenant: TenantCaller,
    Path(path): Path<ApiKeyPath>,
) -> Result<NoContent, ApiError> {
    oauth
        .api_keys
        .pause
        .execute(&tenant.caller, &tenant.auditor, path.api_key())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/api-keys/{id}/resume",
    tag = "OAuth",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such key", body = ErrorBody),
        (status = 409, description = "The key is not paused", body = ErrorBody)
    )
)]
/// Resume an API key
///
/// Lets a paused API key sign in again. `409` if it is not paused.
/// Records `oauth.api_key_resumed`. Requires `ApiKeys(Update)` and every
/// permission the key carries, since resuming gives that access back.
pub(crate) async fn resume_api_key(
    State(oauth): State<OAuthState>,
    tenant: TenantCaller,
    Path(path): Path<ApiKeyPath>,
) -> Result<NoContent, ApiError> {
    oauth
        .api_keys
        .resume
        .execute(&tenant.caller, &tenant.auditor, path.api_key())
        .await?;
    Ok(NoContent)
}

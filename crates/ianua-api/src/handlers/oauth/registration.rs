//! Handlers of dynamic client registration: an app registering itself with
//! an initial access token (RFC 7591), then reading, replacing or deleting
//! its registration with its registration access token (RFC 7592), and an
//! admin issuing, listing and revoking initial access tokens.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::oauth::registration::managed::ManagingClient;
use ianua_app::use_cases::oauth::registration::{RegisterClientRequest, UpdateRequest};
use ianua_assembly::oauth::OAuthState;

use crate::dto::oauth::errors::OAuthErrorBody;
use crate::dto::oauth::registration::{
    InitialAccessTokenResponse, IssueInitialAccessTokenBody, IssuedInitialAccessTokenResponse,
    RegisteredClientResponse, RegistrationBody,
};
use crate::error::oauth::{BearerError, RegistrationError};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::oauth::bearer::{BearerToken, RegistrationBearer};
use crate::extractors::paths::oauth::{InitialAccessTokenPath, RegisteredClientPath};
use crate::extractors::public_tenant::PublicTenant;
use crate::response::{Created, NoContent};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/register",
    tag = "OAuth",
    request_body = RegistrationBody,
    responses(
        (status = 201, description = "Registered; the secret and registration access token are shown once", body = RegisteredClientResponse),
        (status = 400, description = "`invalid_redirect_uri` or `invalid_client_metadata`", body = OAuthErrorBody),
        (status = 401, description = "No initial access token, or one that is unknown, used up, expired or revoked", body = OAuthErrorBody),
        (status = 403, description = "The plan's client limit is reached, or the app asks for what only an admin may give", body = ErrorBody),
        (status = 404, description = "No such workspace", body = ErrorBody)
    )
)]
/// Register a client (dynamic registration)
///
/// RFC 7591: an app registers itself, sending an initial access token the
/// tenant handed out as `Authorization: Bearer` and its metadata in the
/// standard's names (`client_name`, `redirect_uris`, `grant_types`,
/// `scope`, `token_endpoint_auth_method`, `jwks`/`jwks_uri`, `logo_uri`,
/// sign-out channels, token binding). An app registering itself always
/// asks people for consent and may not use `client_credentials` or token
/// exchange. Answers its `client_id`, its `client_secret` when it proves
/// itself with one, and the `registration_access_token` and
/// `registration_client_uri` it manages its registration with; both
/// secrets are shown once. Spends one use of the initial access token.
/// Records `oauth.client_registered`.
pub(crate) async fn register_client(
    State(oauth): State<OAuthState>,
    tenant: PublicTenant,
    BearerToken(initial_access_token): BearerToken,
    Json(body): Json<RegistrationBody>,
) -> Result<Created<RegisteredClientResponse>, RegistrationError> {
    let request = RegisterClientRequest {
        initial_access_token,
        metadata: body.metadata()?,
    };
    let registered = oauth
        .registration
        .register
        .execute(&tenant.tenant, &tenant.auditor, request)
        .await?;
    let issuer = tenant.issuer(&oauth.app_base_url);
    Ok(Created(RegisteredClientResponse::registered(
        registered, &issuer,
    )))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/register/{client_id}",
    tag = "OAuth",
    responses(
        (status = 200, description = "The registration", body = RegisteredClientResponse),
        (status = 401, description = "No registration access token, or not this client's", body = OAuthErrorBody),
        (status = 404, description = "No such workspace", body = ErrorBody)
    )
)]
/// Read my registration
///
/// RFC 7592 2.1: an app that registered itself reads its registration,
/// sending its registration access token as `Authorization: Bearer`. The
/// secret is not shown again. A wrong token and an unknown client answer
/// the same `401`. Records nothing.
pub(crate) async fn read_registration(
    State(oauth): State<OAuthState>,
    tenant: PublicTenant,
    Path(path): Path<RegisteredClientPath>,
    BearerToken(registration_token): BearerToken,
) -> Result<Json<RegisteredClientResponse>, BearerError> {
    let managing = ManagingClient {
        client_id: path.client_id()?,
        registration_token,
    };
    let client = oauth
        .registration
        .read
        .execute(&tenant.tenant, managing)
        .await?;
    let issuer = tenant.issuer(&oauth.app_base_url);
    Ok(Json(RegisteredClientResponse::of(&client, &issuer)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/register/{client_id}",
    tag = "OAuth",
    request_body = RegistrationBody,
    responses(
        (status = 200, description = "The registration as it is now", body = RegisteredClientResponse),
        (status = 400, description = "`invalid_redirect_uri` or `invalid_client_metadata`", body = OAuthErrorBody),
        (status = 401, description = "No registration access token, or not this client's", body = OAuthErrorBody),
        (status = 403, description = "The app asks for what only an admin may give", body = ErrorBody),
        (status = 404, description = "No such workspace", body = ErrorBody)
    )
)]
/// Replace my registration
///
/// RFC 7592 2.2: an app replaces its registration's metadata: its name,
/// redirects, sign-out addresses, scopes, page links, sign-out channels and
/// token binding. What the body leaves out is cleared. Its grants and how
/// it proves itself stay as registered. Records `oauth.client_updated`.
pub(crate) async fn update_registration(
    State(oauth): State<OAuthState>,
    tenant: PublicTenant,
    RegistrationBearer {
        path,
        token: registration_token,
    }: RegistrationBearer,
    Json(body): Json<RegistrationBody>,
) -> Result<Json<RegisteredClientResponse>, RegistrationError> {
    let request = UpdateRequest {
        managing: ManagingClient {
            client_id: path.client_id().map_err(|e| e.0)?,
            registration_token,
        },
        changes: body.changes()?,
    };
    let client = oauth
        .registration
        .update
        .execute(&tenant.tenant, &tenant.auditor, request)
        .await?;
    let issuer = tenant.issuer(&oauth.app_base_url);
    Ok(Json(RegisteredClientResponse::of(&client, &issuer)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/register/{client_id}",
    tag = "OAuth",
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "No registration access token, or not this client's", body = OAuthErrorBody),
        (status = 404, description = "No such workspace", body = ErrorBody)
    )
)]
/// Delete my registration
///
/// RFC 7592 2.3: an app deletes its registration. It can no longer sign
/// anyone in or obtain tokens, and its registration access token stops
/// working. Records `oauth.client_revoked`.
pub(crate) async fn delete_registration(
    State(oauth): State<OAuthState>,
    tenant: PublicTenant,
    Path(path): Path<RegisteredClientPath>,
    BearerToken(registration_token): BearerToken,
) -> Result<NoContent, BearerError> {
    let managing = ManagingClient {
        client_id: path.client_id()?,
        registration_token,
    };
    oauth
        .registration
        .delete
        .execute(&tenant.tenant, &tenant.auditor, managing)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/initial-access-tokens",
    tag = "OAuth",
    request_body = IssueInitialAccessTokenBody,
    responses(
        (status = 201, description = "Issued; the token is shown once", body = IssuedInitialAccessTokenResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "No use or more than a thousand, or longer than thirty days", body = ErrorBody)
    )
)]
/// Issue an initial access token
///
/// A token that lets apps register themselves as clients, `uses` times
/// (1 to 1000, one by default) for `expires_in_seconds` (at most thirty
/// days). The raw token is returned once; only its hash is kept. Hand it
/// to whoever sets the app up. Records `oauth.initial_access_token_issued`.
pub(crate) async fn issue_initial_access_token(
    State(oauth): State<OAuthState>,
    tenant: TenantCaller,
    Json(body): Json<IssueInitialAccessTokenBody>,
) -> Result<Created<IssuedInitialAccessTokenResponse>, ApiError> {
    let issued = oauth
        .registration
        .issue_token
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(IssuedInitialAccessTokenResponse::from(issued)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/initial-access-tokens",
    tag = "OAuth",
    responses(
        (status = 200, description = "Every initial access token, without the tokens", body = Vec<InitialAccessTokenResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List initial access tokens
///
/// The tenant's initial access tokens, each with what it is for, the uses
/// it has left, when it expires and whether it was revoked; never the
/// token itself. Records nothing.
pub(crate) async fn list_initial_access_tokens(
    State(oauth): State<OAuthState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<InitialAccessTokenResponse>>, ApiError> {
    let tokens = oauth
        .registration
        .list_tokens
        .execute(&tenant.caller, ())
        .await?;
    Ok(Json(
        tokens
            .into_iter()
            .map(InitialAccessTokenResponse::from)
            .collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/initial-access-tokens/{id}/revoke",
    tag = "OAuth",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such token", body = ErrorBody)
    )
)]
/// Revoke an initial access token
///
/// No app registers with it any more; clients already registered with it
/// stay. Records `oauth.initial_access_token_revoked`.
pub(crate) async fn revoke_initial_access_token(
    State(oauth): State<OAuthState>,
    tenant: TenantCaller,
    Path(path): Path<InitialAccessTokenPath>,
) -> Result<NoContent, ApiError> {
    oauth
        .registration
        .revoke_token
        .execute(&tenant.caller, &tenant.auditor, path.token())
        .await?;
    Ok(NoContent)
}

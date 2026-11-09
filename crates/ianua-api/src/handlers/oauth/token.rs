//! Handlers of the token endpoint and the endpoints beside it that a
//! client proves itself to: introspection and revocation. Every answer and
//! refusal takes the protocol's own shape (RFC 6749 5).

use axum::extract::State;
use axum::http::StatusCode;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::oauth::OAuthState;

use crate::dto::oauth::errors::OAuthErrorBody;
use crate::dto::oauth::forms::{TokenAboutForm, TokenForm};
use crate::dto::oauth::tokens::{IntrospectionResponse, TokenResponse};
use crate::error::ErrorBody;
use crate::error::oauth::OAuthError;
use crate::extractors::json::Json;
use crate::extractors::oauth::token::TokenRequest;
use crate::extractors::oauth::tokens::{IntrospectionRequest, RevocationRequest};
use crate::extractors::public_tenant::PublicTenant;

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/token",
    tag = "OAuth",
    request_body(content = TokenForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "The tokens", body = TokenResponse),
        (status = 400, description = "`invalid_request`, `invalid_grant`, `unauthorized_client`, `unsupported_grant_type`, `invalid_scope`, `invalid_target`, `invalid_dpop_proof`, `authorization_pending`, `slow_down`, `access_denied` or `expired_token`", body = OAuthErrorBody),
        (status = 401, description = "`invalid_client`, with a `WWW-Authenticate` challenge", body = OAuthErrorBody),
        (status = 404, description = "No such workspace", body = ErrorBody)
    )
)]
/// Token endpoint
///
/// Public; accepts form or JSON. Clients use registered Basic/body secrets,
/// `private_key_jwt` assertions, or only `client_id` for public clients.
/// `grant_type` selects:
/// - `authorization_code`: one-use PKCE-bound `code`, `redirect_uri`, `code_verifier`.
/// - `refresh_token`: rotates `refresh_token`, optionally narrows `scope`; reuse ends its family.
/// - `client_credentials`: the client acts as itself with optional `scope`.
/// - `urn:ietf:params:oauth:grant-type:device_code`: `device_code`; polling can answer
///   `authorization_pending`, `slow_down`, `access_denied` or `expired_token`.
/// - `urn:ietf:params:oauth:grant-type:token-exchange`: access-token `subject_token`,
///   `subject_token_type`, client-id `audience`, optional `actor_token` and `scope`.
/// One valid `DPoP` header binds tokens to its key; invalid, duplicate or required-but-missing
/// proofs give `invalid_dpop_proof`. Required TLS binding gives `invalid_request`: no certificate arrives.
/// Returns `access_token`, `token_type` (`Bearer`/`DPoP`), `expires_in`, `scope`, and grant-dependent
/// `refresh_token`/`id_token` (`openid`). RFC 6749 errors use `400`, or `401` plus challenge for `invalid_client`; grant events are recorded.
pub(crate) async fn token(
    State(oauth): State<OAuthState>,
    tenant: PublicTenant,
    TokenRequest(grant): TokenRequest,
) -> Result<Json<TokenResponse>, OAuthError> {
    let issued = oauth
        .tokens
        .grants
        .issue(&tenant.tenant, &tenant.auditor, grant)
        .await?;
    Ok(Json(TokenResponse::from(issued)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/introspect",
    tag = "OAuth",
    request_body(content = TokenAboutForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "What the token says about itself", body = IntrospectionResponse),
        (status = 400, description = "`invalid_request`", body = OAuthErrorBody),
        (status = 401, description = "`invalid_client`, with a `WWW-Authenticate` challenge", body = OAuthErrorBody),
        (status = 404, description = "No such workspace", body = ErrorBody)
    )
)]
/// Introspect an access token
///
/// RFC 7662: a resource server, proving itself as a confidential client
/// (a public client is refused), asks what an access token says about
/// itself. A token that works answers `active: true` with its `scope`,
/// `client_id`, `sub`, `aud`, `iss`, `exp`, `iat`, `token_type`, what it is
/// bound to (`cnf`) and who acts for its subject (`act`). Anything else
/// (unknown, expired, revoked, its client or person gone) answers only
/// `active: false`. Records nothing.
pub(crate) async fn introspect(
    State(oauth): State<OAuthState>,
    tenant: PublicTenant,
    IntrospectionRequest(request): IntrospectionRequest,
) -> Result<Json<IntrospectionResponse>, OAuthError> {
    let issuer = request.issuer.clone();
    let result = oauth
        .tokens
        .introspect
        .execute(&tenant.tenant, request)
        .await?;
    Ok(Json(IntrospectionResponse::of(result, &issuer)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/revoke",
    tag = "OAuth",
    request_body(content = TokenAboutForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "Revoked, or nothing to revoke"),
        (status = 400, description = "`invalid_request`", body = OAuthErrorBody),
        (status = 401, description = "`invalid_client`, with a `WWW-Authenticate` challenge", body = OAuthErrorBody),
        (status = 404, description = "No such workspace", body = ErrorBody)
    )
)]
/// Revoke a token
///
/// RFC 7009: a client revokes an access or refresh token it holds, usually
/// on sign-out; `token_type_hint` (`access_token` or `refresh_token`) says
/// where to look first. Revoking a refresh token ends its family. The
/// answer is `200` whether or not the token was found, was already
/// revoked, or belongs to another client, so it tells nothing about
/// tokens; only a client that does not prove itself is refused. Records
/// the revocation when a token was revoked.
pub(crate) async fn revoke(
    State(oauth): State<OAuthState>,
    tenant: PublicTenant,
    RevocationRequest(request): RevocationRequest,
) -> Result<StatusCode, OAuthError> {
    oauth
        .tokens
        .revoke
        .execute(&tenant.tenant, &tenant.auditor, request)
        .await?;
    Ok(StatusCode::OK)
}

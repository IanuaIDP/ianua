//! Handlers of the flows that hand out codes and take people through them:
//! the browser's authorization request and the dashboard's consent step,
//! pushed requests, the device flow, signing out through an app,
//! `userinfo`, and the OIDC discovery document that names them all.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::oauth::OAuthState;

use crate::dto::oauth::browser::{
    AuthorizeBody, AuthorizeResponse, EndSessionBody, EndSessionResponse, PushedRequestResponse,
    logout_page, screened_reply,
};
use crate::dto::oauth::device::{DeviceAnswerBody, DeviceCodeResponse};
use crate::dto::oauth::errors::OAuthErrorBody;
use crate::dto::oauth::forms::{AccessTokenForm, DeviceCodeForm, PushedRequestForm};
use crate::dto::oauth::provider::OidcDiscoveryDocument;
use crate::dto::oauth::tokens::UserInfoResponse;
use crate::error::oauth::{BearerError, OAuthError};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::form::Form;
use crate::extractors::json::Json;
use crate::extractors::oauth::authorization::AuthorizationParams;
use crate::extractors::oauth::bearer::AccessTokenPresented;
use crate::extractors::oauth::device::DeviceCodeAsk;
use crate::extractors::oauth::logout::{LogoutParams, LogoutVisit};
use crate::extractors::oauth::pushed::PushedAuthorization;
use crate::extractors::paths::oauth::IssuerPath;
use crate::extractors::public_tenant::PublicTenant;
use crate::extractors::query::Query;
use crate::response::oauth::BrowserReply;
use crate::response::{Created, Found, NoContent};

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/authorize",
    tag = "OAuth",
    params(AuthorizationParams),
    responses(
        (status = 302, description = "To the dashboard's sign-in and consent page, or back to the client with an `error`"),
        (status = 200, description = "For `response_mode=form_post`, a page that posts the `error` to the client"),
        (status = 403, description = "The workspace is closed", body = ErrorBody),
        (status = 404, description = "No such workspace", body = ErrorBody),
        (status = 422, description = "The client is unknown, the redirect is missing, malformed or not one it registered, or the `request_uri` is not usable", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Start the authorization code flow in a browser
///
/// The OIDC-discovered authorization endpoint takes `response_type=code`, `client_id`,
/// `redirect_uri`, `scope`, `state`, an optional `nonce`, a PKCE
/// `code_challenge` with `code_challenge_method=S256`, and optionally
/// `prompt`, `max_age`, `acr_values`, `response_mode` (`query` or
/// `form_post`), `id_token_hint`, `login_hint` and `ui_locales`. A client
/// that pushed its request first sends only `client_id` and `request_uri`.
///
/// A valid request redirects (`302`) with its parameters to dashboard sign-in and consent, which posts to the
/// consent step on this path. When the client is unknown or the redirect
/// is not one it registered, the browser is answered `422` and nothing is
/// sent to the redirect. Any other fault goes back to the redirect with
/// `error` (`unsupported_response_type`, `invalid_request`,
/// `unauthorized_client`, `invalid_scope`), the client's `state`, and
/// `iss`. Public, limited per address. Records nothing.
pub(crate) async fn browser_authorize(
    State(oauth): State<OAuthState>,
    tenant: PublicTenant,
    Query(params): Query<AuthorizationParams>,
) -> Result<BrowserReply, ApiError> {
    let answer = oauth
        .browser
        .screen
        .execute(&tenant.tenant, params.ask()?)
        .await?;
    screened_reply(answer, &params, &tenant, &oauth.app_base_url)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/authorize",
    tag = "OAuth",
    request_body = AuthorizeBody,
    responses(
        (status = 200, description = "What the step came to: a code, sign in first, ask for consent, or a refusal for the client", body = AuthorizeResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "The redirect is not one the client registered", body = ErrorBody),
        (status = 404, description = "No such client", body = ErrorBody),
        (status = 422, description = "The request is malformed, or its `request_uri` expired or was used", body = ErrorBody)
    )
)]
/// The consent step of the authorization code flow
///
/// The dashboard's sign-in and consent page posts the authorization request
/// the browser brought (every parameter as it came, or `client_id` and
/// `request_uri`) with the signed-in person's `consent`: `not_asked_yet`
/// to learn what to show, or `given` (the default) once they agreed.
///
/// The `outcome` is `issued` (with the `code`, `consent_granted`, and where
/// to send the browser: `redirect_to`, or a `form_post` for a client that
/// asked for one), `sign_in` (sign the person in again, or as someone else,
/// as `prompt`, `max_age`, `acr_values` or `id_token_hint` ask), `consent`
/// (ask about `scopes`), or `refused` (the `error`, sent to the client the
/// same way). Records `oauth.consent_granted` when the person agreed to
/// something new, then `oauth.authorization_code_issued`. Requires a tenant
/// user's own session.
pub(crate) async fn authorize(
    State(oauth): State<OAuthState>,
    tenant: TenantCaller,
    Path(path): Path<IssuerPath>,
    Json(body): Json<AuthorizeBody>,
) -> Result<Json<AuthorizeResponse>, ApiError> {
    let issuer = path.issuer(&oauth.app_base_url)?;
    let outcome = oauth
        .browser
        .authorize
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.request(issuer.clone())?,
        )
        .await?;
    Ok(Json(AuthorizeResponse::of(outcome, &issuer)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/par",
    tag = "OAuth",
    request_body(content = PushedRequestForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 201, description = "Pushed; send the browser on with the `request_uri`", body = PushedRequestResponse),
        (status = 400, description = "`invalid_request`, `unauthorized_client`, `unsupported_response_type` or `invalid_scope`", body = OAuthErrorBody),
        (status = 401, description = "`invalid_client`, with a `WWW-Authenticate` challenge", body = OAuthErrorBody),
        (status = 404, description = "No such workspace", body = ErrorBody)
    )
)]
/// Push an authorization request
///
/// RFC 9126: the client sends its authorization request here first,
/// proving itself as at the token endpoint, so the parameters never pass
/// through the browser. The request is screened as the browser's would be.
/// Answers a `request_uri`, usable once, for sixty seconds, and only with
/// this client's `client_id`, to send the browser to the authorization
/// endpoint with. Records `oauth.authorization_request_pushed`.
pub(crate) async fn push_authorization_request(
    State(oauth): State<OAuthState>,
    tenant: PublicTenant,
    PushedAuthorization(request): PushedAuthorization,
) -> Result<Created<PushedRequestResponse>, OAuthError> {
    let pushed = oauth
        .browser
        .push
        .execute(&tenant.tenant, &tenant.auditor, request)
        .await?;
    Ok(Created(PushedRequestResponse::from(pushed)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/logout",
    tag = "OAuth",
    params(LogoutParams),
    responses(
        (status = 302, description = "To the dashboard's sign-out page, carrying the request"),
        (status = 403, description = "The workspace is closed", body = ErrorBody),
        (status = 404, description = "No such workspace", body = ErrorBody)
    )
)]
/// Sign out through an app
///
/// The end session endpoint the OIDC discovery document names
/// (RP-Initiated Logout). An app sends the browser here with an optional
/// `id_token_hint`, `client_id`, `post_logout_redirect_uri` (one it
/// registered) and `state`. The browser is sent on to the dashboard's
/// sign-out page, carrying the request, which ends the session with
/// `POST .../oauth/end-session`. Records nothing.
pub(crate) async fn browser_logout(
    State(oauth): State<OAuthState>,
    tenant: PublicTenant,
    Query(params): Query<LogoutParams>,
) -> Found {
    Found(logout_page(&params, &tenant, &oauth.app_base_url))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/logout",
    tag = "OAuth",
    request_body(content = LogoutParams, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 302, description = "To the dashboard's sign-out page, carrying the request"),
        (status = 403, description = "The workspace is closed", body = ErrorBody),
        (status = 404, description = "No such workspace", body = ErrorBody)
    )
)]
/// Sign out through an app, by form
///
/// The same as the `GET`, for an app that posts its sign-out request as a
/// form, as RP-Initiated Logout allows. Records nothing.
pub(crate) async fn browser_logout_by_form(
    State(oauth): State<OAuthState>,
    tenant: PublicTenant,
    Form(params): Form<LogoutParams>,
) -> Found {
    Found(logout_page(&params, &tenant, &oauth.app_base_url))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/end-session",
    tag = "OAuth",
    request_body = EndSessionBody,
    responses(
        (status = 200, description = "What the sign-out came to, and where the person goes", body = EndSessionResponse),
        (status = 403, description = "The `id_token_hint` was issued to another app, or the session is another plane's", body = ErrorBody),
        (status = 404, description = "No such workspace", body = ErrorBody),
        (status = 422, description = "The `id_token_hint` was not signed by this tenant, or a parameter is malformed", body = ErrorBody)
    )
)]
/// End the session an app asked to end
///
/// The dashboard's sign-out page posts the app's request, with the
/// person's session as bearer if they hold one. When the app named them
/// with an `id_token_hint`, or they `confirmed`, the session ends: its
/// refresh tokens are revoked and the apps it signed in to are told
/// (`front_channel_logout_uris` to load in hidden frames; the back channel
/// is told by the worker). Otherwise the `outcome` is `confirm`, or
/// `not_signed_in` when no session is held here. `redirect_to` is the
/// app's registered address with its `state`, or none for the dashboard's
/// own signed-out page. Records `session.revoked` when the session ends.
pub(crate) async fn end_session(
    State(oauth): State<OAuthState>,
    visit: LogoutVisit,
    Json(body): Json<EndSessionBody>,
) -> Result<Json<EndSessionResponse>, ApiError> {
    let request = body.request_of(visit.issuer)?;
    let outcome = oauth
        .browser
        .end_session
        .execute(&visit.browser, &visit.auditor, request)
        .await?;
    Ok(Json(EndSessionResponse::of(
        outcome,
        body.request.state.as_deref(),
    )))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/device/code",
    tag = "OAuth",
    request_body(content = DeviceCodeForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "The codes", body = DeviceCodeResponse),
        (status = 400, description = "`invalid_request`, `unauthorized_client` or `invalid_scope`", body = OAuthErrorBody),
        (status = 401, description = "`invalid_client`, with a `WWW-Authenticate` challenge", body = OAuthErrorBody),
        (status = 404, description = "No such workspace", body = ErrorBody)
    )
)]
/// Start the device authorization flow
///
/// RFC 8628 3.1: the device endpoint the discovery document names. The
/// device's client proves itself as at the token endpoint (only its
/// `client_id` for a public client) and asks for a `scope`. Answers a
/// `device_code` (the device polls the token endpoint with it), a
/// `user_code`, the `verification_uri` the person visits to type it, the
/// same with the code filled in (`verification_uri_complete`), the polling
/// `interval` and `expires_in`. Records
/// `oauth.device_authorization_requested`.
pub(crate) async fn request_device_code(
    State(oauth): State<OAuthState>,
    tenant: PublicTenant,
    DeviceCodeAsk(request): DeviceCodeAsk,
) -> Result<Json<DeviceCodeResponse>, OAuthError> {
    let result = oauth
        .device
        .request_code
        .execute(&tenant.tenant, &tenant.auditor, request)
        .await?;
    Ok(Json(DeviceCodeResponse::from(result)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/device/approve",
    tag = "OAuth",
    request_body = DeviceAnswerBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 404, description = "No request shows that code", body = ErrorBody),
        (status = 422, description = "The request expired or was answered", body = ErrorBody)
    )
)]
/// Approve a device authorization
///
/// The signed-in person enters the `user_code` shown on the device to
/// approve the request, binding it to their account. The device's next
/// poll at the token endpoint collects its tokens. Returns `404` if the
/// `user_code` is unknown, or `422` if the request expired or was already
/// answered. Records `oauth.device_authorization_approved`. Requires a
/// tenant user's own session.
pub(crate) async fn approve_device(
    State(oauth): State<OAuthState>,
    tenant: TenantCaller,
    Json(body): Json<DeviceAnswerBody>,
) -> Result<NoContent, ApiError> {
    oauth
        .device
        .approve
        .execute(&tenant.caller, &tenant.auditor, body.user_code()?)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/device/deny",
    tag = "OAuth",
    request_body = DeviceAnswerBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 404, description = "No request shows that code", body = ErrorBody),
        (status = 422, description = "The request expired or was answered", body = ErrorBody)
    )
)]
/// Deny a device authorization
///
/// The signed-in person refuses the request whose `user_code` the device
/// shows: they did not start the sign-in there, or no longer want it. The
/// device's next poll is answered `access_denied`. Returns `404` if the
/// `user_code` is unknown, or `422` if the request expired or was already
/// answered. Records `oauth.device_authorization_denied`. Requires a tenant
/// user's own session.
pub(crate) async fn deny_device(
    State(oauth): State<OAuthState>,
    tenant: TenantCaller,
    Json(body): Json<DeviceAnswerBody>,
) -> Result<NoContent, ApiError> {
    oauth
        .device
        .deny
        .execute(&tenant.caller, &tenant.auditor, body.user_code()?)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/userinfo",
    tag = "OIDC Provider",
    responses(
        (status = 200, description = "The claims the token's scopes let out", body = UserInfoResponse),
        (status = 401, description = "No access token, or one that does not work, with a `WWW-Authenticate` challenge", body = OAuthErrorBody),
        (status = 403, description = "`insufficient_scope`: a token without `openid`, or one for a machine", body = OAuthErrorBody),
        (status = 404, description = "No such workspace", body = ErrorBody)
    )
)]
/// Userinfo
///
/// OIDC Core 5.3: an app sends the access token it was handed as
/// `Authorization: Bearer` and learns about the person it acts for what
/// the token's scopes let out, as the ID token does: `sub` always,
/// `email` and `email_verified` with `email`, `name`, `locale` and
/// `zoneinfo` with `profile`, and `roles` with `roles`. Only a token with
/// `openid` acting for a person is answered. A `DPoP`-bound token comes as
/// `Authorization: DPoP` with a `DPoP` proof for this request naming it
/// (RFC 9449 7); presented any other way, or with a proof that does not
/// check out, it is refused `401`. Records nothing.
pub(crate) async fn userinfo(
    State(oauth): State<OAuthState>,
    tenant: PublicTenant,
    AccessTokenPresented(presented): AccessTokenPresented,
) -> Result<Json<UserInfoResponse>, BearerError> {
    let claims = oauth
        .tokens
        .userinfo
        .execute(&tenant.tenant, presented)
        .await?;
    Ok(Json(UserInfoResponse::from(claims)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/oauth/userinfo",
    tag = "OIDC Provider",
    request_body(content = AccessTokenForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "The claims the token's scopes let out", body = UserInfoResponse),
        (status = 401, description = "No access token, or one that does not work, with a `WWW-Authenticate` challenge", body = OAuthErrorBody),
        (status = 403, description = "`insufficient_scope`: a token without `openid`, or one for a machine", body = OAuthErrorBody),
        (status = 404, description = "No such workspace", body = ErrorBody)
    )
)]
/// Userinfo, by `POST`
///
/// The same as the `GET`, for an app that posts: the token in the
/// `Authorization` header, or as `access_token` in a form body (RFC 6750
/// 2.2). Records nothing.
pub(crate) async fn userinfo_by_post(
    State(oauth): State<OAuthState>,
    tenant: PublicTenant,
    AccessTokenPresented(presented): AccessTokenPresented,
) -> Result<Json<UserInfoResponse>, BearerError> {
    let claims = oauth
        .tokens
        .userinfo
        .execute(&tenant.tenant, presented)
        .await?;
    Ok(Json(UserInfoResponse::from(claims)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/.well-known/openid-configuration",
    tag = "OIDC Provider",
    responses(
        (status = 200, description = "Discovery document", body = OidcDiscoveryDocument),
        (status = 403, description = "The workspace is not available", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// OIDC discovery document
///
/// The standard OpenID discovery document, so relying parties configure
/// themselves. Every URL is under this tenant's issuer: the authorization,
/// token, `userinfo`, pushed request, device, introspection, revocation,
/// end session and registration endpoints, and the JWKS document. It names
/// the grants, response modes, prompts, `acr` values, claims, signing
/// algorithms and client authentication methods offered, PKCE with
/// `S256`, the `iss` in authorization answers, and back- and front-channel
/// logout. Public. Records nothing.
pub(crate) async fn discovery(
    State(oauth): State<OAuthState>,
    tenant: PublicTenant,
) -> Json<OidcDiscoveryDocument> {
    Json(OidcDiscoveryDocument::from(
        &tenant.issuer(&oauth.app_base_url),
    ))
}

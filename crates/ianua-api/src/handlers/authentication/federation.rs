//! Single sign-on handlers: sending the browser to a tenant's identity
//! provider, taking its answer back, and swapping the one-time code for a
//! session.

use axum::extract::{Path, State};
use ianua_app::use_case::Command as _;
use ianua_app::use_cases::authentication::federation::BeginSingleSignOnRequest;
use ianua_assembly::authentication::AuthenticationState;

use crate::dto::authentication::federation::{
    OidcCallbackQuery, SamlAcsForm, SsoBeginQuery, SsoExchangeBody, SsoExchangeResponse,
};
use crate::dto::authentication::single_sign_on::{BackToDashboard, ToIdentityProvider};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::authentication::{SignInVisitor, SsoBrowser};
use crate::extractors::form::Form;
use crate::extractors::json::Json;
use crate::extractors::paths::authentication::SsoConnectionPath;
use crate::extractors::query::Query;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/connections/{id}/login",
    tag = "Federation",
    params(SsoBeginQuery),
    responses(
        (status = 303, description = "Redirect to the identity provider"),
        (status = 403, description = "The connection is off, or the tenant does not take its protocol", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "No state, or one too short", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Begin single sign-on
///
/// Public (no session). The "Sign in with ..." button links here. Sends the
/// browser (`303`) to the connection's identity provider, OIDC or SAML, and
/// hands it a short-lived `ianua_sso` cookie: only the browser holding it
/// may finish the sign-in. `state` is a random value the dashboard keeps
/// and sends again with the one-time code, so only this dashboard can swap
/// it.
///
/// `404` if the connection doesn't exist; `403` if it is disabled or the
/// tenant does not accept its protocol.
pub(crate) async fn begin_single_sign_on(
    State(auth): State<AuthenticationState>,
    browser: SsoBrowser,
    Path(path): Path<SsoConnectionPath>,
    Query(query): Query<SsoBeginQuery>,
) -> Result<ToIdentityProvider, ApiError> {
    let SsoBrowser {
        visitor, way_back, ..
    } = browser;
    let request = BeginSingleSignOnRequest {
        connection_id: path.connection(),
        returns_to: way_back.returns_to(),
        origin: visitor.origin,
        dashboard_state: query.dashboard_state()?,
    };
    let start = auth
        .federation
        .begin
        .execute(&visitor.tenant, &visitor.auditor, request)
        .await?;
    Ok(ToIdentityProvider::new(&start, &way_back))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/oidc/callback",
    tag = "Federation",
    params(OidcCallbackQuery),
    responses(
        (status = 303, description = "Back to the dashboard"),
        (status = 404, description = "Unknown org/tenant", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// OIDC callback
///
/// Public endpoint the identity provider sends the browser back to. Checks
/// the `state` and the browser's `ianua_sso` cookie, exchanges the `code`,
/// and opens a session. Always answers `303` to the dashboard: to its
/// `/sso?code=...` page with a one-time code on success, or to the sign-in
/// page with `?sso=failed` otherwise. The session's token never appears in
/// an address.
pub(crate) async fn oidc_callback(
    State(auth): State<AuthenticationState>,
    browser: SsoBrowser,
    Query(query): Query<OidcCallbackQuery>,
) -> BackToDashboard {
    let SsoBrowser {
        visitor,
        binding,
        way_back,
    } = browser;
    let outcome = match query.login(binding, visitor.origin) {
        Ok(request) => {
            auth.federation
                .oidc_login
                .execute(&visitor.tenant, &visitor.auditor, request)
                .await
        }
        Err(refused) => Err(refused),
    };
    BackToDashboard::new(&way_back, outcome)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/saml/acs",
    tag = "Federation",
    request_body(content = SamlAcsForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 303, description = "Back to the dashboard"),
        (status = 404, description = "Unknown org/tenant", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// SAML assertion consumer service
///
/// Public endpoint the identity provider posts its answer to, as a form with
/// `SAMLResponse` and `RelayState`. Accepts only an answer to a request sent
/// from here, brought back by the browser holding its `ianua_sso` cookie.
/// Answers `303` to the dashboard like the OIDC callback.
pub(crate) async fn saml_acs(
    State(auth): State<AuthenticationState>,
    browser: SsoBrowser,
    Form(form): Form<SamlAcsForm>,
) -> BackToDashboard {
    let SsoBrowser {
        visitor,
        binding,
        way_back,
    } = browser;
    let service_provider = way_back.service_provider.clone();
    let outcome = match form.login(binding, service_provider, visitor.origin) {
        Ok(request) => {
            auth.federation
                .saml_login
                .execute(&visitor.tenant, &visitor.auditor, request)
                .await
        }
        Err(refused) => Err(refused),
    };
    BackToDashboard::new(&way_back, outcome)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/sso/exchange",
    tag = "Authentication",
    request_body = SsoExchangeBody,
    responses(
        (status = 200, description = "Signed in", body = SsoExchangeResponse),
        (status = 403, description = "Code unknown, used or lapsed, or swapped by another dashboard", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Finish single sign-on
///
/// After the identity provider vouches for someone, their browser is sent
/// back to the dashboard with a one-time code, never a token. The dashboard
/// posts the code here with the `state` it sent when it started the
/// sign-in, and gets the session. A code swapped with any other `state` is
/// refused, so a code sent to someone else's browser signs nobody in.
///
/// A code works once, for a short while, and only while the session it
/// stands for is still live. `403` otherwise.
///
/// The session still owes a second factor when the identity provider
/// reported none and the person has one here, or the tenant requires one:
/// `mfa_required` and `mfa_enrollment_required` say which, as after a
/// password sign-in.
pub(crate) async fn exchange_sign_in_code(
    State(auth): State<AuthenticationState>,
    visitor: SignInVisitor,
    Json(body): Json<SsoExchangeBody>,
) -> Result<Json<SsoExchangeResponse>, ApiError> {
    let exchanged = auth
        .federation
        .exchange
        .execute(&visitor.tenant, &visitor.auditor, body.into())
        .await?;
    Ok(Json(exchanged.into()))
}

//! Single sign-on to the dashboard: sending a member to their
//! organization's identity provider, and signing them in from its answer.

use axum::extract::State;
use ianua_app::use_case::Command as _;
use ianua_assembly::organization::OrganizationState;

use crate::dto::organization::sign_in::OrgLoginResponse;
use crate::dto::organization::sso::{OrgSsoCallbackBody, OrgSsoStartBody, OrgSsoStartResponse};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::json::Json;
use crate::extractors::organization::sign_in::SsoVisitor;

#[utoipa::path(
    post,
    path = "/api/v1/login/sso",
    tag = "Authentication",
    request_body = OrgSsoStartBody,
    responses(
        (status = 200, description = "Where to send the browser", body = OrgSsoStartResponse),
        (status = 403, description = "Single sign-on is not available for this organization from here", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Start a single sign-on
///
/// Begins a member's dashboard sign-in through their organization's
/// identity provider. Send the `organization` slug, and `tenant_slug` to
/// land in a tenant other than the first the member reaches. The answer
/// names the provider's page to send the browser to, and a `binding`
/// secret: keep it for the length of the sign-in and send it with the
/// provider's answer to `…/login/sso/callback`. Only the browser holding it
/// finishes the sign-in.
///
/// The provider answers to the dashboard: an OIDC provider redirects to
/// `/login/sso/oidc`, a SAML provider posts to `/login/sso/saml`. An
/// unknown organization, one with no provider, a provider switched off and
/// a protocol the organization does not take from here all answer the same
/// `403`. Records `organization.org_sso_sign_in_started`. Public.
pub(crate) async fn start(
    State(organization): State<OrganizationState>,
    visitor: SsoVisitor,
    Json(body): Json<OrgSsoStartBody>,
) -> Result<Json<OrgSsoStartResponse>, ApiError> {
    let request = body.into_request(visitor.returns_to, visitor.origin)?;
    let started = organization
        .sign_in
        .sso_start
        .execute(&(), &visitor.auditor, request)
        .await?;
    Ok(Json(OrgSsoStartResponse::from(started)))
}

#[utoipa::path(
    post,
    path = "/api/v1/login/sso/callback",
    tag = "Authentication",
    request_body = OrgSsoCallbackBody,
    responses(
        (status = 200, description = "Signed in", body = OrgLoginResponse),
        (status = 403, description = "The answer is not one this browser's sign-in awaits, or does not prove a member", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Finish a single sign-on
///
/// The dashboard hands on what the identity provider sent the browser back
/// with: `{"protocol": "oidc", "state", "code"}` from a redirect, or
/// `{"protocol": "saml", "relay_state", "saml_response"}` from a posted
/// form, with the `binding` the start handed this browser. The answer is
/// checked, the member it proves is found, and their session opens as a
/// password sign-in's does; the session's token comes back here, never in
/// an address.
///
/// Every step refuses by default with `403`: an answer to no sign-in
/// started here, one brought back by another browser, one from a provider
/// switched off or replaced since, a forged or replayed assertion, and an
/// address that is no member's or that the provider did not prove. Nobody
/// becomes a member by signing in. Records
/// `organization.org_login_succeeded`. Public.
pub(crate) async fn callback(
    State(organization): State<OrganizationState>,
    visitor: SsoVisitor,
    Json(body): Json<OrgSsoCallbackBody>,
) -> Result<Json<OrgLoginResponse>, ApiError> {
    let request = body.into_request(visitor.returns_to.service_provider, visitor.origin)?;
    let success = organization
        .sign_in
        .sso_callback
        .execute(&(), &visitor.auditor, request)
        .await?;
    Ok(Json(OrgLoginResponse::from(success)))
}

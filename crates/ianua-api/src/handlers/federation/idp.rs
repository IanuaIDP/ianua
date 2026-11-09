//! Identity provider handlers: the tenant answering its SAML apps. The
//! metadata an app reads to trust the tenant, the single sign-on service
//! apps send people to, and the answers the dashboard asks for once the
//! person is signed in.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::federation::idp::{BuildSamlResponseRequest, SamlSignInTrigger};
use ianua_assembly::federation::FederationState;

use crate::dto::federation::idp::SamlMetadata;
use crate::dto::federation::messages::{InitiateQuery, SamlForm, SamlFormPost, SsoAnswerBody};
use crate::dto::federation::site::FederationSite;
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::federation::{PostedSamlMessage, RedirectedSamlMessage, SsoAnswer};
use crate::extractors::json::Json;
use crate::extractors::paths::federation::SamlAppPath;
use crate::extractors::public_tenant::PublicTenant;
use crate::extractors::query::Query;
use crate::response::Found;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/saml/metadata",
    tag = "SAML IdP",
    responses(
        (status = 200, description = "IdP SAML metadata XML", content_type = "application/xml", body = String),
        (status = 403, description = "The workspace is not available", body = ErrorBody),
        (status = 404, description = "No such tenant, or no signing keys", body = ErrorBody)
    )
)]
/// SAML IdP metadata
///
/// Serves the tenant's SAML identity provider metadata (XML) that service
/// providers fetch to configure trust: the entity id (this tenant's
/// issuer), the single sign-on and single logout endpoints, the `NameID`
/// formats offered, and a certificate over the tenant's signing key.
/// Public: no authentication. Returns `404` if the tenant has no signing
/// key set yet. Records nothing.
pub(crate) async fn idp_metadata(
    State(federation): State<FederationState>,
    tenant: PublicTenant,
    site: FederationSite,
) -> Result<SamlMetadata, ApiError> {
    let xml = federation
        .idp
        .metadata
        .execute(&tenant.tenant, site.identity_provider()?)
        .await?;
    Ok(SamlMetadata::identity_provider(xml))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/saml/sso",
    tag = "SAML IdP",
    params(
        ("SAMLRequest" = String, Query, description = "The app's sign-in request, deflated and base64-encoded"),
        ("RelayState" = Option<String>, Query, description = "What the app wants back with the answer"),
        ("SigAlg" = Option<String>, Query, description = "The signature algorithm, when the app signs"),
        ("Signature" = Option<String>, Query, description = "The signature over the query, when the app signs")
    ),
    responses(
        (status = 302, description = "On to the dashboard's sign-in page for the app"),
        (status = 403, description = "The workspace is not available", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "The query carries no request, or half a signature", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// SAML single sign-on, HTTP-Redirect binding
///
/// Where an app sends a person's browser with its sign-in request, as the
/// tenant's identity provider metadata names. The request is held on the
/// server with when it arrived, and the browser is sent on (`302`) to the
/// dashboard's `.../saml/sso` page with `binding=redirect`, the query
/// exactly as it arrived (`query`) and the id it is held by (`request`).
/// The page signs the person in if needed and posts `request` to
/// `.../saml/sso/answer` within ten minutes. Public, limited per address.
/// Records nothing.
pub(crate) async fn sso_redirect(
    State(federation): State<FederationState>,
    tenant: PublicTenant,
    site: FederationSite,
    message: RedirectedSamlMessage,
) -> Result<Found, ApiError> {
    let held = federation
        .idp
        .receive
        .execute(&tenant.tenant, &tenant.auditor, message.arrived.try_into()?)
        .await?;
    let query = message.body.sign_in_bounce_query(&held);
    Ok(Found(site.dashboard_page("/saml/sso", &query)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/saml/sso",
    tag = "SAML IdP",
    request_body(content = SamlForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 302, description = "On to the dashboard's sign-in page for the app"),
        (status = 403, description = "The workspace is not available", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "The form carries no request", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// SAML single sign-on, HTTP-POST binding
///
/// Where an app posts a person's browser with its sign-in request in a
/// form (`SAMLRequest`, `RelayState`). The request is held on the server
/// with when it arrived, and the browser is sent on (`302`) to the
/// dashboard's `.../saml/sso` page with `binding=post`, the `message`, the
/// `relay_state` and `request`, as for the redirect binding. Public,
/// limited per address. Records nothing.
pub(crate) async fn sso_post(
    State(federation): State<FederationState>,
    tenant: PublicTenant,
    site: FederationSite,
    message: PostedSamlMessage,
) -> Result<Found, ApiError> {
    let held = federation
        .idp
        .receive
        .execute(&tenant.tenant, &tenant.auditor, message.arrived.try_into()?)
        .await?;
    let query = message.body.sign_in_bounce_query(&held);
    Ok(Found(site.dashboard_page("/saml/sso", &query)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/saml/sso/initiate",
    tag = "SAML IdP",
    params(InitiateQuery),
    responses(
        (status = 302, description = "On to the dashboard's page signing the person in to the app"),
        (status = 403, description = "The workspace is not available", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Start a sign-in to a SAML app here
///
/// A link that signs a person in to one of the tenant's apps without the
/// app asking first, such as an app tile. The browser is sent on (`302`) to
/// the dashboard's `.../saml/apps/{app_id}/sign-in` page, which signs the
/// person in if needed and asks `POST .../saml/apps/{app_id}/sign-in`.
/// Public, limited per address. Records nothing.
pub(crate) async fn sso_initiate(
    _tenant: PublicTenant,
    site: FederationSite,
    Query(query): Query<InitiateQuery>,
) -> Found {
    Found(site.dashboard_page(&query.sign_in_page(), ""))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/saml/sso/answer",
    tag = "SAML IdP",
    request_body = SsoAnswerBody,
    responses(
        (status = 200, description = "The answer, for the browser to post to the app", body = SamlFormPost),
        (status = 401, description = "No session of the person's own, or the app asked for a fresh sign-in", body = ErrorBody),
        (status = 403, description = "No app of the tenant sent it, the app is off, or its signature or address does not hold", body = ErrorBody),
        (status = 404, description = "No signing key set", body = ErrorBody),
        (status = 409, description = "The app names people by address and the person's is not verified", body = ErrorBody),
        (status = 410, description = "No request is held under that id: unknown, answered already, or more than ten minutes old", body = ErrorBody),
        (status = 422, description = "The body names no request id, the request is malformed, or asks for another NameID format", body = ErrorBody)
    )
)]
/// Answer an app's sign-in request
///
/// The dashboard's `.../saml/sso` page, with the person signed in, posts
/// the id the app's request is held by, as it received it: `request`. The
/// request and when it arrived are read from the server, so an app that
/// asked for a fresh sign-in is answered only for a sign-in made after its
/// request arrived. A request is answered once. The answer is the signed
/// SAML response and where to post it: the page builds a form posting
/// `message` as `parameter` (with `RelayState` when there is one) to
/// `destination`. Requires a tenant user's own session. Records
/// `federation.saml_assertion_issued`.
pub(crate) async fn answer_sign_in(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    site: FederationSite,
    SsoAnswer(trigger): SsoAnswer,
) -> Result<Json<SamlFormPost>, ApiError> {
    let request = BuildSamlResponseRequest {
        issuer: site.idp_entity_id()?,
        trigger,
        lifetime: federation.idp.assertion_lifetime,
    };
    let output = federation
        .idp
        .answer
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Json(SamlFormPost::sign_in(output)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/saml/apps/{app_id}/sign-in",
    tag = "SAML IdP",
    responses(
        (status = 200, description = "The answer, for the browser to post to the app", body = SamlFormPost),
        (status = 401, description = "No session of the person's own", body = ErrorBody),
        (status = 403, description = "The app is switched off", body = ErrorBody),
        (status = 404, description = "No such app, or no signing key set", body = ErrorBody),
        (status = 409, description = "The app names people by address and the person's is not verified", body = ErrorBody)
    )
)]
/// Sign in to a SAML app
///
/// A sign-in started here, such as from an app tile: the signed SAML
/// response for the signed-in person, to the app's default address, for
/// the browser to post as `parameter` to `destination`. Requires a tenant
/// user's own session. Records `federation.saml_assertion_issued`.
pub(crate) async fn sign_in_to_app(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    site: FederationSite,
    Path(path): Path<SamlAppPath>,
) -> Result<Json<SamlFormPost>, ApiError> {
    let request = BuildSamlResponseRequest {
        issuer: site.idp_entity_id()?,
        trigger: SamlSignInTrigger::Initiated(path.app()),
        lifetime: federation.idp.assertion_lifetime,
    };
    let output = federation
        .idp
        .answer
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Json(SamlFormPost::sign_in(output)))
}

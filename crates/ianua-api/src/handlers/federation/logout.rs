//! Single logout handlers, both ways: the tenant as identity provider to
//! its SAML apps, and this platform as service provider to a connection's
//! provider. A peer's request goes on to the dashboard, which holds the
//! person's session; a peer's answer to a request sent from here is taken
//! at once.

use axum::extract::State;
use ianua_app::use_case::Command as _;
use ianua_app::use_cases::federation::logout::{
    AnswerAppRequest, AnswerProviderRequest, Answerer, TakeResponseRequest,
};
use ianua_assembly::federation::FederationState;
use time::OffsetDateTime;

use crate::dto::federation::messages::{
    LogoutRequestsResponse, SamlForm, SamlFormPost, SamlMessageBody,
};
use crate::dto::federation::site::FederationSite;
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::federation::{
    ConnectionSite, ForwardedSamlRequest, LogoutVisitor, PostedSamlMessage, RedirectedSamlMessage,
    SamlMessageKind,
};
use crate::extractors::json::Json;
use crate::extractors::public_tenant::PublicTenant;
use crate::response::Found;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/saml/slo",
    tag = "SAML IdP",
    params(
        ("SAMLRequest" = Option<String>, Query, description = "An app's logout request"),
        ("SAMLResponse" = Option<String>, Query, description = "An app's answer to a logout request sent from here"),
        ("RelayState" = Option<String>, Query, description = "What the app wants back"),
        ("SigAlg" = Option<String>, Query, description = "The signature algorithm, when signed"),
        ("Signature" = Option<String>, Query, description = "The signature over the query, when signed")
    ),
    responses(
        (status = 302, description = "On to the dashboard's logout page, or its sign-in page saying how the logout went"),
        (status = 403, description = "The workspace is not available, or the answer is not one to a request sent from here", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "No message, or a malformed one", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// SAML single logout with an app, HTTP-Redirect binding
///
/// Where the tenant's SAML apps send logouts, as the identity provider
/// metadata names. An app's logout request sends the browser on (`302`) to
/// the dashboard's `.../saml/slo` page with `binding=redirect` and the
/// query as it arrived; the page posts it to `.../saml/slo/answer` with the
/// person's session. An app's answer to a logout sent from here is taken
/// at once, and the browser goes to the dashboard's sign-in page with
/// `logout=success`, `partial` or `failed`, recording
/// `federation.logout_response_taken`. Public, limited per address.
pub(crate) async fn app_logout_redirect(
    State(federation): State<FederationState>,
    tenant: PublicTenant,
    site: FederationSite,
    message: RedirectedSamlMessage,
) -> Result<Found, ApiError> {
    if message.arrived.kind == SamlMessageKind::Request {
        let asked_at = OffsetDateTime::now_utc().unix_timestamp();
        return Ok(Found(site.dashboard_page(
            "/saml/slo",
            &message.body.bounce_query(asked_at),
        )));
    }
    let request = TakeResponseRequest {
        answerer: Answerer::App,
        message: message.arrived.message,
    };
    let status = federation
        .logout
        .take_response
        .execute(&tenant.tenant, &tenant.auditor, request)
        .await?;
    Ok(Found(site.logged_out_page(status)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/saml/slo",
    tag = "SAML IdP",
    request_body(content = SamlForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 302, description = "On to the dashboard's logout page, or its sign-in page saying how the logout went"),
        (status = 403, description = "The workspace is not available, or the answer is not one to a request sent from here", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "No message, or a malformed one", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// SAML single logout with an app, HTTP-POST binding
///
/// As the redirect binding, for an app that posts its logout request or
/// answer in a form (`SAMLRequest` or `SAMLResponse`, `RelayState`). A
/// request goes on to the dashboard with `binding=post`, the `message` and
/// the `relay_state`. Public, limited per address.
pub(crate) async fn app_logout_post(
    State(federation): State<FederationState>,
    tenant: PublicTenant,
    site: FederationSite,
    message: PostedSamlMessage,
) -> Result<Found, ApiError> {
    if message.arrived.kind == SamlMessageKind::Request {
        let asked_at = OffsetDateTime::now_utc().unix_timestamp();
        return Ok(Found(site.dashboard_page(
            "/saml/slo",
            &message.body.bounce_query(asked_at),
        )));
    }
    let request = TakeResponseRequest {
        answerer: Answerer::App,
        message: message.arrived.message,
    };
    let status = federation
        .logout
        .take_response
        .execute(&tenant.tenant, &tenant.auditor, request)
        .await?;
    Ok(Found(site.logged_out_page(status)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/saml/slo/answer",
    tag = "SAML IdP",
    request_body = SamlMessageBody,
    responses(
        (status = 200, description = "The answer, for the browser to post to the app", body = SamlFormPost),
        (status = 403, description = "No app of the tenant sent it, or its signature does not hold", body = ErrorBody),
        (status = 404, description = "No signing key set", body = ErrorBody),
        (status = 409, description = "The app has no logout address", body = ErrorBody),
        (status = 422, description = "Not a logout request, or a malformed one", body = ErrorBody)
    )
)]
/// Answer an app's logout request
///
/// The dashboard's `.../saml/slo` page posts the app's request as it
/// received it (`{"binding": "redirect", "query": ...}` or `{"binding":
/// "post", "message": ..., "relay_state": ...}`), with the person's session
/// when the browser holds one. When the request names the person as the
/// app knows them, their session ends and `authentication.session_revoked`
/// is recorded. Either way the answer is the signed logout response for
/// the browser to post as `parameter` to `destination`.
pub(crate) async fn answer_app_logout(
    State(federation): State<FederationState>,
    visitor: LogoutVisitor,
    site: FederationSite,
    ForwardedSamlRequest(arrived): ForwardedSamlRequest,
) -> Result<Json<SamlFormPost>, ApiError> {
    let request = AnswerAppRequest {
        idp_entity_id: site.idp_entity_id()?,
        message: arrived.message,
    };
    let answer = federation
        .logout
        .answer_app
        .execute(&visitor.browser, &visitor.auditor, request)
        .await?;
    Ok(Json(SamlFormPost::logout_answer(
        answer,
        arrived.relay_state,
    )))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/saml/slo/start",
    tag = "SAML IdP",
    responses(
        (status = 200, description = "The logout requests, for the browser to post one by one", body = LogoutRequestsResponse),
        (status = 401, description = "No session of the person's own", body = ErrorBody),
        (status = 404, description = "No signing key set", body = ErrorBody)
    )
)]
/// Start single logout
///
/// Before the dashboard signs a person out, it asks here for the logout
/// requests owed to every peer their session reached: each SAML app it
/// signed in to, then the SAML provider it was opened through. The browser
/// posts each as `parameter` to `destination`; the answers come back to
/// the `.../saml/slo` addresses. Requires a tenant user's own session.
/// Records `federation.logout_request_sent` for each.
pub(crate) async fn start_single_logout(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    site: FederationSite,
) -> Result<Json<LogoutRequestsResponse>, ApiError> {
    let messages = federation
        .logout
        .start
        .execute(&tenant.caller, &tenant.auditor, site.single_logout()?)
        .await?;
    Ok(Json(messages.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/connections/{id}/saml/slo",
    tag = "Federation",
    params(
        ("SAMLRequest" = Option<String>, Query, description = "The provider's logout request"),
        ("SAMLResponse" = Option<String>, Query, description = "The provider's answer to a logout request sent from here"),
        ("RelayState" = Option<String>, Query, description = "What the provider wants back"),
        ("SigAlg" = Option<String>, Query, description = "The signature algorithm"),
        ("Signature" = Option<String>, Query, description = "The signature over the query")
    ),
    responses(
        (status = 302, description = "On to the dashboard's logout page, or its sign-in page saying how the logout went"),
        (status = 403, description = "The workspace is not available, or the answer does not hold", body = ErrorBody),
        (status = 404, description = "No such tenant or connection", body = ErrorBody),
        (status = 409, description = "Not a SAML connection, or the answer came too late", body = ErrorBody),
        (status = 422, description = "No message, or a malformed one", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// SAML single logout with a provider, HTTP-Redirect binding
///
/// Where a SAML connection's provider sends logouts, as the connection's
/// service provider metadata names. Its logout request sends the browser
/// on (`302`) to the dashboard's `.../federation/connections/{id}/saml/slo`
/// page with `binding=redirect` and the query as it arrived; the page posts
/// it to `.../saml/slo/answer` under the connection. Its answer to a
/// logout sent from here is taken at once, and the browser goes to the
/// dashboard's sign-in page with `logout=success`, `partial` or `failed`.
/// Public, limited per address.
pub(crate) async fn provider_logout_redirect(
    State(federation): State<FederationState>,
    tenant: PublicTenant,
    ConnectionSite { site, path }: ConnectionSite,
    message: RedirectedSamlMessage,
) -> Result<Found, ApiError> {
    if message.arrived.kind == SamlMessageKind::Request {
        let asked_at = OffsetDateTime::now_utc().unix_timestamp();
        let query = message.body.bounce_query(asked_at);
        return Ok(Found(
            site.connection_logout_page(&path.connection(), &query),
        ));
    }
    let request = TakeResponseRequest {
        answerer: Answerer::Connection(path.connection()),
        message: message.arrived.message,
    };
    let status = federation
        .logout
        .take_response
        .execute(&tenant.tenant, &tenant.auditor, request)
        .await?;
    Ok(Found(site.logged_out_page(status)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/connections/{id}/saml/slo",
    tag = "Federation",
    request_body(content = SamlForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 302, description = "On to the dashboard's logout page, or its sign-in page saying how the logout went"),
        (status = 403, description = "The workspace is not available, or the answer does not hold", body = ErrorBody),
        (status = 404, description = "No such tenant or connection", body = ErrorBody),
        (status = 409, description = "Not a SAML connection, or the answer came too late", body = ErrorBody),
        (status = 422, description = "No message, or a malformed one", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// SAML single logout with a provider, HTTP-POST binding
///
/// As the redirect binding, for a provider that posts its logout request
/// or answer in a form. Public, limited per address.
pub(crate) async fn provider_logout_post(
    State(federation): State<FederationState>,
    tenant: PublicTenant,
    ConnectionSite { site, path }: ConnectionSite,
    message: PostedSamlMessage,
) -> Result<Found, ApiError> {
    if message.arrived.kind == SamlMessageKind::Request {
        let asked_at = OffsetDateTime::now_utc().unix_timestamp();
        let query = message.body.bounce_query(asked_at);
        return Ok(Found(
            site.connection_logout_page(&path.connection(), &query),
        ));
    }
    let request = TakeResponseRequest {
        answerer: Answerer::Connection(path.connection()),
        message: message.arrived.message,
    };
    let status = federation
        .logout
        .take_response
        .execute(&tenant.tenant, &tenant.auditor, request)
        .await?;
    Ok(Found(site.logged_out_page(status)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/connections/{id}/saml/slo/answer",
    tag = "Federation",
    request_body = SamlMessageBody,
    responses(
        (status = 200, description = "The answer, for the browser to post to the provider", body = SamlFormPost),
        (status = 403, description = "The request is unsigned, signed by a certificate the connection does not take, or names another issuer", body = ErrorBody),
        (status = 404, description = "No such connection, or no signing key set", body = ErrorBody),
        (status = 409, description = "Not a SAML connection, or its provider has no logout endpoint", body = ErrorBody),
        (status = 422, description = "Not a logout request, or a malformed one", body = ErrorBody)
    )
)]
/// Answer a provider's logout request
///
/// The dashboard's `.../federation/connections/{id}/saml/slo` page posts
/// the provider's request as it received it, with the person's session
/// when the browser holds one. When the request names the subject and
/// provider session the session was opened with, the session ends and
/// `authentication.session_revoked` is recorded. Either way the answer is
/// the signed logout response for the browser to post as `parameter` to
/// `destination`.
pub(crate) async fn answer_provider_logout(
    State(federation): State<FederationState>,
    visitor: LogoutVisitor,
    ConnectionSite { site, path }: ConnectionSite,
    ForwardedSamlRequest(arrived): ForwardedSamlRequest,
) -> Result<Json<SamlFormPost>, ApiError> {
    let request = AnswerProviderRequest {
        connection_id: path.connection(),
        sp_entity_id: site.sp_entity_id()?,
        message: arrived.message,
    };
    let answer = federation
        .logout
        .answer_provider
        .execute(&visitor.browser, &visitor.auditor, request)
        .await?;
    Ok(Json(SamlFormPost::logout_answer(
        answer,
        arrived.relay_state,
    )))
}

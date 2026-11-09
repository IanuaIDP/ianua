//! A tenant as the identity provider of outside SAML apps: its published
//! metadata, registering and switching apps, the services an app's
//! messages are carried to, and the dashboard's answers to them.

use serde::de::IgnoredAny;

use super::{Request, TenantPath, Text};
use crate::net::Call;
use crate::wire::saml_apps::{
    AnswerLogout, AnswerSignIn, FormPost, LogoutRequests, NewSamlApp, SamlAppMade,
};

/// `GET …/saml/metadata`: the tenant's identity provider metadata, XML.
#[must_use]
pub fn metadata(tenant: &TenantPath) -> Request<Text> {
    Request::text(Call::get(tenant.at("/saml/metadata")))
}

/// `POST …/saml/apps`.
#[must_use]
pub fn create(tenant: &TenantPath, app: &NewSamlApp) -> Request<SamlAppMade> {
    Request::of(Call::post(tenant.at("/saml/apps")).json(app))
}

/// `POST …/saml/apps/{id}/disable`.
#[must_use]
pub fn disable(tenant: &TenantPath, app_id: &str) -> Request<()> {
    Request::of(Call::post(
        tenant.at(&format!("/saml/apps/{app_id}/disable")),
    ))
}

/// `POST …/saml/apps/{id}/activate`.
#[must_use]
pub fn activate(tenant: &TenantPath, app_id: &str) -> Request<()> {
    Request::of(Call::post(
        tenant.at(&format!("/saml/apps/{app_id}/activate")),
    ))
}

/// `POST` of the SAML form `form` to the tenant's service at `url`, as a
/// browser carries an app's message there from the app's own site,
/// `from_site`. The platform answers by sending the browser on.
#[must_use]
pub fn carry(url: &str, form: String, from_site: &str) -> Request<IgnoredAny> {
    Request::of(
        Call::post(url)
            .raw("application/x-www-form-urlencoded", form)
            .header("origin", from_site)
            .header("sec-fetch-site", "cross-site"),
    )
}

/// `GET …/saml/sso/initiate?app_id={id}`: the link of an app tile, which
/// sends the browser on to the dashboard's sign-in page for the app.
#[must_use]
pub fn initiate(tenant: &TenantPath, app_id: &str) -> Request<IgnoredAny> {
    Request::of(Call::get(
        tenant.at(&format!("/saml/sso/initiate?app_id={app_id}")),
    ))
}

/// `POST …/saml/apps/{id}/sign-in`: the signed answer for the person
/// signed in, to the app's default address, with no request from the app.
#[must_use]
pub fn sign_in_to(tenant: &TenantPath, app_id: &str) -> Request<FormPost> {
    Request::of(Call::post(
        tenant.at(&format!("/saml/apps/{app_id}/sign-in")),
    ))
}

/// `POST …/saml/sso/answer`.
#[must_use]
pub fn answer(tenant: &TenantPath, held: &AnswerSignIn) -> Request<FormPost> {
    Request::of(Call::post(tenant.at("/saml/sso/answer")).json(held))
}

/// `POST …/saml/slo/answer`.
#[must_use]
pub fn answer_logout(tenant: &TenantPath, request: &AnswerLogout) -> Request<FormPost> {
    Request::of(Call::post(tenant.at("/saml/slo/answer")).json(request))
}

/// `POST …/saml/slo/start`.
#[must_use]
pub fn start_logout(tenant: &TenantPath) -> Request<LogoutRequests> {
    Request::of(Call::post(tenant.at("/saml/slo/start")))
}

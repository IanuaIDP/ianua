//! A tenant as an OAuth 2.0 and OpenID Connect provider: an administrator
//! registering a client, a signed-in person giving consent, and the client
//! redeeming codes, reading user info, revoking tokens, signing the person
//! out, and checking the provider's discovery and keys.

use serde::de::IgnoredAny;

use super::{Request, TenantPath};
use crate::net::Call;
use crate::wire::oauth::{
    Authorized, AuthorizedApp, ClientCredentialsGrant, ClientRegistered,
    ConfidentialClientRegistered, Consent, DeviceAnswer, DeviceAsk, DeviceCodes, DevicePoll,
    Discovery, EndSession, Introspection, Keys, NewClient, NewConfiguredClient, NewMachineClient,
    ProvenQuestion, ProvenTokenRequest, RegisteredClient, Revocation, RotateSecret, RotatedSecret,
    SessionEnded, TokenFacts, TokenRequest, Tokens, UserInfo,
};

/// The content type of the forms OAuth endpoints read.
const FORM: &str = "application/x-www-form-urlencoded";

/// `POST …/oauth/clients`: registers a client with the tenant.
#[must_use]
pub fn register_client(tenant: &TenantPath, client: &NewClient) -> Request<ClientRegistered> {
    Request::of(Call::post(tenant.at("/oauth/clients")).json(client))
}

/// `POST …/oauth/clients`: registers a machine client with the tenant;
/// its secret is in the answer, once.
#[must_use]
pub fn register_machine_client(
    tenant: &TenantPath,
    client: &NewMachineClient,
) -> Request<ConfidentialClientRegistered> {
    Request::of(Call::post(tenant.at("/oauth/clients")).json(client))
}

/// `POST …/oauth/token`: a machine client gets a token for itself, sent
/// as a form.
#[must_use]
pub fn machine_token(tenant: &TenantPath, grant: &ClientCredentialsGrant) -> Request<Tokens> {
    Request::of(Call::post(tenant.at("/oauth/token")).raw(FORM, grant.form()))
}

/// `POST …/oauth/introspect`: a confidential client asks what an access
/// token says about itself, sent as a form.
#[must_use]
pub fn introspect(tenant: &TenantPath, question: &Introspection) -> Request<TokenFacts> {
    Request::of(Call::post(tenant.at("/oauth/introspect")).raw(FORM, question.form()))
}

/// `POST …/oauth/authorize`: a signed-in person consents to a client's
/// request, and a code is issued for its callback.
#[must_use]
pub fn authorize(tenant: &TenantPath, consent: &Consent) -> Request<Authorized> {
    Request::of(Call::post(tenant.at("/oauth/authorize")).json(consent))
}

/// `POST …/oauth/token`: a client redeems a grant, sent as a form.
#[must_use]
pub fn token(tenant: &TenantPath, grant: &TokenRequest) -> Request<Tokens> {
    Request::of(Call::post(tenant.at("/oauth/token")).raw(FORM, grant.form()))
}

/// `POST …/oauth/revoke`: a client gives a token up, sent as a form.
#[must_use]
pub fn revoke(tenant: &TenantPath, revocation: &Revocation) -> Request<()> {
    Request::of(Call::post(tenant.at("/oauth/revoke")).raw(FORM, revocation.form()))
}

/// `GET …/oauth/userinfo`: who `access_token` stands for.
#[must_use]
pub fn user_info(tenant: &TenantPath, access_token: &str) -> Request<UserInfo> {
    let call = Call::get(tenant.at("/oauth/userinfo"))
        .header("authorization", &format!("Bearer {access_token}"));
    Request::of(call)
}

/// `GET …/oauth/logout?{query}`: an app sends the browser to sign out;
/// the platform sends it on to the dashboard's sign-out page.
#[must_use]
pub fn logout(tenant: &TenantPath, query: &str) -> Request<IgnoredAny> {
    Request::of(Call::get(tenant.at(&format!("/oauth/logout?{query}"))))
}

/// `POST …/oauth/end-session`: the dashboard's sign-out page hands back
/// the app's request.
#[must_use]
pub fn end_session(tenant: &TenantPath, request: &EndSession) -> Request<SessionEnded> {
    Request::of(Call::post(tenant.at("/oauth/end-session")).json(request))
}

/// `GET …/.well-known/openid-configuration`: the provider's discovery
/// document.
#[must_use]
pub fn discovery(tenant: &TenantPath) -> Request<Discovery> {
    Request::of(Call::get(tenant.at("/.well-known/openid-configuration")))
}

/// `GET {jwks_uri}`: the signing keys the discovery document points to.
#[must_use]
pub fn keys(jwks_uri: &str) -> Request<Keys> {
    Request::of(Call::get(jwks_uri))
}

/// `POST …/oauth/device/code`: a device asks for its codes, sent as a
/// form.
#[must_use]
pub fn device_codes(tenant: &TenantPath, ask: &DeviceAsk) -> Request<DeviceCodes> {
    Request::of(Call::post(tenant.at("/oauth/device/code")).raw(FORM, ask.form()))
}

/// `POST …/oauth/device/approve`: the signed-in person approves the
/// device showing `answer`'s code.
#[must_use]
pub fn approve_device(tenant: &TenantPath, answer: &DeviceAnswer) -> Request<()> {
    Request::of(Call::post(tenant.at("/oauth/device/approve")).json(answer))
}

/// `POST …/oauth/device/deny`: the signed-in person refuses the device
/// showing `answer`'s code.
#[must_use]
pub fn deny_device(tenant: &TenantPath, answer: &DeviceAnswer) -> Request<()> {
    Request::of(Call::post(tenant.at("/oauth/device/deny")).json(answer))
}

/// `POST …/oauth/token`: a device polls for its tokens, sent as a form.
#[must_use]
pub fn device_token(tenant: &TenantPath, poll: &DevicePoll) -> Request<Tokens> {
    Request::of(Call::post(tenant.at("/oauth/token")).raw(FORM, poll.form()))
}

/// `GET …/oauth/authorize?{query}`: an app sends the browser to ask for a
/// code; the platform sends it on to the dashboard's consent page, or back
/// to the app with what is wrong.
#[must_use]
pub fn browser_authorize(tenant: &TenantPath, query: &str) -> Request<IgnoredAny> {
    Request::of(Call::get(tenant.at(&format!("/oauth/authorize?{query}"))))
}

/// `POST …/oauth/clients`: registers a client with the proof and settings
/// `client` names; a secret, if it gets one, is in the answer, once.
#[must_use]
pub fn register_configured(
    tenant: &TenantPath,
    client: &NewConfiguredClient,
) -> Request<RegisteredClient> {
    Request::of(Call::post(tenant.at("/oauth/clients")).json(client))
}

/// `POST …/oauth/token`: a client redeems a grant while proving itself,
/// sent as a form.
#[must_use]
pub fn proven_token(tenant: &TenantPath, request: &ProvenTokenRequest) -> Request<Tokens> {
    Request::of(Call::post(tenant.at("/oauth/token")).raw(FORM, request.form()))
}

/// `POST …/oauth/introspect`: a client, proving itself however it does,
/// asks what a token says of itself.
#[must_use]
pub fn proven_introspect(tenant: &TenantPath, question: &ProvenQuestion) -> Request<TokenFacts> {
    Request::of(Call::post(tenant.at("/oauth/introspect")).raw(FORM, question.form()))
}

/// `POST …/oauth/revoke`: a client, proving itself however it does, gives
/// a token up.
#[must_use]
pub fn proven_revoke(tenant: &TenantPath, question: &ProvenQuestion) -> Request<()> {
    Request::of(Call::post(tenant.at("/oauth/revoke")).raw(FORM, question.form()))
}

/// `GET …/oauth/userinfo` with `access_token` bound to a key: presented
/// as `Authorization: DPoP` beside `proof`, the `DPoP` proof made for this
/// request.
#[must_use]
pub fn bound_user_info(tenant: &TenantPath, access_token: &str, proof: &str) -> Request<UserInfo> {
    let call = Call::get(tenant.at("/oauth/userinfo"))
        .header("authorization", &format!("DPoP {access_token}"))
        .header("dpop", proof);
    Request::of(call)
}

/// `POST …/oauth/clients/{id}/rotate-secret`: gives the client a new
/// secret, shown once.
#[must_use]
pub fn rotate_secret(
    tenant: &TenantPath,
    client_id: &str,
    rotation: &RotateSecret,
) -> Request<RotatedSecret> {
    let path = tenant.at(&format!("/oauth/clients/{client_id}/rotate-secret"));
    Request::of(Call::post(path).json(rotation))
}

/// `POST …/oauth/clients/{id}/revoke`: ends the client for good.
#[must_use]
pub fn revoke_client(tenant: &TenantPath, client_id: &str) -> Request<()> {
    Request::of(Call::post(
        tenant.at(&format!("/oauth/clients/{client_id}/revoke")),
    ))
}

/// `DELETE …/oauth/clients/{id}/consent`: the signed-in person withdraws
/// the consent they gave the client.
#[must_use]
pub fn withdraw_consent(tenant: &TenantPath, client_id: &str) -> Request<()> {
    Request::of(Call::delete(
        tenant.at(&format!("/oauth/clients/{client_id}/consent")),
    ))
}

/// `GET …/oauth/my-apps`: the apps the signed-in person consented to.
#[must_use]
pub fn my_apps(tenant: &TenantPath) -> Request<Vec<AuthorizedApp>> {
    Request::of(Call::get(tenant.at("/oauth/my-apps")))
}

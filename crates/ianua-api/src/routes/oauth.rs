//! OAuth endpoints: a tenant's clients, API keys and initial access
//! tokens, apps registering themselves, the browser and device flows,
//! signing out through an app, the token endpoint with introspection and
//! revocation, `userinfo`, and the OIDC discovery document.

use std::time::Duration;

use axum::Router;
use utoipa::OpenApi;

use crate::dto::oauth::api_keys::{
    ApiKeyResponse, CreateApiKeyBody, CreateApiKeyResponse, UpdateApiKeyBody,
};
use crate::dto::oauth::browser::{
    AuthorizeBody, AuthorizeResponse, AuthorizeStep, ConsentAnswerBody, EndSessionBody,
    EndSessionResponse, EndSessionStep, FormPostReply, PushedRequestResponse,
};
use crate::dto::oauth::clients::{
    AuthorizedAppResponse, ClientResponse, CreateClientBody, CreateClientResponse,
    RotateSecretBody, RotatedSecretResponse, UpdateClientBody,
};
use crate::dto::oauth::device::{DeviceAnswerBody, DeviceCodeResponse};
use crate::dto::oauth::errors::OAuthErrorBody;
use crate::dto::oauth::forms::{
    AccessTokenForm, ClientProofForm, DeviceCodeForm, PushedRequestForm, TokenAboutForm, TokenForm,
};
use crate::dto::oauth::metadata::{
    ClientSettingsBody, ClientSettingsView, ConsentChoice, ProvingBody, SenderChoice,
    TokenFormatChoice, TokenLifetimesBody,
};
use crate::dto::oauth::provider::OidcDiscoveryDocument;
use crate::dto::oauth::registration::{
    InitialAccessTokenResponse, IssueInitialAccessTokenBody, IssuedInitialAccessTokenResponse,
    RegisteredClientResponse, RegistrationBody,
};
use crate::dto::oauth::tokens::{
    ActorClaim, ConfirmationClaim, IntrospectionResponse, TokenResponse, UserInfoResponse,
};
use crate::extractors::oauth::authorization::AuthorizationParams;
use crate::extractors::oauth::logout::LogoutParams;
use crate::handlers::oauth::{api_keys, clients, flows, registration, token};
use crate::method::{delete, get, post, shared};
use crate::middleware::ip_rate_limit::{ip_rate_limit, per_address};
use crate::state::ApiState;

/// The OAuth endpoints called by programs and browsers rather than a
/// signed-in person (the authorization, token, pushed request, device,
/// introspection, revocation, `userinfo`, sign-out and registration
/// endpoints, and discovery), limited per client address.
pub(crate) fn public_routes(state: &ApiState) -> Router<ApiState> {
    let tenant = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}";
    let oauth = format!("{tenant}/oauth");
    let limiter = per_address(
        state,
        state.http.rate.api_default_per_minute,
        Duration::from_secs(60),
    );
    public_flow_routes(tenant, &oauth)
        .merge(registration_routes(&oauth))
        .layer(axum::middleware::from_fn_with_state(limiter, ip_rate_limit))
}

/// Browser and device flows, discovery, and bearer token operations.
fn public_flow_routes(tenant: &str, oauth: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{tenant}/.well-known/openid-configuration"),
            get(flows::discovery),
        )
        .route(&format!("{oauth}/authorize"), get(flows::browser_authorize))
        .route(
            &format!("{oauth}/par"),
            post(flows::push_authorization_request),
        )
        .route(&format!("{oauth}/token"), post(token::token))
        .route(&format!("{oauth}/introspect"), post(token::introspect))
        .route(&format!("{oauth}/revoke"), post(token::revoke))
        .route(
            &format!("{oauth}/device/code"),
            post(flows::request_device_code),
        )
        .route(
            &format!("{oauth}/userinfo"),
            get(flows::userinfo).post(shared(flows::userinfo_by_post)),
        )
        .route(
            &format!("{oauth}/logout"),
            get(flows::browser_logout).post(shared(flows::browser_logout_by_form)),
        )
}

/// Dynamic client registration and updates authenticated by its registration token.
fn registration_routes(oauth: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{oauth}/register"),
            post(registration::register_client),
        )
        .route(
            &format!("{oauth}/register/{{client_id}}"),
            get(registration::read_registration)
                .put(shared(registration::update_registration))
                .delete(shared(registration::delete_registration)),
        )
}

/// The OAuth endpoints for a signed-in caller, and the dashboard's
/// sign-out step, which a browser holding no session may also reach.
pub(crate) fn routes() -> Router<ApiState> {
    let tenant = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}";
    let oauth = format!("{tenant}/oauth");
    Router::new()
        .route(&format!("{oauth}/authorize"), post(flows::authorize))
        .route(&format!("{oauth}/end-session"), post(flows::end_session))
        .route(
            &format!("{oauth}/device/approve"),
            post(flows::approve_device),
        )
        .route(&format!("{oauth}/device/deny"), post(flows::deny_device))
        .merge(client_routes(&oauth))
        .merge(initial_token_routes(&oauth))
        .merge(api_key_routes(&oauth))
}

/// Client configuration, secret rotation, and the caller's authorized apps.
fn client_routes(oauth: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{oauth}/clients"),
            post(clients::create_client).get(shared(clients::list_clients)),
        )
        .route(
            &format!("{oauth}/clients/{{id}}"),
            get(clients::get_client).patch(shared(clients::update_client)),
        )
        .route(
            &format!("{oauth}/clients/{{id}}/rotate-secret"),
            post(clients::rotate_client_secret),
        )
        .route(
            &format!("{oauth}/clients/{{id}}/revoke"),
            post(clients::revoke_client),
        )
        .route(
            &format!("{oauth}/clients/{{id}}/consent"),
            delete(clients::revoke_client_consent),
        )
        .route(&format!("{oauth}/my-apps"), get(clients::list_my_apps))
}

/// Initial access tokens used to authorize dynamic registrations.
fn initial_token_routes(oauth: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{oauth}/initial-access-tokens"),
            post(registration::issue_initial_access_token)
                .get(shared(registration::list_initial_access_tokens)),
        )
        .route(
            &format!("{oauth}/initial-access-tokens/{{id}}/revoke"),
            post(registration::revoke_initial_access_token),
        )
}

/// API key issuance, changes, and suspension of their use.
fn api_key_routes(oauth: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{oauth}/api-keys"),
            post(api_keys::create_api_key).get(shared(api_keys::list_api_keys)),
        )
        .route(
            &format!("{oauth}/api-keys/{{id}}"),
            get(api_keys::get_api_key).patch(shared(api_keys::update_api_key)),
        )
        .route(
            &format!("{oauth}/api-keys/{{id}}/revoke"),
            post(api_keys::revoke_api_key),
        )
        .route(
            &format!("{oauth}/api-keys/{{id}}/pause"),
            post(api_keys::pause_api_key),
        )
        .route(
            &format!("{oauth}/api-keys/{{id}}/resume"),
            post(api_keys::resume_api_key),
        )
}

/// The OAuth part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        clients::create_client,
        clients::list_clients,
        clients::get_client,
        clients::update_client,
        clients::rotate_client_secret,
        clients::revoke_client,
        clients::revoke_client_consent,
        clients::list_my_apps,
        api_keys::create_api_key,
        api_keys::list_api_keys,
        api_keys::get_api_key,
        api_keys::update_api_key,
        api_keys::revoke_api_key,
        api_keys::pause_api_key,
        api_keys::resume_api_key,
        registration::register_client,
        registration::read_registration,
        registration::update_registration,
        registration::delete_registration,
        registration::issue_initial_access_token,
        registration::list_initial_access_tokens,
        registration::revoke_initial_access_token,
        flows::browser_authorize,
        flows::authorize,
        flows::push_authorization_request,
        flows::browser_logout,
        flows::browser_logout_by_form,
        flows::end_session,
        flows::request_device_code,
        flows::approve_device,
        flows::deny_device,
        flows::userinfo,
        flows::userinfo_by_post,
        flows::discovery,
        token::token,
        token::introspect,
        token::revoke,
    ),
    components(schemas(
        CreateClientBody,
        CreateClientResponse,
        UpdateClientBody,
        ClientResponse,
        RotateSecretBody,
        RotatedSecretResponse,
        AuthorizedAppResponse,
        ProvingBody,
        ClientSettingsBody,
        ClientSettingsView,
        TokenLifetimesBody,
        ConsentChoice,
        TokenFormatChoice,
        SenderChoice,
        CreateApiKeyBody,
        CreateApiKeyResponse,
        UpdateApiKeyBody,
        ApiKeyResponse,
        RegistrationBody,
        RegisteredClientResponse,
        IssueInitialAccessTokenBody,
        IssuedInitialAccessTokenResponse,
        InitialAccessTokenResponse,
        AuthorizationParams,
        AuthorizeBody,
        ConsentAnswerBody,
        AuthorizeResponse,
        AuthorizeStep,
        FormPostReply,
        PushedRequestResponse,
        LogoutParams,
        EndSessionBody,
        EndSessionResponse,
        EndSessionStep,
        DeviceCodeResponse,
        DeviceAnswerBody,
        TokenResponse,
        IntrospectionResponse,
        ConfirmationClaim,
        ActorClaim,
        UserInfoResponse,
        OidcDiscoveryDocument,
        OAuthErrorBody,
        ClientProofForm,
        TokenForm,
        TokenAboutForm,
        DeviceCodeForm,
        PushedRequestForm,
        AccessTokenForm,
    ))
)]
pub(crate) struct Document;

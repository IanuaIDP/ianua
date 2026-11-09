//! The OAuth endpoints: clients, API keys and initial access tokens, apps
//! registering themselves, the browser and device flows, the token endpoint
//! with introspection and revocation, `userinfo`, signing out, and the
//! discovery document, and what they answer.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum_test::{TestResponse, TestServer};
use base64::Engine;
use ianua_api::test_support::{ORG, TENANT, TENANT_USER, adapters, router};
use ianua_app::ports::oauth::SignedDpopProof;
use ianua_app::test_support::acting::{FakeTenantAuthorities, Refusal};
use ianua_app::test_support::oauth::{
    FakeDpopVerifier, FakeOAuthClientStore, TEST_AFTER_LOGOUT, TEST_CLIENT_SECRET, TEST_REDIRECT,
    TEST_VERIFIER, client_with, public_client, stored_client,
};
use ianua_app::test_support::{RejectingLimitEnforcer, test_ctx};
use ianua_assembly::deps::Adapters;
use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClient};
use ianua_domain::domains::oauth::grants::token_binding::{JwkThumbprint, SenderConstraint};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::TokenId;
use serde_json::{Value, json};

/// The test tenant's address, followed by `rest`.
fn tenant_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}{rest}")
}

/// A server over the default fake adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// A server whose test tenant holds `client`.
fn serving(client: OAuthClient<ResolvedTenant>) -> TestServer {
    TestServer::new(router(Adapters {
        o_auth_client_store: Arc::new(FakeOAuthClientStore::holding(&test_ctx().tenant(), client)),
        ..adapters()
    }))
    .unwrap()
}

/// The `Authorization: Basic` value `client` proves itself with.
fn basic(client: &OAuthClient<ResolvedTenant>) -> String {
    let pair = format!("{}:{TEST_CLIENT_SECRET}", client.client_id_value().as_str());
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(pair)
    )
}

/// The OAuth `error` an answer carries.
fn error_of(response: &TestResponse) -> String {
    response.json::<Value>()["error"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// The `Location` a redirecting answer sends the browser to.
fn location(response: &TestResponse) -> String {
    response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

/// The body registering a dashboard client that signs in with an
/// authorization code.
fn create_client_body() -> Value {
    json!({
        "name": "Dashboard",
        "redirect_uris": [TEST_REDIRECT],
        "grant_types": ["AuthorizationCode"],
        "scopes": ["read"]
    })
}

/// An admin registers a client and is shown its secret once; the client is
/// then listed with its `client_id`, without the secret.
#[tokio::test]
async fn a_registered_client_is_listed_without_its_secret() {
    let server = server();

    let created = server
        .post(&tenant_path("/oauth/clients"))
        .authorization_bearer(TENANT_USER)
        .json(&create_client_body())
        .await;
    created.assert_status(StatusCode::CREATED);
    let created: Value = created.json();
    assert!(created["client_secret"].is_string());

    let page: Value = server
        .get(&tenant_path("/oauth/clients"))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(page["items"].as_array().map(Vec::len), Some(1));
    let entry = &page["items"][0];
    assert_eq!(entry["id"], created["id"]);
    assert_eq!(entry["client_id"], created["client_id"]);
    assert_eq!(entry["status"], "Active");
    assert_eq!(entry["token_endpoint_auth_method"], "client_secret_basic");
    assert!(entry.get("client_secret").is_none());
}

/// A public client, for a single-page app, is registered with no secret
/// to show.
#[tokio::test]
async fn a_public_client_is_shown_no_secret() {
    let server = server();
    let mut body = create_client_body();
    body["token_endpoint_auth_method"] = json!("none");

    let created = server
        .post(&tenant_path("/oauth/clients"))
        .authorization_bearer(TENANT_USER)
        .json(&body)
        .await;

    created.assert_status(StatusCode::CREATED);
    assert!(created.json::<Value>().get("client_secret").is_none());
}

/// A redirect that is plain HTTP to a public host is refused before
/// anything is stored.
#[tokio::test]
async fn a_plain_http_redirect_is_refused() {
    let server = server();

    let response = server
        .post(&tenant_path("/oauth/clients"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": "Dashboard", "redirect_uris": ["http://app.example.com/cb"]}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A plan refusal makes client registration return 403.
#[tokio::test]
async fn a_client_over_the_plan_limit_is_refused() {
    let server = TestServer::new(router(Adapters {
        limit_enforcer: Arc::new(RejectingLimitEnforcer),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .post(&tenant_path("/oauth/clients"))
        .authorization_bearer(TENANT_USER)
        .json(&create_client_body())
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// An admin rotates a client's secret, keeping the old one for an hour,
/// and is shown the new one once.
#[tokio::test]
async fn a_rotated_secret_is_shown_once() {
    let client = stored_client("Portal", &[GrantType::AuthorizationCode]);
    let id = client.id().to_string();
    let server = serving(client);

    let response = server
        .post(&tenant_path(&format!("/oauth/clients/{id}/rotate-secret")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"overlap_seconds": 3600}))
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert!(body["client_secret"].is_string());
    assert_ne!(body["client_secret"], TEST_CLIENT_SECRET);
}

/// An API key is shown once on creation, then read back by its id.
#[tokio::test]
async fn an_api_key_is_shown_once_and_read_back() {
    let server = server();

    let created = server
        .post(&tenant_path("/oauth/api-keys"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": "CI", "scopes": ["idp:routing:view"]}))
        .await;
    created.assert_status(StatusCode::CREATED);
    let created: Value = created.json();
    assert!(created["raw_key"].is_string());

    let key: Value = server
        .get(&tenant_path(&format!(
            "/oauth/api-keys/{}",
            created["id"].as_str().unwrap()
        )))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(key["name"], "CI");
    assert!(key.get("raw_key").is_none());
}

/// A key just made was never used. Its last use and the address of it
/// read back as `null`, the fields present for when it is.
#[tokio::test]
async fn a_new_api_key_shows_no_last_use() {
    let server = server();
    let created: Value = server
        .post(&tenant_path("/oauth/api-keys"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": "CI", "scopes": ["idp:routing:view"]}))
        .await
        .json();

    let key: Value = server
        .get(&tenant_path(&format!(
            "/oauth/api-keys/{}",
            created["id"].as_str().unwrap()
        )))
        .authorization_bearer(TENANT_USER)
        .await
        .json();

    assert!(key["last_used_at"].is_null());
    assert!(key["last_used_ip"].is_null());
    assert!(key.get("last_used_at").is_some());
    assert!(key.get("last_used_ip").is_some());
}

/// Listing API keys without tenant authority returns 403.
#[tokio::test]
async fn a_caller_the_app_refuses_is_forbidden() {
    let server = TestServer::new(router(Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&tenant_path("/oauth/api-keys"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// Ann lists the apps she authorized; she authorized none yet.
#[tokio::test]
async fn my_apps_lists_what_i_authorized() {
    let server = server();

    let response = server
        .get(&tenant_path("/oauth/my-apps"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    assert_eq!(response.json::<Value>(), json!([]));
}

/// A relying party reads the discovery document without signing in; every
/// endpoint is under the tenant's issuer, and every grant is named.
#[tokio::test]
async fn the_discovery_document_names_every_endpoint() {
    let server = server();

    let response = server
        .get(&tenant_path("/.well-known/openid-configuration"))
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_discovery_endpoints(&body);
    assert_eq!(body["code_challenge_methods_supported"], json!(["S256"]));
    assert!(
        body["grant_types_supported"]
            .as_array()
            .unwrap()
            .contains(&json!("refresh_token"))
    );
    assert!(
        body["id_token_signing_alg_values_supported"]
            .as_array()
            .unwrap()
            .contains(&json!("EdDSA"))
    );
}

/// Checks that discovery names the tenant issuer and locates each endpoint under it.
fn assert_discovery_endpoints(body: &Value) {
    let issuer = body["issuer"].as_str().unwrap();
    assert!(issuer.ends_with(&format!("/api/v1/organizations/{ORG}/tenants/{TENANT}")));
    for (field, path) in [
        ("token_endpoint", "/oauth/token"),
        ("userinfo_endpoint", "/oauth/userinfo"),
        ("pushed_authorization_request_endpoint", "/oauth/par"),
        ("device_authorization_endpoint", "/oauth/device/code"),
        ("introspection_endpoint", "/oauth/introspect"),
        ("revocation_endpoint", "/oauth/revoke"),
        ("end_session_endpoint", "/oauth/logout"),
        ("registration_endpoint", "/oauth/register"),
        ("jwks_uri", "/.well-known/jwks.json"),
    ] {
        assert_eq!(body[field], format!("{issuer}{path}"), "{field}");
    }
}

/// A token request without a client returns 401, invalid_client and an
/// authentication challenge.
#[tokio::test]
async fn a_token_request_without_a_client_is_challenged() {
    let server = server();

    let response = server
        .post(&tenant_path("/oauth/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "abc"),
            ("redirect_uri", TEST_REDIRECT),
            ("code_verifier", TEST_VERIFIER),
        ])
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(error_of(&response), "invalid_client");
    assert!(response.headers().get(WWW_AUTHENTICATE).is_some());
}

/// An unknown client receives 401 with invalid_client.
#[tokio::test]
async fn a_token_request_for_an_unknown_client_is_challenged() {
    let server = server();

    let response = server
        .post(&tenant_path("/oauth/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "client_unknown"),
            ("client_secret", "secret"),
        ])
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(error_of(&response), "invalid_client");
}

/// An incorrect machine-client secret returns 401 with invalid_client.
#[tokio::test]
async fn a_wrong_client_secret_is_refused() {
    let client = stored_client("Billing", &[GrantType::ClientCredentials]);
    let id = client.client_id_value().as_str().to_owned();
    let server = serving(client);

    let response = server
        .post(&tenant_path("/oauth/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", id.as_str()),
            ("client_secret", "guessed"),
        ])
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(error_of(&response), "invalid_client");
}

/// A grant the server does not offer is refused `unsupported_grant_type`.
#[tokio::test]
async fn an_unknown_grant_is_unsupported() {
    let server = server();

    let response = server
        .post(&tenant_path("/oauth/token"))
        .form(&[("grant_type", "password"), ("username", "ann")])
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&response), "unsupported_grant_type");
}

/// A machine client proves itself in a Basic header and is handed a bearer
/// access token for its scopes, with no ID token.
#[tokio::test]
async fn a_machine_client_is_handed_an_access_token() {
    let client = stored_client("Billing", &[GrantType::ClientCredentials]);
    let authorization = basic(&client);
    let server = serving(client);

    let response = server
        .post(&tenant_path("/oauth/token"))
        .add_header(AUTHORIZATION, authorization)
        .form(&[("grant_type", "client_credentials"), ("scope", "read")])
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert!(body["access_token"].is_string());
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["scope"], "read");
    assert!(body.get("id_token").is_none());
}

/// A resource server introspects the machine's token and is told it works,
/// for the machine itself.
#[tokio::test]
async fn an_issued_token_introspects_as_active() {
    let client = stored_client("Billing", &[GrantType::ClientCredentials]);
    let authorization = basic(&client);
    let client_id = client.client_id_value().as_str().to_owned();
    let server = serving(client);
    let issued: Value = server
        .post(&tenant_path("/oauth/token"))
        .add_header(AUTHORIZATION, authorization.clone())
        .form(&[("grant_type", "client_credentials")])
        .await
        .json();

    let response = server
        .post(&tenant_path("/oauth/introspect"))
        .add_header(AUTHORIZATION, authorization)
        .form(&[("token", issued["access_token"].as_str().unwrap())])
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["active"], true);
    assert_eq!(body["client_id"], client_id);
    assert_eq!(body["sub"], client_id);
}

/// A token nobody issued introspects as inactive, and says nothing else.
#[tokio::test]
async fn an_unknown_token_introspects_as_inactive() {
    let client = stored_client("Gateway", &[GrantType::ClientCredentials]);
    let authorization = basic(&client);
    let server = serving(client);

    let response = server
        .post(&tenant_path("/oauth/introspect"))
        .add_header(AUTHORIZATION, authorization)
        .form(&[("token", "never-issued")])
        .await;

    response.assert_status_ok();
    assert_eq!(response.json::<Value>(), json!({"active": false}));
}

/// A public client receives 401 with invalid_client when introspecting a token.
#[tokio::test]
async fn a_public_client_may_not_introspect() {
    let client = public_client("SPA", &[GrantType::AuthorizationCode]);
    let id = client.client_id_value().as_str().to_owned();
    let server = serving(client);

    let response = server
        .post(&tenant_path("/oauth/introspect"))
        .form(&[("token", "anything"), ("client_id", id.as_str())])
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(error_of(&response), "invalid_client");
}

/// Revoking a token nobody issued answers `200`, so the answer says
/// nothing about which tokens exist.
#[tokio::test]
async fn revoking_an_unknown_token_answers_ok() {
    let client = stored_client("Portal", &[GrantType::AuthorizationCode]);
    let authorization = basic(&client);
    let server = serving(client);

    let response = server
        .post(&tenant_path("/oauth/revoke"))
        .add_header(AUTHORIZATION, authorization)
        .form(&[
            ("token", "never-issued"),
            ("token_type_hint", "refresh_token"),
        ])
        .await;

    response.assert_status_ok();
}

/// A device asks for its codes with a form, and is handed a user code, the
/// page to type it on, the same page with it filled in, and how often to
/// poll.
#[tokio::test]
async fn a_device_is_handed_its_codes() {
    let client = stored_client("TV", &[GrantType::DeviceCode]);
    let authorization = basic(&client);
    let server = serving(client);

    let response = server
        .post(&tenant_path("/oauth/device/code"))
        .add_header(AUTHORIZATION, authorization)
        .form(&[("scope", "read")])
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert!(body["device_code"].is_string());
    let user_code = body["user_code"].as_str().unwrap();
    assert!(
        body["verification_uri_complete"]
            .as_str()
            .unwrap()
            .contains(&format!("user_code={user_code}"))
    );
    assert!(body["interval"].is_number());
}

/// The device polls the token endpoint before anyone typed its code, and
/// is told `authorization_pending`.
#[tokio::test]
async fn a_device_polling_too_early_is_told_to_wait() {
    let client = stored_client("TV", &[GrantType::DeviceCode]);
    let authorization = basic(&client);
    let server = serving(client);
    let codes: Value = server
        .post(&tenant_path("/oauth/device/code"))
        .add_header(AUTHORIZATION, authorization.clone())
        .form(&[("scope", "read")])
        .await
        .json();

    let response = server
        .post(&tenant_path("/oauth/token"))
        .add_header(AUTHORIZATION, authorization)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", codes["device_code"].as_str().unwrap()),
        ])
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&response), "authorization_pending");
}

/// A device token request naming an unsupported resource returns 400
/// with invalid_target.
#[tokio::test]
async fn a_resource_naming_no_stream_route_is_an_invalid_target() {
    let client = stored_client("TV", &[GrantType::DeviceCode]);
    let authorization = basic(&client);
    let server = serving(client);
    let codes: Value = server
        .post(&tenant_path("/oauth/device/code"))
        .add_header(AUTHORIZATION, authorization.clone())
        .form(&[("scope", "read")])
        .await
        .json();

    let response = server
        .post(&tenant_path("/oauth/token"))
        .add_header(AUTHORIZATION, authorization)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", codes["device_code"].as_str().unwrap()),
            ("resource", "https://billing.acme.example"),
        ])
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&response), "invalid_target");
}

/// A browser's authorization request from `client`, with `extra`
/// parameters replacing or adding to a proper one.
fn browser_request(
    client: &OAuthClient<ResolvedTenant>,
    extra: &[(&str, &str)],
) -> Vec<(String, String)> {
    let id = client.client_id_value().as_str();
    [
        ("response_type", "code"),
        ("client_id", id),
        ("redirect_uri", TEST_REDIRECT),
        ("scope", "read"),
        ("state", "xyz"),
        ("code_challenge", TEST_VERIFIER),
        ("code_challenge_method", "S256"),
    ]
    .iter()
    .filter(|(name, _)| !extra.iter().any(|(replaced, _)| replaced == name))
    .chain(extra.iter())
    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
    .collect()
}

/// A relying party sends Ann's browser to the authorization endpoint the
/// discovery document names, naming its client by the `client_id` it was
/// issued. The request holds, so the browser goes on to the dashboard's
/// sign-in and consent page, carrying the request.
#[tokio::test]
async fn a_browser_request_goes_on_to_the_consent_page() {
    let client = stored_client("Portal", &[GrantType::AuthorizationCode]);
    let request = browser_request(&client, &[]);
    let server = serving(client);

    let response = server
        .get(&tenant_path("/oauth/authorize"))
        .add_query_params(request)
        .await;

    response.assert_status(StatusCode::FOUND);
    let to = location(&response);
    assert!(to.contains(&format!(
        "/organizations/{ORG}/tenants/{TENANT}/oauth/authorize?"
    )));
    assert!(to.contains("state=xyz"));
}

/// An unregistered redirect URI returns 422 without a Location header.
#[tokio::test]
async fn a_browser_request_to_an_unregistered_redirect_goes_nowhere() {
    let client = stored_client("Portal", &[GrantType::AuthorizationCode]);
    let request = browser_request(&client, &[("redirect_uri", "https://evil.test/cb")]);
    let server = serving(client);

    let response = server
        .get(&tenant_path("/oauth/authorize"))
        .add_query_params(request)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    assert!(response.headers().get("location").is_none());
}

/// A request without PKCE goes back to the client's own redirect, telling
/// it the fault, with its state and the issuer.
#[tokio::test]
async fn a_browser_request_without_pkce_goes_back_to_the_client() {
    let client = stored_client("Portal", &[GrantType::AuthorizationCode]);
    let request = browser_request(&client, &[("code_challenge_method", "plain")]);
    let server = serving(client);

    let response = server
        .get(&tenant_path("/oauth/authorize"))
        .add_query_params(request)
        .await;

    response.assert_status(StatusCode::FOUND);
    assert!(location(&response).starts_with(&format!(
        "{TEST_REDIRECT}?error=invalid_request&state=xyz&iss="
    )));
}

/// The portal pushes its request first and is handed a `request_uri`; the
/// browser it sends on with only that goes on to the consent page.
#[tokio::test]
async fn a_pushed_request_carries_the_browser_on() {
    let client = stored_client("Portal", &[GrantType::AuthorizationCode]);
    let authorization = basic(&client);
    let id = client.client_id_value().as_str().to_owned();
    let pushed_form = browser_request(&client, &[])
        .into_iter()
        .filter(|(name, _)| name != "client_id")
        .collect::<Vec<_>>();
    let server = serving(client);

    let pushed = server
        .post(&tenant_path("/oauth/par"))
        .add_header(AUTHORIZATION, authorization)
        .form(&pushed_form)
        .await;
    pushed.assert_status(StatusCode::CREATED);
    let request_uri = pushed.json::<Value>()["request_uri"]
        .as_str()
        .unwrap()
        .to_owned();

    let response = server
        .get(&tenant_path("/oauth/authorize"))
        .add_query_params([
            ("client_id", id.as_str()),
            ("request_uri", request_uri.as_str()),
        ])
        .await;

    response.assert_status(StatusCode::FOUND);
    assert!(location(&response).contains("request_uri="));
}

/// Userinfo without a token returns 401 with a Bearer challenge.
#[tokio::test]
async fn userinfo_without_a_token_is_challenged() {
    let server = server();

    let response = server.get(&tenant_path("/oauth/userinfo")).await;

    response.assert_status(StatusCode::UNAUTHORIZED);
    let challenge = response.headers()[WWW_AUTHENTICATE]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(challenge.starts_with("Bearer"));
}

/// Userinfo with an unknown token returns 401 with invalid_token.
#[tokio::test]
async fn userinfo_with_an_unknown_token_is_refused() {
    let server = server();

    let response = server
        .get(&tenant_path("/oauth/userinfo"))
        .authorization_bearer("never-issued")
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(error_of(&response), "invalid_token");
}

/// An admin issues an initial access token; an app registers itself with
/// it, then reads and deletes its registration with the token it was
/// handed.
#[tokio::test]
async fn an_app_registers_and_manages_itself() {
    let server = server();
    let issued = issue_registration_token(&server).await;

    let registered = server
        .post(&tenant_path("/oauth/register"))
        .authorization_bearer(issued["token"].as_str().unwrap())
        .json(&json!({
            "client_name": "MCP tool",
            "redirect_uris": ["http://127.0.0.1:8123/callback"],
            "token_endpoint_auth_method": "none"
        }))
        .await;
    registered.assert_status(StatusCode::CREATED);
    let registered: Value = registered.json();
    let client_id = registered["client_id"].as_str().unwrap();
    let management = registered["registration_access_token"].as_str().unwrap();
    assert!(registered.get("client_secret").is_none());

    let read = server
        .get(&tenant_path(&format!("/oauth/register/{client_id}")))
        .authorization_bearer(management)
        .await;
    read.assert_status_ok();
    assert_eq!(read.json::<Value>()["client_name"], "MCP tool");

    server
        .delete(&tenant_path(&format!("/oauth/register/{client_id}")))
        .authorization_bearer(management)
        .await
        .assert_status(StatusCode::NO_CONTENT);
}

/// Issues the one-use initial access token used by the registering MCP client.
async fn issue_registration_token(server: &TestServer) -> Value {
    server
        .post(&tenant_path("/oauth/initial-access-tokens"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": "MCP clients", "uses": 1, "expires_in_seconds": 3600}))
        .await
        .json()
}

/// Dynamic client registration without an initial access token returns 401.
#[tokio::test]
async fn registering_without_an_initial_access_token_is_refused() {
    let server = server();

    let response = server
        .post(&tenant_path("/oauth/register"))
        .json(&json!({"client_name": "Mallory's app", "redirect_uris": [TEST_REDIRECT]}))
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// An app sends the browser to the end session endpoint; it goes on to the
/// dashboard's sign-out page, carrying the request.
#[tokio::test]
async fn signing_out_through_an_app_goes_to_the_dashboard() {
    let server = server();

    let response = server
        .get(&tenant_path("/oauth/logout"))
        .add_query_params([
            ("state", "s1"),
            ("post_logout_redirect_uri", TEST_AFTER_LOGOUT),
        ])
        .await;

    response.assert_status(StatusCode::FOUND);
    let to = location(&response);
    assert!(to.contains(&format!(
        "/organizations/{ORG}/tenants/{TENANT}/oauth/logout?"
    )));
    assert!(to.contains("state=s1"));
}

/// A browser holding no session asks to sign out through the portal; there
/// is nothing to end, and it is sent back to the portal's registered
/// address with its state.
#[tokio::test]
async fn a_browser_signed_out_already_goes_back_to_the_app() {
    let client = stored_client("Portal", &[GrantType::AuthorizationCode]);
    let id = client.client_id_value().as_str().to_owned();
    let server = serving(client);

    let response = server
        .post(&tenant_path("/oauth/end-session"))
        .json(&json!({
            "client_id": id,
            "post_logout_redirect_uri": TEST_AFTER_LOGOUT,
            "state": "s1"
        }))
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["outcome"], "not_signed_in");
    assert_eq!(body["redirect_to"], format!("{TEST_AFTER_LOGOUT}?state=s1"));
}

/// Ann's session is not ended by a sign-out request that does not name
/// her until she confirms it.
#[tokio::test]
async fn an_unnamed_sign_out_asks_to_confirm_first() {
    let server = server();

    let response = server
        .post(&tenant_path("/oauth/end-session"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({}))
        .await;

    response.assert_status_ok();
    assert_eq!(response.json::<Value>()["outcome"], "confirm");
}

/// Discovery offers `DPoP` with the algorithms a proof may use, and offers
/// nothing bound to a TLS client certificate, which never reaches the API.
#[tokio::test]
async fn discovery_offers_dpop_and_no_certificate_binding() {
    let body: Value = server()
        .get(&tenant_path("/.well-known/openid-configuration"))
        .await
        .json();

    assert_eq!(
        body["dpop_signing_alg_values_supported"],
        json!(["ES256", "RS256", "EdDSA"])
    );
    assert!(
        body.get("tls_client_certificate_bound_access_tokens")
            .is_none()
    );
    for field in [
        "token_endpoint_auth_methods_supported",
        "introspection_endpoint_auth_methods_supported",
        "revocation_endpoint_auth_methods_supported",
    ] {
        assert!(
            !body[field]
                .as_array()
                .unwrap()
                .contains(&json!("tls_client_auth")),
            "{field}"
        );
    }
}

/// The billing machine, its tokens bound as `constraint` says.
fn billing_bound(constraint: SenderConstraint) -> OAuthClient<ResolvedTenant> {
    client_with("Billing", &[GrantType::ClientCredentials], |row| {
        row.settings.sender_constraint = constraint;
    })
}

/// What the token endpoint answers `client`, proving itself in a Basic
/// header, on `server`, with `dpop` as its `DPoP` headers.
async fn machine_token(
    server: &TestServer,
    client: &OAuthClient<ResolvedTenant>,
    dpop: &[&str],
) -> TestResponse {
    let mut request = server
        .post(&tenant_path("/oauth/token"))
        .add_header(AUTHORIZATION, basic(client));
    for proof in dpop {
        request = request.add_header("dpop", (*proof).to_owned());
    }
    request.form(&[("grant_type", "client_credentials")]).await
}

/// A DPoP-required client without proof receives 400 with invalid_dpop_proof.
#[tokio::test]
async fn a_dpop_bound_client_without_a_proof_is_refused() {
    let client = billing_bound(SenderConstraint::DpopRequired);
    let server = serving(client.clone());

    let response = machine_token(&server, &client, &[]).await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&response), "invalid_dpop_proof");
}

/// A certificate-bound client without a certificate receives 400 with invalid_request.
#[tokio::test]
async fn a_certificate_bound_client_is_refused() {
    let client = billing_bound(SenderConstraint::CertificateRequired);
    let server = serving(client.clone());

    let response = machine_token(&server, &client, &[]).await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&response), "invalid_request");
}

/// An invalid DPoP proof returns 400 with invalid_dpop_proof.
#[tokio::test]
async fn a_proof_that_does_not_verify_is_refused() {
    let client = stored_client("Billing", &[GrantType::ClientCredentials]);
    let server = serving(client.clone());

    let response = machine_token(&server, &client, &["forged.dpop.proof"]).await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&response), "invalid_dpop_proof");
}

/// Duplicate DPoP headers return 400 with invalid_dpop_proof.
#[tokio::test]
async fn two_dpop_proofs_are_refused() {
    let client = stored_client("Billing", &[GrantType::ClientCredentials]);
    let server = serving(client.clone());

    let response = machine_token(&server, &client, &["a.b.c", "d.e.f"]).await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&response), "invalid_dpop_proof");
}

/// A client proving its key gets a `DPoP` token, and a resource server
/// introspecting it is told what it is bound to, so the token cannot be
/// taken as a bearer token there either.
#[tokio::test]
async fn a_dpop_bound_token_is_issued_and_introspects_with_its_key() {
    let issuer = discovered_issuer().await;
    let key = JwkThumbprint::new("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I").unwrap();
    let proof = SignedDpopProof {
        thumbprint: key.clone(),
        jti: TokenId::new("proof-1").unwrap(),
        method: "POST".to_owned(),
        url: format!("{issuer}/oauth/token"),
        issued_at: time::OffsetDateTime::now_utc(),
    };
    let client = billing_bound(SenderConstraint::DpopRequired);
    let server = serving_with_proof(client.clone(), proof);

    let issued = machine_token(&server, &client, &["a.dpop.proof"]).await;
    issued.assert_status_ok();
    let issued: Value = issued.json();
    let introspected: Value = server
        .post(&tenant_path("/oauth/introspect"))
        .add_header(AUTHORIZATION, basic(&client))
        .form(&[("token", issued["access_token"].as_str().unwrap())])
        .await
        .json();

    assert_eq!(issued["token_type"], "DPoP");
    assert_eq!(introspected["active"], true);
    assert_eq!(introspected["token_type"], "DPoP");
    assert_eq!(introspected["cnf"]["jkt"], key.as_str());
}

/// Serves a registered client with a verifier accepting the supplied proof.
fn serving_with_proof(client: OAuthClient<ResolvedTenant>, proof: SignedDpopProof) -> TestServer {
    TestServer::new(router(Adapters {
        o_auth_client_store: Arc::new(FakeOAuthClientStore::holding(&test_ctx().tenant(), client)),
        dpop_proof_verifier: Arc::new(FakeDpopVerifier::accepting(proof)),
        ..adapters()
    }))
    .unwrap()
}

/// The test tenant's issuer, as discovery names it.
async fn discovered_issuer() -> String {
    let body: Value = server()
        .get(&tenant_path("/.well-known/openid-configuration"))
        .await
        .json();
    body["issuer"].as_str().unwrap().to_owned()
}

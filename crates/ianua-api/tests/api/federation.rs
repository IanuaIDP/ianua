//! The federation endpoints: connections and what they let a provider do,
//! links, home realm discovery, the SCIM switch, the tenant's SAML apps,
//! its single sign-on and logout services, and the SAML metadata
//! documents, and what they answer.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::http::header::{CONTENT_TYPE, LOCATION};
use axum_test::TestServer;
use ianua_api::test_support::{ORG, TENANT, TENANT_USER, adapters, router};
use ianua_app::ports::federation::HeldSamlSignIn;
use ianua_app::test_support::acting::{FakeTenantAuthorities, Refusal};
use ianua_app::test_support::federation::{FakeHeldSamlSignIns, posted_message};
use ianua_app::test_support::test_ctx;
use ianua_assembly::deps::Adapters;
use ianua_domain::types::SamlArrivalId;
use serde_json::{Value, json};

/// The path under the test tenant's federation routes.
fn federation_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/federation{rest}")
}

/// The path under the test tenant's identity provider routes.
fn saml_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/saml{rest}")
}

/// A server over the default test adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// A request body for a SAML connection to Okta.
fn saml_connection() -> Value {
    json!({
        "provider_name": "Okta",
        "config": {
            "Saml": {
                "entity_id": "https://idp.acme.com",
                "sso_url": "https://idp.acme.com/sso",
                "certificate": "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----",
                "name_id_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
            }
        }
    })
}

/// Creates the Okta SAML connection on `server` and returns its id.
async fn created_connection(server: &TestServer) -> String {
    let created = server
        .post(&federation_path("/connections"))
        .authorization_bearer(TENANT_USER)
        .json(&saml_connection())
        .await;
    created.assert_status(StatusCode::CREATED);
    created.json::<Value>()["id"].as_str().unwrap().to_owned()
}

/// Where a redirect answer sends the browser.
fn location(response: &axum_test::TestResponse) -> String {
    response
        .headers()
        .get(LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

/// An admin creates a SAML connection and reads it back in the shape the
/// dashboard lists.
#[tokio::test]
async fn a_created_connection_reads_back() {
    let server = server();
    let id = created_connection(&server).await;

    let response = server
        .get(&federation_path(&format!("/connections/{id}")))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["provider_name"], "Okta");
    assert_eq!(body["protocol"], "Saml");
    assert_eq!(body["status"], "Active");
    assert_eq!(body["jit_provisioning"], false);
    assert_eq!(body["allowed_domains"], json!([]));
    assert_eq!(body["email_trust"], "Unverified");
    assert_eq!(body["saml"]["requires_encrypted_assertions"], false);
}

/// A provider name that is blank is refused.
#[tokio::test]
async fn a_blank_provider_name_is_refused() {
    let server = server();
    let mut body = saml_connection();
    body["provider_name"] = json!("  ");

    let response = server
        .post(&federation_path("/connections"))
        .authorization_bearer(TENANT_USER)
        .json(&body)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A next certificate that is the current one is refused: rolling over to
/// it would change nothing.
#[tokio::test]
async fn a_next_certificate_equal_to_the_current_one_is_refused() {
    let server = server();
    let mut body = saml_connection();
    body["config"]["Saml"]["next_certificate"] = body["config"]["Saml"]["certificate"].clone();

    let response = server
        .post(&federation_path("/connections"))
        .authorization_bearer(TENANT_USER)
        .json(&body)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// The settings the old update ignored are changed and read back.
#[tokio::test]
async fn trust_and_profile_mapping_are_changed_through_the_update() {
    let server = server();
    let id = created_connection(&server).await;

    server
        .patch(&federation_path(&format!("/connections/{id}")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "email_trust": "Authoritative",
            "attribute_mapping": {"name": "display_name"}
        }))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let body: Value = server
        .get(&federation_path(&format!("/connections/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(body["email_trust"], "Authoritative");
    assert_eq!(body["attribute_mapping"], json!({"name": "display_name"}));
}

/// A claim may fill only a profile field; the address is never one.
#[tokio::test]
async fn mapping_a_claim_to_the_address_is_refused() {
    let server = server();
    let id = created_connection(&server).await;

    let response = server
        .patch(&federation_path(&format!("/connections/{id}")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"attribute_mapping": {"mail": "email"}}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Listing federation connections without tenant authority returns 403.
#[tokio::test]
async fn a_caller_the_app_refuses_is_forbidden() {
    let server = TestServer::new(router(Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&federation_path("/connections"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// SCIM switched on for the first time hands out its token once; switched
/// off, it answers nothing.
#[tokio::test]
async fn scim_is_switched_on_with_a_token_and_off_again() {
    let server = server();

    let enabled = server
        .post(&federation_path("/scim"))
        .authorization_bearer(TENANT_USER)
        .await;
    enabled.assert_status(StatusCode::CREATED);
    assert!(enabled.json::<Value>()["bearer_token"].is_string());

    server
        .delete(&federation_path("/scim"))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::NO_CONTENT);
}

/// The SCIM card reads the endpoint's status in the shape it expects:
/// never set up, then on with its settings, and never the token.
#[tokio::test]
async fn the_scim_status_reads_back_in_the_dashboards_shape() {
    let server = server();
    let before: Value = server
        .get(&federation_path("/scim"))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(before["configured"], false);
    assert_eq!(
        before["scim_path"],
        format!("/scim/v2/organizations/{ORG}/tenants/{TENANT}")
    );

    server
        .post(&federation_path("/scim"))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::CREATED);
    let after: Value = server
        .get(&federation_path("/scim"))
        .authorization_bearer(TENANT_USER)
        .await
        .json();

    assert_eq!(after["configured"], true);
    assert_eq!(after["enabled"], true);
    assert!(after["settings"]["auto_activate"].is_boolean());
    assert!(after.get("bearer_token").is_none());
}

/// An identity provider fetches a connection's service provider metadata
/// without signing in, as SAML metadata.
#[tokio::test]
async fn a_connections_service_provider_metadata_is_public_xml() {
    let server = server();
    let id = created_connection(&server).await;

    let response = server
        .get(&federation_path(&format!(
            "/connections/{id}/saml/metadata"
        )))
        .await;

    response.assert_status_ok();
    assert_eq!(
        response.headers().get(CONTENT_TYPE).unwrap(),
        "application/samlmetadata+xml"
    );
}

/// Metadata for a connection that does not exist is not found.
#[tokio::test]
async fn metadata_of_an_unknown_connection_is_not_found() {
    let response = server()
        .get(&federation_path(&format!(
            "/connections/{}/saml/metadata",
            uuid::Uuid::now_v7()
        )))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// Requiring encrypted assertions with only half of a key pair is refused
/// before any key is kept.
#[tokio::test]
async fn half_a_key_pair_is_refused() {
    let server = server();
    let id = created_connection(&server).await;

    let response = server
        .put(&federation_path(&format!(
            "/connections/{id}/encrypted-assertions"
        )))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"private_key": "-----BEGIN PRIVATE KEY-----"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Rolling over a connection with no next certificate is a conflict.
#[tokio::test]
async fn rolling_over_without_a_next_certificate_is_a_conflict() {
    let server = server();
    let id = created_connection(&server).await;

    let response = server
        .post(&federation_path(&format!(
            "/connections/{id}/certificate/roll-over"
        )))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::CONFLICT);
}

/// A group mapping with no rule is refused.
#[tokio::test]
async fn a_group_mapping_without_rules_is_refused() {
    let server = server();
    let id = created_connection(&server).await;

    let response = server
        .put(&federation_path(&format!(
            "/connections/{id}/group-mapping"
        )))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"claim": "groups", "rules": []}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// An address whose domain no connection routes signs in here.
#[tokio::test]
async fn an_unrouted_address_signs_in_here() {
    let response = server()
        .post(&federation_path("/discover"))
        .json(&json!({"email": "ann@example.com"}))
        .await;

    response.assert_status_ok();
    assert_eq!(response.json::<Value>()["routed"], false);
}

/// Something that is not an address is refused.
#[tokio::test]
async fn discovering_a_non_address_is_refused() {
    let response = server()
        .post(&federation_path("/discover"))
        .json(&json!({"email": "not an address"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A person with no linked provider lists none.
#[tokio::test]
async fn a_person_without_links_lists_none() {
    let response = server()
        .get(&federation_path("/links"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    response.assert_json(&json!({"links": []}));
}

/// Unlinking an account that was never linked through the connection is
/// not found.
#[tokio::test]
async fn unlinking_an_account_never_linked_is_not_found() {
    let server = server();

    let response = server
        .delete(&federation_path(&format!(
            "/connections/{}/link",
            uuid::Uuid::now_v7()
        )))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// A proof in a form the API does not know is refused.
#[tokio::test]
async fn an_unknown_proof_method_is_refused() {
    let server = server();

    let response = server
        .post(&federation_path(&format!(
            "/connections/{}/link/reconfirm",
            uuid::Uuid::now_v7()
        )))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"proof": {"method": "carrier_pigeon"}}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A request body for a SAML app.
fn saml_app() -> Value {
    json!({
        "name": "Salesforce",
        "entity_id": "https://acme.my.salesforce.com",
        "acs_urls": ["https://acme.my.salesforce.com/saml"]
    })
}

/// An admin adds a SAML app and reads it back with the defaults it was
/// given.
#[tokio::test]
async fn a_saml_app_is_added_and_read_back() {
    let server = server();
    let created = server
        .post(&saml_path("/apps"))
        .authorization_bearer(TENANT_USER)
        .json(&saml_app())
        .await;
    created.assert_status(StatusCode::CREATED);
    let id = created.json::<Value>()["id"].as_str().unwrap().to_owned();

    let response = server
        .get(&saml_path(&format!("/apps/{id}")))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["status"], "Active");
    assert_eq!(body["name_id_format"], "persistent");
    assert_eq!(body["signing"], "assertion");
    assert_eq!(body["attributes"][0]["name"], "email");
    assert_eq!(body["encryption_certificate"], Value::Null);
}

/// An app with nowhere to post its assertions is refused.
#[tokio::test]
async fn a_saml_app_without_an_assertion_address_is_refused() {
    let mut body = saml_app();
    body["acs_urls"] = json!([]);

    let response = server()
        .post(&saml_path("/apps"))
        .authorization_bearer(TENANT_USER)
        .json(&body)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// An app that does not exist is not found.
#[tokio::test]
async fn an_unknown_saml_app_is_not_found() {
    let response = server()
        .get(&saml_path(&format!("/apps/{}", uuid::Uuid::now_v7())))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// An app's sign-in request by redirect is held on the server and goes on
/// to the dashboard with the query exactly as it arrived and the id it is
/// held by, never with when it arrived.
#[tokio::test]
async fn a_redirected_sign_in_request_goes_on_to_the_dashboard() {
    let held = Arc::new(FakeHeldSamlSignIns::empty());
    let server = server_with(Adapters {
        held_saml_sign_in_store: held.clone(),
        ..adapters()
    });

    let response = server
        .get(&saml_path("/sso?SAMLRequest=abc%2B&RelayState=back"))
        .await;

    response.assert_status(StatusCode::FOUND);
    let to = location(&response);
    assert!(to.contains(&format!("/organizations/{ORG}/tenants/{TENANT}/saml/sso?")));
    assert!(to.contains("binding=redirect"));
    assert!(to.contains("query=SAMLRequest%3Dabc%252B%26RelayState%3Dback"));
    assert!(!to.contains("asked_at="));
    let kept = held.all();
    assert_eq!(kept.len(), 1);
    assert!(to.contains(&format!("request={}", kept[0].id)));
    assert_eq!(kept[0].relay_state.as_deref(), Some("back"));
}

/// A server over `adapters`.
fn server_with(adapters: Adapters) -> TestServer {
    TestServer::new(router(adapters)).unwrap()
}

/// The answer to `body` posted by the test tenant user on `server`.
async fn answered(server: &TestServer, body: Value) -> axum_test::TestResponse {
    server
        .post(&saml_path("/sso/answer"))
        .authorization_bearer(TENANT_USER)
        .json(&body)
        .await
}

/// Salesforce's request, held in the test tenant as `id`, arrived `ago`.
fn held_request(id: uuid::Uuid, ago: time::Duration) -> FakeHeldSamlSignIns {
    FakeHeldSamlSignIns::holding(
        test_ctx().tenant_id(),
        HeldSamlSignIn {
            id: SamlArrivalId::from_uuid(id),
            message: posted_message(),
            relay_state: None,
            arrived_at: time::OffsetDateTime::now_utc() - ago,
        },
    )
}

/// A request the server holds is answered from what it holds: it reaches
/// the app's checks, which refuse it here since the tenant has no such app.
#[tokio::test]
async fn a_held_request_is_read_back_from_the_server() {
    let id = uuid::Uuid::now_v7();
    let server = server_with(Adapters {
        held_saml_sign_in_store: Arc::new(held_request(id, time::Duration::minutes(1))),
        ..adapters()
    });

    let response = answered(&server, json!({"request": id})).await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A SAML answer without a request identifier returns 422.
#[tokio::test]
async fn an_answer_without_a_request_id_is_refused() {
    let response = answered(&server(), json!({})).await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A malformed SAML request identifier returns 422.
#[tokio::test]
async fn a_tampered_request_id_is_refused() {
    let response = answered(&server(), json!({"request": "not-an-id"})).await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Answering an unknown SAML request returns 410.
#[tokio::test]
async fn an_unknown_request_id_is_refused() {
    let response = answered(&server(), json!({"request": uuid::Uuid::now_v7()})).await;

    response.assert_status(StatusCode::GONE);
}

/// An eleven-minute-old held request returns 410 even when the body
/// supplies its own arrival time.
#[tokio::test]
async fn an_expired_request_id_is_refused() {
    let id = uuid::Uuid::now_v7();
    let server = server_with(Adapters {
        held_saml_sign_in_store: Arc::new(held_request(id, time::Duration::minutes(11))),
        ..adapters()
    });

    let response = answered(&server, json!({"request": id, "asked_at": 0})).await;

    response.assert_status(StatusCode::GONE);
}

/// An app's sign-in request posted in a form goes on to the dashboard with
/// its message and relay state.
#[tokio::test]
async fn a_posted_sign_in_request_goes_on_to_the_dashboard() {
    let response = server()
        .post(&saml_path("/sso"))
        .form(&[("SAMLRequest", "abc"), ("RelayState", "back")])
        .await;

    response.assert_status(StatusCode::FOUND);
    let to = location(&response);
    assert!(to.contains("binding=post"));
    assert!(to.contains("message=abc"));
    assert!(to.contains("relay_state=back"));
}

/// A redirect carrying half a signature is refused rather than taken as
/// unsigned.
#[tokio::test]
async fn half_a_redirect_signature_is_refused() {
    let response = server()
        .get(&saml_path("/sso?SAMLRequest=abc&SigAlg=rsa-sha256"))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A sign-in started at a link goes on to the dashboard's page for the
/// app.
#[tokio::test]
async fn a_sign_in_started_here_goes_on_to_the_apps_page() {
    let app = uuid::Uuid::now_v7();

    let response = server()
        .get(&saml_path(&format!("/sso/initiate?app_id={app}")))
        .await;

    response.assert_status(StatusCode::FOUND);
    assert!(location(&response).contains(&format!("/saml/apps/{app}/sign-in")));
}

/// Answering a SAML sign-in without authentication returns 401.
#[tokio::test]
async fn answering_a_sign_in_needs_a_session() {
    let response = server()
        .post(&saml_path("/sso/answer"))
        .json(&json!({"request": uuid::Uuid::now_v7()}))
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// A SAMLResponse submitted as a logout request returns 422.
#[tokio::test]
async fn an_answer_is_not_answered_as_a_request() {
    let response = server()
        .post(&saml_path("/slo/answer"))
        .json(&json!({"binding": "redirect", "query": "SAMLResponse=abc"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// An app's logout request goes on to the dashboard, which holds the
/// person's session.
#[tokio::test]
async fn an_apps_logout_request_goes_on_to_the_dashboard() {
    let response = server().get(&saml_path("/slo?SAMLRequest=abc")).await;

    response.assert_status(StatusCode::FOUND);
    assert!(
        location(&response).contains(&format!("/organizations/{ORG}/tenants/{TENANT}/saml/slo?"))
    );
}

/// A provider's logout request goes on to the dashboard page of its
/// connection.
#[tokio::test]
async fn a_providers_logout_request_goes_on_to_its_connections_page() {
    let id = uuid::Uuid::now_v7();

    let response = server()
        .get(&federation_path(&format!(
            "/connections/{id}/saml/slo?SAMLRequest=abc"
        )))
        .await;

    response.assert_status(StatusCode::FOUND);
    assert!(location(&response).contains(&format!("/federation/connections/{id}/saml/slo?")));
}

/// An unsolicited SAML logout response produces a client error.
#[tokio::test]
async fn an_unsolicited_logout_answer_is_refused() {
    let response = server().get(&saml_path("/slo?SAMLResponse=abc")).await;

    assert!(response.status_code().is_client_error());
}

/// Nobody signed in has a session to log out of everywhere.
#[tokio::test]
async fn starting_single_logout_needs_a_session() {
    let response = server().post(&saml_path("/slo/start")).await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

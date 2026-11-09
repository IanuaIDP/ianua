//! The routing endpoints: routes and their conditions, services with their
//! sign-in and upstream TLS, stream routes and their access, egress
//! policies, connectors and their enrollment, and route traffic, and the
//! shape each answers in.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, TENANT, TENANT_USER, adapters, router};
use ianua_app::test_support::RejectingLimitEnforcer;
use ianua_app::test_support::acting::{FakeTenantAuthorities, Refusal};
use ianua_app::test_support::domain::{TEST_CERTIFICATE_PEM, TEST_PRIVATE_KEY_PEM};
use ianua_app::test_support::routing::unpinned_upstream;
use serde_json::{Value, json};

/// The test tenant's address, followed by `rest`.
fn tenant_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}{rest}")
}

/// A server over the default fake adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// The id a creating request answered with.
async fn created_id(server: &TestServer, path: &str, body: Value) -> String {
    let response = server
        .post(&tenant_path(path))
        .authorization_bearer(TENANT_USER)
        .json(&body)
        .await;
    response.assert_status(StatusCode::CREATED);
    response.json::<Value>()["id"].as_str().unwrap().to_owned()
}

/// A pipeline and a service for a route to name, as Ann sets them up first.
async fn pipeline_and_service(server: &TestServer) -> (String, String) {
    let pipeline = created_id(server, "/pipelines", json!({"name": "edge"})).await;
    let upstream = serde_json::to_value(unpinned_upstream("https://backend.example.com")).unwrap();
    let service = created_id(
        server,
        "/services",
        json!({"name": "backend", "upstream": upstream}),
    )
    .await;
    (pipeline, service)
}

/// A public route for `/api/orders/*` through this pipeline to this service.
fn route_body(pipeline: &str, service: &str) -> Value {
    json!({
        "name": "orders",
        "path_pattern": "/api/orders/*",
        "methods": ["Get", "Post"],
        "service_id": service,
        "policy": "Public",
        "path_rewrite": {"mode": "strip_prefix"},
        "pipeline_id": pipeline
    })
}

/// Ann creates a route and reads it back in the shape the dashboard reads:
/// the rewrite tagged by `mode`, no host restriction as an empty list, the
/// data class it defaulted to and its status by name.
#[tokio::test]
async fn a_tenant_user_creates_a_route_and_reads_it_back() {
    let server = server();
    let (pipeline, service) = pipeline_and_service(&server).await;

    let id = created_id(&server, "/routes", route_body(&pipeline, &service)).await;
    let response = server
        .get(&tenant_path(&format!("/routes/{id}")))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let route: Value = response.json();
    assert_eq!(route["name"], "orders");
    assert_eq!(route["methods"], json!(["Get", "Post"]));
    assert_eq!(route["policy"], "Public");
    assert_eq!(route["path_rewrite"], json!({"mode": "strip_prefix"}));
    assert_eq!(route["hosts"], json!([]));
    assert_eq!(route["status"], "Active");
    assert_eq!(route["data_class"], "Internal");
    assert_eq!(route["priority"], 100);
    assert_eq!(route["pipeline_id"], pipeline);
    assert_eq!(route["service_id"], service);
}

/// The listing is a page, and a status filter narrows it.
#[tokio::test]
async fn the_route_listing_is_a_page_filtered_by_status() {
    let server = server();
    let (pipeline, service) = pipeline_and_service(&server).await;
    created_id(&server, "/routes", route_body(&pipeline, &service)).await;

    let active = server
        .get(&tenant_path("/routes?status=Active"))
        .authorization_bearer(TENANT_USER)
        .await;
    let disabled = server
        .get(&tenant_path("/routes?status=Disabled"))
        .authorization_bearer(TENANT_USER)
        .await;

    assert_eq!(
        active.json::<Value>()["items"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(
        disabled.json::<Value>()["items"].as_array().map(Vec::len),
        Some(0)
    );
}

/// A disabled route can be deleted; an active one has to be drained first.
#[tokio::test]
async fn a_route_is_disabled_before_it_is_deleted() {
    let server = server();
    let (pipeline, service) = pipeline_and_service(&server).await;
    let id = created_id(&server, "/routes", route_body(&pipeline, &service)).await;

    server
        .delete(&tenant_path(&format!("/routes/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    server
        .post(&tenant_path(&format!("/routes/{id}/disable")))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::NO_CONTENT);
    server
        .delete(&tenant_path(&format!("/routes/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::NO_CONTENT);
}

/// A host that is not a domain name is refused before anything is stored.
#[tokio::test]
async fn a_route_on_a_host_that_is_not_a_domain_name_is_refused() {
    let server = server();
    let (pipeline, service) = pipeline_and_service(&server).await;
    let mut body = route_body(&pipeline, &service);
    body["hosts"] = json!(["not a host"]);

    let response = server
        .post(&tenant_path("/routes"))
        .authorization_bearer(TENANT_USER)
        .json(&body)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Listing routes without tenant authority returns 403.
#[tokio::test]
async fn a_caller_the_app_refuses_is_forbidden() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&tenant_path("/routes"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A service reads back with its upstream, its default probe settings and
/// no sign-in.
#[tokio::test]
async fn a_service_reads_back_with_its_probe_settings() {
    let server = server();
    let (_, service) = pipeline_and_service(&server).await;

    let response = server
        .get(&tenant_path(&format!("/services/{service}")))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["name"], "backend");
    assert!(
        body["upstream"]["url"]
            .as_str()
            .unwrap()
            .starts_with("https://backend.example.com")
    );
    assert_eq!(body["health_check"]["enabled"], true);
    assert_eq!(body["app_sign_in"], Value::Null);
    assert_eq!(body["status"], "Active");
}

/// Sending no sign-in turns it off, which a service without one accepts.
#[tokio::test]
async fn an_empty_app_sign_in_turns_it_off() {
    let server = server();
    let (_, service) = pipeline_and_service(&server).await;

    let response = server
        .put(&tenant_path(&format!("/services/{service}/app-sign-in")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({}))
        .await;

    response.assert_status(StatusCode::NO_CONTENT);
}

/// Ann opens a port; it reads back answering every handshake, with the
/// platform's timeouts and an even backend weight.
#[tokio::test]
async fn a_stream_route_reads_back_with_its_defaults() {
    let server = server();
    let id = created_id(
        &server,
        "/stream-routes",
        json!({
            "name": "postgres",
            "protocol": "tcp",
            "listen_port": 15432,
            "policy": "public",
            "backends": [{"host": "db.example.com", "port": 5432}]
        }),
    )
    .await;

    let response = server
        .get(&tenant_path(&format!("/stream-routes/{id}")))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let route: Value = response.json();
    assert_eq!(route["protocol"], "tcp");
    assert_eq!(route["listen_port"], 15432);
    assert_eq!(route["sni"], json!({"mode": "any"}));
    assert_eq!(route["backends"][0]["weight"], 1);
    assert_eq!(
        route["timeouts"],
        json!({"connect_secs": 10, "idle_secs": 3600})
    );
    assert_eq!(route["status"], "Active");
}

/// A port below 1024 belongs to the system and is refused.
#[tokio::test]
async fn a_privileged_port_is_refused() {
    let server = server();

    let response = server
        .post(&tenant_path("/stream-routes"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "name": "ssh",
            "protocol": "tcp",
            "listen_port": 22,
            "policy": "public",
            "backends": [{"host": "db.example.com", "port": 22}]
        }))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Ann gives a service a way out; the policy reads back with its
/// destinations, the data ceiling it defaulted to and who made it.
#[tokio::test]
async fn an_egress_policy_reads_back_with_its_maker() {
    let server = server();

    let response = server
        .post(&tenant_path("/egress-policies"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "name": "fetcher",
            "service": "spiffe://ianua.test/ns/svc/sa/fetcher",
            "destinations": [{"host": "api.github.com", "port": 443}]
        }))
        .await;

    response.assert_status(StatusCode::CREATED);
    let policy: Value = response.json();
    assert_eq!(
        policy["destinations"],
        json!([{"host": "api.github.com", "port": 443}])
    );
    assert_eq!(policy["max_data_class"], "Internal");
    assert_eq!(policy["created_by"]["kind"], "user");
    let listed = server
        .get(&tenant_path("/egress-policies"))
        .authorization_bearer(TENANT_USER)
        .await;
    assert_eq!(listed.json::<Value>().as_array().unwrap().len(), 1);
}

/// A tenant with no traffic gets the window it asked about and no rows.
#[tokio::test]
async fn route_traffic_answers_its_window() {
    let server = server();

    let response = server
        .get(&tenant_path(
            "/metrics/routes?since=2026-06-01T00:00:00Z&until=2026-06-29T00:00:00Z",
        ))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["items"], json!([]));
    assert!(body["window"]["start"].is_string());
}

/// Ann pins a canary to a header: the route reads back with the condition,
/// and an empty list matches every request again.
#[tokio::test]
async fn route_conditions_are_set_and_cleared() {
    let server = server();
    let (pipeline, service) = pipeline_and_service(&server).await;
    let id = created_id(&server, "/routes", route_body(&pipeline, &service)).await;
    let canary = json!([{"subject": {"header": "x-canary"}, "value": {"exact": "on"}}]);

    server
        .put(&tenant_path(&format!("/routes/{id}/conditions")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"conditions": canary}))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    let pinned: Value = server
        .get(&tenant_path(&format!("/routes/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    server
        .put(&tenant_path(&format!("/routes/{id}/conditions")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"conditions": []}))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    let cleared: Value = server
        .get(&tenant_path(&format!("/routes/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .json();

    assert_eq!(pinned["conditions"], canary);
    assert_eq!(cleared["conditions"], json!([]));
}

/// A header named by two conditions is refused before anything is saved.
#[tokio::test]
async fn a_header_named_twice_in_the_conditions_is_refused() {
    let server = server();
    let (pipeline, service) = pipeline_and_service(&server).await;
    let id = created_id(&server, "/routes", route_body(&pipeline, &service)).await;

    let response = server
        .put(&tenant_path(&format!("/routes/{id}/conditions")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"conditions": [
            {"subject": {"header": "x-canary"}, "value": "present"},
            {"subject": {"header": "x-canary"}, "value": {"exact": "on"}}
        ]}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// The payroll service configured with a private authority and client identity.
fn payroll_service_with_tls() -> Value {
    let upstream = serde_json::to_value(unpinned_upstream("https://backend.example.com")).unwrap();
    json!({
        "name": "payroll",
        "upstream": upstream,
        "tls": {
            "ca_certificates": TEST_CERTIFICATE_PEM,
            "client_certificate": {
                "certificate": TEST_CERTIFICATE_PEM,
                "private_key": TEST_PRIVATE_KEY_PEM
            },
            "server_name": "payroll.corp.internal"
        }
    })
}

/// Ann reaches a backend on a private PKI: the service reads back with its
/// CA, server name and client certificate, never the key, and removing the
/// TLS trusts the public roots again.
#[tokio::test]
async fn a_services_upstream_tls_reads_back_without_its_key() {
    let server = server();
    let id = created_id(&server, "/services", payroll_service_with_tls()).await;

    let with_tls = server
        .get(&tenant_path(&format!("/services/{id}")))
        .authorization_bearer(TENANT_USER)
        .await;
    server
        .delete(&tenant_path(&format!("/services/{id}/tls")))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::NO_CONTENT);
    let without: Value = server
        .get(&tenant_path(&format!("/services/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .json();

    with_tls.assert_status_ok();
    let body: Value = with_tls.json();
    assert_eq!(body["tls"]["ca_certificates"], TEST_CERTIFICATE_PEM);
    assert_eq!(body["tls"]["client_certificate"], TEST_CERTIFICATE_PEM);
    assert_eq!(body["tls"]["server_name"], "payroll.corp.internal");
    assert!(body["upstream"].get("tls").is_none());
    assert!(
        !body.to_string().contains("PRIVATE KEY"),
        "the client key is never answered"
    );
    assert_eq!(without["tls"], Value::Null);
}

/// Setting TLS on an existing service is saved and read back.
#[tokio::test]
async fn upstream_tls_is_set_on_an_existing_service() {
    let server = server();
    let (_, service) = pipeline_and_service(&server).await;

    server
        .put(&tenant_path(&format!("/services/{service}/tls")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"tls": {"server_name": "api.corp.internal"}}))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    let body: Value = server
        .get(&tenant_path(&format!("/services/{service}")))
        .authorization_bearer(TENANT_USER)
        .await
        .json();

    assert_eq!(body["tls"]["server_name"], "api.corp.internal");
    assert_eq!(body["tls"]["ca_certificates"], Value::Null);
}

/// A wildcard upstream TLS server name returns 422.
#[tokio::test]
async fn a_wildcard_upstream_server_name_is_refused() {
    let server = server();
    let (_, service) = pipeline_and_service(&server).await;

    let response = server
        .put(&tenant_path(&format!("/services/{service}/tls")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"tls": {"server_name": "*.corp.internal"}}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Ann renames an egress policy; its destinations stay as they were.
#[tokio::test]
async fn an_egress_policy_is_renamed() {
    let server = server();
    let id = created_id(
        &server,
        "/egress-policies",
        json!({
            "name": "fetcher",
            "service": "spiffe://ianua.test/ns/svc/sa/fetcher",
            "destinations": [{"host": "api.github.com", "port": 443}]
        }),
    )
    .await;

    server
        .patch(&tenant_path(&format!("/egress-policies/{id}")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": "partner-fetcher"}))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    let policy: Value = server
        .get(&tenant_path(&format!("/egress-policies/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .json();

    assert_eq!(policy["name"], "partner-fetcher");
    assert_eq!(
        policy["destinations"],
        json!([{"host": "api.github.com", "port": 443}])
    );
}

/// Ann opens a database port to people signed in through the tunnel; it
/// reads back holding them to the policy she named.
#[tokio::test]
async fn a_tunnel_stream_route_reads_back_with_its_access() {
    let server = server();
    let id = created_id(
        &server,
        "/stream-routes",
        json!({
            "name": "postgres",
            "protocol": "tcp",
            "listen_port": 15433,
            "policy": "tunnel",
            "access": {"people": "Authenticated"},
            "backends": [{"host": "db.example.com", "port": 5432}]
        }),
    )
    .await;

    let route: Value = server
        .get(&tenant_path(&format!("/stream-routes/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .json();

    assert_eq!(route["policy"], "tunnel");
    assert_eq!(route["access"], json!({"people": "Authenticated"}));
}

/// A public stream route with authenticated-person access returns 422.
#[tokio::test]
async fn a_public_port_tied_to_people_is_refused() {
    let server = server();

    let response = server
        .post(&tenant_path("/stream-routes"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "name": "postgres",
            "protocol": "tcp",
            "listen_port": 15434,
            "policy": "public",
            "access": {"people": "Authenticated"},
            "backends": [{"host": "db.example.com", "port": 5432}]
        }))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A signing request the test authority reads as naming the key `key`.
fn signing_request(key: u8) -> String {
    format!("-----BEGIN CERTIFICATE REQUEST-----\nkey{key}\n-----END CERTIFICATE REQUEST-----\n")
}

/// The connector enrollment address of the test tenant.
fn enroll_path() -> String {
    tenant_path("/connectors/enroll")
}

/// Adds the payroll connector and answers its id and code.
async fn created_connector(server: &TestServer) -> (String, Value) {
    let created = server
        .post(&tenant_path("/connectors"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": "payroll", "scope": {"domains": ["*.payroll.corp.internal"]}}))
        .await;
    created.assert_status(StatusCode::CREATED);
    let created: Value = created.json();
    (
        created["id"].as_str().unwrap().to_owned(),
        created["enrollment_code"].clone(),
    )
}

/// Ann adds a connector and is shown its code once; the agent enrolls with
/// it and a signing request for its key, gets a certificate with the
/// authority to check the gateway by, and the connector reads back
/// enrolled with that key.
#[tokio::test]
async fn a_connector_enrolls_with_its_code_and_key() {
    let server = server();
    let (id, code) = created_connector(&server).await;

    let enrolled = server
        .post(&enroll_path())
        .json(&json!({"code": code, "csr": signing_request(7)}))
        .await;
    let connector: Value = server
        .get(&tenant_path(&format!("/connectors/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .json();

    enrolled.assert_status_ok();
    let answer: Value = enrolled.json();
    assert_eq!(answer["id"], id);
    assert_enrollment_certificate(&answer);
    assert_eq!(connector["status"], "Active");
    assert_eq!(connector["enrollment"]["state"], "enrolled");
    assert_eq!(
        connector["enrollment"]["key"],
        format!("sha256:{}", "07".repeat(32))
    );
    assert!(connector["last_seen_at"].is_null());
    assert!(
        !connector.to_string().contains("enroll-code"),
        "the code is shown once, at creation"
    );
}

/// Checks enrollment returns the client certificate, its authority and renewal time.
fn assert_enrollment_certificate(answer: &Value) {
    assert!(
        answer["certificate"]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE")
    );
    assert!(
        answer["authority"]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE")
    );
    assert!(answer["renew_after"].is_string());
}

/// An unknown connector enrollment code returns 403.
#[tokio::test]
async fn an_unknown_enrollment_code_is_forbidden() {
    let server = server();

    let response = server
        .post(&enroll_path())
        .json(&json!({"code": "guessed", "csr": signing_request(7)}))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// Reusing an enrollment code for another key returns 403 without a certificate.
#[tokio::test]
async fn a_reused_enrollment_code_is_forbidden() {
    let server = server();
    let (_, code) = created_connector(&server).await;
    server
        .post(&enroll_path())
        .json(&json!({"code": code, "csr": signing_request(7)}))
        .await
        .assert_status_ok();

    let again = server
        .post(&enroll_path())
        .json(&json!({"code": code, "csr": signing_request(9)}))
        .await;

    again.assert_status(StatusCode::FORBIDDEN);
    assert!(again.json::<Value>().get("certificate").is_none());
}

/// Missing and non-PEM certificate signing requests both return 422 at enrollment.
#[tokio::test]
async fn an_enrollment_without_a_signing_request_is_refused() {
    let server = server();
    let (_, code) = created_connector(&server).await;

    let missing = server
        .post(&enroll_path())
        .json(&json!({"code": code}))
        .await;
    let not_pem = server
        .post(&enroll_path())
        .json(&json!({"code": code, "csr": "hello"}))
        .await;

    assert_eq!(missing.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(not_pem.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
}

/// The agent asks for its next certificate with a request for its own
/// key and gets one; a request for another key is refused.
#[tokio::test]
async fn a_connector_renews_only_for_its_own_key() {
    let server = server();
    let (id, code) = created_connector(&server).await;
    server
        .post(&enroll_path())
        .json(&json!({"code": code, "csr": signing_request(7)}))
        .await
        .assert_status_ok();
    let renew = tenant_path(&format!("/connectors/{id}/renew"));

    let own = server
        .post(&renew)
        .json(&json!({"csr": signing_request(7)}))
        .await;
    let other = server
        .post(&renew)
        .json(&json!({"csr": signing_request(9)}))
        .await;

    own.assert_status_ok();
    assert!(own.json::<Value>()["certificate"].is_string());
    other.assert_status(StatusCode::FORBIDDEN);
}

/// A successfully enrolled connector receives 403 on renewal after revocation.
#[tokio::test]
async fn a_revoked_connector_is_not_renewed() {
    let server = server();
    let (id, code) = created_connector(&server).await;
    server
        .post(&enroll_path())
        .json(&json!({"code": code, "csr": signing_request(7)}))
        .await
        .assert_status_ok();
    server
        .post(&tenant_path(&format!("/connectors/{id}/revoke")))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let renewed = server
        .post(&tenant_path(&format!("/connectors/{id}/renew")))
        .json(&json!({"csr": signing_request(7)}))
        .await;

    renewed.assert_status(StatusCode::FORBIDDEN);
}

/// A connector is revoked before it is deleted, and is gone from the list
/// afterwards.
#[tokio::test]
async fn a_connector_is_revoked_before_it_is_deleted() {
    let server = server();
    let id = created_id(
        &server,
        "/connectors",
        json!({"name": "payroll", "scope": {"networks": ["10.20.0.0/16"]}}),
    )
    .await;

    server
        .delete(&tenant_path(&format!("/connectors/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    server
        .post(&tenant_path(&format!("/connectors/{id}/revoke")))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::NO_CONTENT);
    server
        .delete(&tenant_path(&format!("/connectors/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::NO_CONTENT);
    let listed: Value = server
        .get(&tenant_path("/connectors"))
        .authorization_bearer(TENANT_USER)
        .await
        .json();

    assert_eq!(listed, json!([]));
}

/// A plan refusal makes connector creation return 403 without an enrollment code.
#[tokio::test]
async fn a_connector_past_the_plan_limit_is_refused() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        limit_enforcer: Arc::new(RejectingLimitEnforcer),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .post(&tenant_path("/connectors"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": "payroll", "scope": {"networks": ["10.20.0.0/16"]}}))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
    assert!(response.json::<Value>().get("enrollment_code").is_none());
}

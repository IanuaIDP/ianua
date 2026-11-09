//! The gateway configuration endpoints: export, apply and OpenAPI drafts,
//! in JSON or YAML.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::http::header::{ACCEPT, CONTENT_TYPE};
use axum_test::TestServer;
use ianua_api::test_support::{ORG, TENANT, TENANT_USER, adapters, router};
use ianua_app::test_support::acting::{FakeTenantAuthorities, Refusal};
use ianua_app::test_support::routing::unpinned_upstream;
use serde_json::{Value, json};

/// The path under the test tenant's gateway configuration.
fn config(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/gateway/config{rest}")
}

/// A server over the default test adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// A document declaring one service, which the tenant does not have yet.
fn one_service(plan: &str) -> Value {
    let upstream = serde_json::to_value(unpinned_upstream("https://backend.example.com")).unwrap();
    json!({
        "config": {"services": [{"name": "backend", "upstream": upstream}]},
        "plan": plan
    })
}

/// A tenant with nothing configured exports an empty document.
#[tokio::test]
async fn an_empty_tenant_exports_an_empty_document() {
    let server = server();

    let response = server
        .get(&config(""))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_json(&json!({
        "services": [],
        "pipelines": [],
        "routes": [],
        "stream_routes": [],
        "egress_policies": [],
        "consumers": [],
    }));
}

/// A dry-run document declaring a certificate consumer and an egress policy.
fn consumer_and_egress_plan() -> Value {
    json!({
        "config": {
            "consumers": [{
                "name": "billing-sync",
                "credential": {"credential_kind": "client_cert", "fingerprint": "ab".repeat(32)},
            }],
            "egress_policies": [{
                "name": "fetcher",
                "service": "spiffe://acme.test/fetcher",
                "destinations": [{"host": "api.example.com", "port": 443}],
            }],
        },
        "plan": "dry_run"
    })
}

/// A document declaring a consumer by its certificate's fingerprint and an
/// egress policy plans both, by the kinds the plan names them with.
#[tokio::test]
async fn a_dry_run_plans_consumers_and_egress_policies() {
    let server = server();
    let document = consumer_and_egress_plan();

    let response = server
        .post(&config(""))
        .authorization_bearer(TENANT_USER)
        .json(&document)
        .await;

    response.assert_status_ok();
    let plan: Value = response.json();
    let kinds: Vec<&str> = plan["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|change| change["resource"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"consumer"));
    assert!(kinds.contains(&"egress_policy"));
    assert!(
        plan["changes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|change| change["change"] == "create")
    );
}

/// Asked for YAML, the export answers in YAML under its media type.
#[tokio::test]
async fn the_export_answers_in_yaml_when_asked() {
    let server = server();

    let response = server
        .get(&config(""))
        .authorization_bearer(TENANT_USER)
        .add_header(ACCEPT, "application/yaml")
        .await;

    response.assert_status_ok();
    assert_eq!(response.header(CONTENT_TYPE), "application/yaml");
    assert!(response.text().contains("services: []"));
}

/// A dry run reports the plan and writes nothing.
#[tokio::test]
async fn a_dry_run_plans_without_writing() {
    let server = server();

    let response = server
        .post(&config(""))
        .authorization_bearer(TENANT_USER)
        .json(&one_service("dry_run"))
        .await;

    response.assert_status_ok();
    response.assert_json(&json!({
        "empty": false,
        "change_count": 1,
        "changes": [{"resource": "service", "name": "backend", "change": "create"}]
    }));
    let exported: Value = server
        .get(&config(""))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(exported["services"], json!([]));
}

/// A route whose path is not a path is refused, and nothing is applied.
#[tokio::test]
async fn a_document_with_an_invalid_route_is_refused() {
    let server = server();
    let document = json!({
        "config": {"routes": [{
            "name": "orders",
            "path_pattern": "orders",
            "service": "backend",
            "pipeline": "edge",
            "policy": "Public"
        }]},
        "plan": "apply"
    });

    let response = server
        .post(&config(""))
        .authorization_bearer(TENANT_USER)
        .json(&document)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// An OpenAPI 3 spec becomes a draft: one service, one route per path.
#[tokio::test]
async fn an_openapi_spec_becomes_a_draft_configuration() {
    let server = server();
    let spec = json!({
        "openapi": "3.0.3",
        "info": {"title": "Pet Store"},
        "servers": [{"url": "https://petstore.example.com"}],
        "paths": {"/pets": {"get": {}, "post": {}}}
    });

    let response = server
        .post(&config("/openapi"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"spec": spec, "pipeline": "edge"}))
        .await;

    response.assert_status_ok();
    let draft: Value = response.json();
    assert_eq!(draft["services"][0]["name"], "pet-store");
    assert_eq!(draft["routes"][0]["name"], "pets");
    assert_eq!(draft["routes"][0]["methods"], json!(["Get", "Post"]));
    assert_eq!(draft["pipelines"][0]["status"], "Draft");
}

/// Exporting gateway configuration without tenant authority returns 403.
#[tokio::test]
async fn a_caller_the_app_refuses_cannot_export() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&config(""))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

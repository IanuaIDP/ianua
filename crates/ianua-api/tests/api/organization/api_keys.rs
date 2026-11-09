//! The organization API key endpoints and the permission catalog.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, ORG_MEMBER, adapters, router};
use ianua_app::test_support::acting::{FakeOrgActors, Refusal};
use serde_json::{Value, json};

/// The path under the test organization.
fn org_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}{rest}")
}

/// A server over the default test adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// The key listing answers a page.
#[tokio::test]
async fn the_key_listing_is_a_page() {
    let response = server()
        .get(&org_path("/api-keys"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status_ok();
    let page: Value = response.json();
    assert!(page["items"].is_array());
}

/// The catalog lists the scopes a key may name, grouped by domain, each
/// with the label to send.
#[tokio::test]
async fn the_permission_catalog_names_each_scope() {
    let response = server()
        .get(&org_path("/permissions"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status_ok();
    let groups: Vec<Value> = response.json();
    assert!(!groups.is_empty());
    let first = &groups[0]["permissions"][0]["label"];
    assert!(
        first
            .as_str()
            .is_some_and(|label| label.starts_with("org:"))
    );
}

/// A scope that is not one is refused before a key is minted.
#[tokio::test]
async fn a_malformed_scope_is_refused() {
    let response = server()
        .post(&org_path("/api-keys"))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({"name": "CI", "scopes": ["NOT A SCOPE"]}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Listing organization keys without authority returns 403.
#[tokio::test]
async fn listing_keys_without_the_right_is_forbidden() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        org_actors: Arc::new(FakeOrgActors::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&org_path("/api-keys"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

//! The cloud account endpoints.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, ORG_MEMBER, adapters, router};
use ianua_app::test_support::acting::{FakeOrgActors, Refusal};
use serde_json::Value;

/// The test organization's address, followed by `rest`.
fn org_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}{rest}")
}

/// A server over the default fake adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// The connections list as an array.
#[tokio::test]
async fn the_connections_list_as_an_array() {
    let response = server()
        .get(&org_path("/cloud-accounts"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status_ok();
    let accounts: Value = response.json();
    assert!(accounts.is_array());
}

/// A cloud ianua does not drive is refused, naming the ones it does.
#[tokio::test]
async fn an_unknown_cloud_is_refused() {
    let response = server()
        .post(&org_path("/cloud-accounts/amazon"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    assert!(response.text().contains("aws"));
}

/// Networks are listed per region, so a request without one is refused.
#[tokio::test]
async fn listing_networks_needs_a_region() {
    let response = server()
        .get(&org_path("/cloud-accounts/aws/networks"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Listing cloud connections without organization authority returns 403.
#[tokio::test]
async fn listing_connections_without_the_right_is_forbidden() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        org_actors: Arc::new(FakeOrgActors::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&org_path("/cloud-accounts"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

//! The organization's own identity provider: reading, adding, changing,
//! switching and removing it.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, ORG_MEMBER, adapters, router};
use ianua_app::test_support::organization::{
    FakeOrgIdentityProviderStore, OrgProviderShape, stored_org_provider,
};
use ianua_app::test_support::test_org_caller;
use serde_json::{Value, json};

/// The test organization's provider address, followed by `rest`.
fn provider_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/identity-provider{rest}")
}

/// A server whose test organization signs in through Acme's Okta over
/// OIDC.
fn with_okta() -> TestServer {
    let provider = stored_org_provider(
        test_org_caller().organization_id(),
        OrgProviderShape::oidc(),
    );
    TestServer::new(router(ianua_assembly::deps::Adapters {
        org_identity_provider_store: Arc::new(FakeOrgIdentityProviderStore::holding(provider)),
        ..adapters()
    }))
    .unwrap()
}

/// Ann reads her organization's provider: its name, protocol and trust,
/// and never its configuration or secret.
#[tokio::test]
async fn the_provider_reads_without_its_configuration() {
    let response = with_okta()
        .get(&provider_path(""))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status_ok();
    let provider: Value = response.json();
    assert_eq!(provider["name"], "Acme Okta");
    assert_eq!(provider["protocol"], "Oidc");
    assert_eq!(provider["status"], "Active");
    assert_eq!(provider["email_trust"], "Unverified");
    assert!(provider.get("config").is_none());
}

/// An organization that never added a provider answers as missing.
#[tokio::test]
async fn an_organization_without_a_provider_is_not_found() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .get(&provider_path(""))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// Disabling the identity provider without password proof returns 422.
#[tokio::test]
async fn switching_needs_the_password_again() {
    let response = with_okta()
        .put(&provider_path("/status"))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({"status": "Disabled"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// The provider goes, and reading it afterwards finds none.
#[tokio::test]
async fn a_removed_provider_is_gone() {
    let server = with_okta();

    let removed = server
        .delete(&provider_path(""))
        .authorization_bearer(ORG_MEMBER)
        .await;
    let read = server
        .get(&provider_path(""))
        .authorization_bearer(ORG_MEMBER)
        .await;

    removed.assert_status(StatusCode::NO_CONTENT);
    read.assert_status(StatusCode::NOT_FOUND);
}

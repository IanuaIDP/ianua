//! The LDAP client certificate and service account endpoints.

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, TENANT, TENANT_USER, adapters, router};
use serde_json::json;

/// The test tenant's LDAP client certificate address, followed by `rest`.
fn certificates(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/auth/ldap-certificates{rest}")
}

/// A server over the default fake adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// Ann has no certificate yet: the list is empty, in the shape the
/// dashboard reads.
#[tokio::test]
async fn a_person_without_certificates_lists_none() {
    let response = server()
        .get(&certificates(""))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_json(&json!({"certificates": []}));
}

/// A device label that is empty is refused before anything is signed.
#[tokio::test]
async fn an_empty_device_label_is_refused() {
    let response = server()
        .post(&certificates(""))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----",
            "device_label": "",
            "proof": {"password": "Correct-Horse-Battery-9"}
        }))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A certificate that is not Ann's is not found.
#[tokio::test]
async fn revoking_a_certificate_that_is_not_yours_is_not_found() {
    let response = server()
        .delete(&certificates(&format!("/{}", uuid::Uuid::now_v7())))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// Nobody signed in may list certificates.
#[tokio::test]
async fn listing_needs_a_signed_in_person() {
    let response = server().get(&certificates("")).await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// The test tenant's LDAP service account address, followed by `rest`.
fn service_accounts(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/auth/ldap-service-accounts{rest}")
}

/// A service account Jira binds as, reading people only.
fn jira() -> serde_json::Value {
    json!({
        "name": "jira",
        "scope": {"access": "ReadOnly", "base_dns": ["ou=people,dc=acme,dc=com"]}
    })
}

/// A new service account shows its secret once, and reads back without
/// it, in the shape the dashboard lists.
#[tokio::test]
async fn a_created_service_account_shows_its_secret_once() {
    let server = server();

    let created = server
        .post(&service_accounts(""))
        .authorization_bearer(TENANT_USER)
        .json(&jira())
        .await;
    created.assert_status(StatusCode::CREATED);
    let body: serde_json::Value = created.json();
    assert!(body["secret"].is_string());
    let id = body["id"].as_str().unwrap().to_owned();

    let read = server
        .get(&service_accounts(&format!("/{id}")))
        .authorization_bearer(TENANT_USER)
        .await;

    read.assert_status_ok();
    let account: serde_json::Value = read.json();
    assert_eq!(account["name"], "jira");
    assert_eq!(account["access"], "ReadOnly");
    assert_eq!(account["status"], "Active");
    assert!(account.get("secret").is_none());
}

/// A base DN that is not attribute=value pairs is refused before anything
/// is made.
#[tokio::test]
async fn a_malformed_base_dn_is_refused() {
    let mut body = jira();
    body["scope"]["base_dns"] = json!(["people"]);

    let response = server()
        .post(&service_accounts(""))
        .authorization_bearer(TENANT_USER)
        .json(&body)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A service account only reads: asking for one that writes is an unknown
/// value, refused before anything is made.
#[tokio::test]
async fn an_access_that_writes_is_refused_as_unknown() {
    for unknown in ["ReadWrite", "read_write"] {
        let mut body = jira();
        body["scope"]["access"] = json!(unknown);

        let response = server()
            .post(&service_accounts(""))
            .authorization_bearer(TENANT_USER)
            .json(&body)
            .await;

        response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    }
}

/// Rotating the secret of an account that does not exist is not found.
#[tokio::test]
async fn rotating_an_unknown_account_is_not_found() {
    let response = server()
        .post(&service_accounts(&format!(
            "/{}/rotate-secret",
            uuid::Uuid::now_v7()
        )))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// Deleting an account that does not exist is not found.
#[tokio::test]
async fn deleting_an_unknown_account_is_not_found() {
    let response = server()
        .delete(&service_accounts(&format!("/{}", uuid::Uuid::now_v7())))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// Nobody signed in may list service accounts.
#[tokio::test]
async fn service_accounts_need_a_signed_in_caller() {
    let response = server().get(&service_accounts("")).await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

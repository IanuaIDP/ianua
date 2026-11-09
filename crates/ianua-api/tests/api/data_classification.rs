//! The data classification endpoints: a tenant's field-level sensitivity
//! rules, and the shape they answer in.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, TENANT, TENANT_USER, adapters, router};
use ianua_app::test_support::acting::{FakeTenantAuthorities, Refusal};
use serde_json::{Value, json};

/// The path under the test tenant's data classification.
fn classification(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/classification{rest}")
}

/// A server over the default test adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// A tenant that has classified nothing gets an empty set, not a `404`.
#[tokio::test]
async fn a_tenant_without_rules_gets_an_empty_set() {
    let server = server();

    let response = server
        .get(&classification(""))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_json(&json!({"id": null, "rules": []}));
}

/// Ann classifies a field; the rule answers with its id and reads back in
/// the set, its level and redaction by name.
#[tokio::test]
async fn a_rule_is_added_and_read_back() {
    let server = server();

    let added = server
        .post(&classification("/rules"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"field_path": "user.ssn", "level": "Restricted", "redaction": "Mask"}))
        .await;
    added.assert_status(StatusCode::CREATED);
    let rule: Value = added.json();

    let set: Value = server
        .get(&classification(""))
        .authorization_bearer(TENANT_USER)
        .await
        .json();

    assert_eq!(rule["field_path"], "user.ssn");
    assert_eq!(rule["level"], "Restricted");
    assert_eq!(rule["redaction"], "Mask");
    assert!(set["id"].is_string());
    assert_eq!(set["rules"], json!([rule]));
}

/// Removing a rule takes it out of the set; the set itself stays.
#[tokio::test]
async fn a_removed_rule_leaves_the_set() {
    let server = server();
    let rule: Value = server
        .post(&classification("/rules"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"field_path": "user.ssn", "level": "Restricted", "redaction": "Mask"}))
        .await
        .json();

    server
        .delete(&classification(&format!(
            "/rules/{}",
            rule["id"].as_str().unwrap()
        )))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let set: Value = server
        .get(&classification(""))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(set["rules"], json!([]));
}

/// The rule Ann adds, masking `user.ssn` as confidential.
async fn masked_ssn(server: &TestServer) -> Value {
    server
        .post(&classification("/rules"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"field_path": "user.ssn", "level": "Confidential", "redaction": "Mask"}))
        .await
        .json()
}

/// Ann decides `user.ssn` must be removed, not masked. The rule changes in
/// place: the same id and field, the new level and redaction.
#[tokio::test]
async fn a_rule_is_changed_in_place() {
    let server = server();
    let rule = masked_ssn(&server).await;
    let id = rule["id"].as_str().unwrap();

    server
        .put(&classification(&format!("/rules/{id}")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"level": "Restricted", "redaction": "Remove"}))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let set: Value = server
        .get(&classification(""))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(
        set["rules"],
        json!([{"id": id, "field_path": "user.ssn", "level": "Restricted", "redaction": "Remove"}])
    );
}

/// Changing a rule the tenant does not have is not found.
#[tokio::test]
async fn changing_an_unknown_rule_is_not_found() {
    let server = server();
    masked_ssn(&server).await;

    let response = server
        .put(&classification(&format!("/rules/{}", uuid::Uuid::now_v7())))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"level": "Restricted", "redaction": "Remove"}))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// Ann asks to encrypt `user.ssn`, which nothing carries out yet. The
/// change is refused.
#[tokio::test]
async fn changing_a_rule_to_encrypt_is_refused() {
    let server = server();
    let rule = masked_ssn(&server).await;

    let response = server
        .put(&classification(&format!(
            "/rules/{}",
            rule["id"].as_str().unwrap()
        )))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"level": "Restricted", "redaction": "Encrypt"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A caller without classification authority receives 403 when requesting
/// a change to public classification.
#[tokio::test]
async fn a_caller_the_app_refuses_cannot_change_a_rule() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .put(&classification(&format!("/rules/{}", uuid::Uuid::now_v7())))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"level": "Public", "redaction": "Mask"}))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// Ann masks `user.ssn`, then adds a second rule for it. Only one rule
/// can classify a field, so the second answers `409`.
#[tokio::test]
async fn a_second_rule_for_one_field_is_a_conflict() {
    let server = server();
    masked_ssn(&server).await;

    let response = server
        .post(&classification("/rules"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"field_path": "user.ssn", "level": "Public", "redaction": "Remove"}))
        .await;

    response.assert_status(StatusCode::CONFLICT);
}

/// A field path with an empty segment is refused before it is stored.
#[tokio::test]
async fn a_field_path_with_an_empty_segment_is_refused() {
    let server = server();

    let response = server
        .post(&classification("/rules"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"field_path": "user..ssn", "level": "Restricted", "redaction": "Mask"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Listing classification rules without the required authority returns 403.
#[tokio::test]
async fn a_caller_the_app_refuses_is_forbidden() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&classification(""))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

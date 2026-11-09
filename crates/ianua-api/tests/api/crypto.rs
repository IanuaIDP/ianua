//! The crypto endpoints: a tenant's signing keys, its public JWKS document,
//! its published assertion keys and algorithm migrations, and what they
//! answer.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, TENANT, TENANT_USER, adapters, router};
use ianua_app::test_support::acting::{FakeTenantAuthorities, Refusal};
use ianua_app::test_support::crypto::{
    FakeAssertionKeyStore, FakeSigningKeyStore, premigration_keys,
};
use ianua_assembly::deps::Adapters;
use ianua_domain::domains::crypto::assertion_key::{
    AssertionKey, AssertionKeySet, NewAssertionKey,
};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{KeyId, PublicKeyPem};
use serde_json::{Value, json};

/// The test tenant's crypto address, followed by `rest`.
fn crypto_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/crypto{rest}")
}

/// A server whose test tenant signs with `key-old` (RS256).
fn with_keys() -> TestServer {
    TestServer::new(router(Adapters {
        signing_key_store: Arc::new(FakeSigningKeyStore::holding(premigration_keys())),
        ..adapters()
    }))
    .unwrap()
}

/// An admin reads the key set: each key by `kid`, algorithm and status.
#[tokio::test]
async fn the_key_set_lists_each_key() {
    let server = with_keys();

    let response = server
        .get(&crypto_path("/keys"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    let key = &body["keys"][0];
    assert_eq!(key["kid"], "key-old");
    assert_eq!(key["algorithm"], "RS256");
    assert!(key.get("status").is_some());
    assert!(key.get("private_key").is_none(), "no private half is sent");
}

/// A relying party fetches the JWKS without signing in and gets the
/// public key in JWK form.
#[tokio::test]
async fn the_jwks_document_is_public() {
    let server = with_keys();

    let response = server
        .get(&format!(
            "/api/v1/organizations/{ORG}/tenants/{TENANT}/.well-known/jwks.json"
        ))
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(
        body["keys"][0],
        json!({"kty": "RSA", "use": "sig", "kid": "key-old", "alg": "RS256", "n": "test-n", "e": "test-e"})
    );
}

/// The test tenant's public address `document` under `.well-known`.
fn well_known(document: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/.well-known/{document}")
}

/// A server whose test tenant signs tokens with `key-old` and assertions
/// with the ES256 key `assert-1`.
fn with_assertion_keys() -> TestServer {
    let key = AssertionKey::create(NewAssertionKey {
        kid: KeyId::new("assert-1").unwrap(),
        public_key: PublicKeyPem::new("-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----")
            .unwrap(),
        private_key: Secret::new("private"),
    });
    TestServer::new(router(Adapters {
        signing_key_store: Arc::new(FakeSigningKeyStore::holding(premigration_keys())),
        assertion_key_store: Arc::new(FakeAssertionKeyStore::holding(&AssertionKeySet::new(key))),
        ..adapters()
    }))
    .unwrap()
}

/// A service behind the gateway fetches the tenant's assertion keys without
/// signing in, and gets the ES256 key that signs `X-Ianua-Assertion`.
#[tokio::test]
async fn the_assertion_keys_are_public() {
    let server = with_assertion_keys();

    let response = server.get(&well_known("ianua-assertion-keys.json")).await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["keys"][0]["kid"], "assert-1");
    assert_eq!(body["keys"][0]["alg"], "ES256");
    assert_eq!(body["keys"].as_array().unwrap().len(), 1);
}

/// The assertion-key response and tenant JWKS contain disjoint key identifiers.
#[tokio::test]
async fn the_assertion_keys_and_the_jwks_share_no_key() {
    let server = with_assertion_keys();

    let jwks: Value = server.get(&well_known("jwks.json")).await.json();
    let assertion_keys: Value = server
        .get(&well_known("ianua-assertion-keys.json"))
        .await
        .json();

    let kids = |set: &Value| -> Vec<String> {
        set["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| key["kid"].as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(kids(&jwks), ["key-old"]);
    assert_eq!(kids(&assertion_keys), ["assert-1"]);
}

/// A tenant whose setup has not made its assertion key yet answers not
/// found.
#[tokio::test]
async fn the_assertion_keys_of_a_tenant_without_any_are_not_found() {
    let server = with_keys();

    let response = server.get(&well_known("ianua-assertion-keys.json")).await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// The JWKS of a tenant that does not exist is not found.
#[tokio::test]
async fn the_jwks_of_an_unknown_tenant_is_not_found() {
    let server = with_keys();

    let response = server
        .get(&format!(
            "/api/v1/organizations/{ORG}/tenants/nobody/.well-known/jwks.json"
        ))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// A rotation answers the new key's id.
#[tokio::test]
async fn rotating_answers_the_new_key() {
    let server = with_keys();

    let response = server
        .post(&crypto_path("/keys/rotate"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"algorithm": "ES256"}))
        .await;

    response.assert_status_ok();
    assert!(response.json::<Value>()["key_id"].is_string());
}

/// An algorithm the platform does not sign with is refused.
#[tokio::test]
async fn an_unknown_algorithm_is_refused() {
    let server = with_keys();

    let response = server
        .post(&crypto_path("/keys/rotate"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"algorithm": "HS256"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A migration is planned, then read back as planned.
#[tokio::test]
async fn a_planned_migration_reads_back() {
    let server = with_keys();

    server
        .post(&crypto_path("/migration/plan"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"target_algorithm": "ES256"}))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    let response = server
        .get(&crypto_path("/migration"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["source_algorithm"], "RS256");
    assert_eq!(body["target_algorithm"], "ES256");
    assert_eq!(body["source_key_id"], "key-old");
}

/// With no migration under way there is nothing to read.
#[tokio::test]
async fn no_migration_is_not_found() {
    let server = with_keys();

    let response = server
        .get(&crypto_path("/migration"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// Reading keys without tenant authority returns 403.
#[tokio::test]
async fn a_caller_the_app_refuses_is_forbidden() {
    let server = TestServer::new(router(Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&crypto_path("/keys"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

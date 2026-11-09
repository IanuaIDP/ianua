//! The custom domain endpoints: registering and listing a tenant's
//! domains, and in what shape they answer.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, TENANT, TENANT_USER, adapters, router, router_with, settings};
use ianua_app::test_support::acting::{FakeTenantAuthorities, Refusal};
use ianua_app::test_support::domain::{
    DomainSeed, FakeCertificateParser, FakeCertificateStore, FakeDomainStore, TEST_CERTIFICATE_PEM,
    TEST_PRIVATE_KEY_PEM, parsed_for,
};
use ianua_app::test_support::test_ctx;
use ianua_domain::domains::tenant::hosts::PlatformAddressing;
use serde_json::{Value, json};

/// The test tenant's domain address, followed by `rest`.
fn domains(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/domains{rest}")
}

/// A tenant that registered `app.acme.com` and has not proved it yet lists
/// it with the challenge to publish and the record that brings traffic
/// here, pointing at the tenant's random gateway hostname.
#[tokio::test]
async fn a_pending_domain_lists_what_to_publish() {
    let store = Arc::new(FakeDomainStore::holding(
        test_ctx().tenant_id(),
        [DomainSeed::pending("app.acme.com").build()],
    ));
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        registered_domain_store: store,
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&domains(""))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let page: Value = response.json();
    let domain = &page["items"][0];
    assert_eq!(domain["domain"], "app.acme.com");
    assert_eq!(domain["connection"], "SelfManaged");
    assert_eq!(domain["verification_status"], "Pending");
    assert_eq!(domain["dns_record_name"], "_ianua-verify.app.acme.com");
    let alias = &domain["traffic_records"]["subdomain"];
    assert_eq!(alias["record_type"], "CNAME");
    let hostnames: Value = server
        .get(&format!(
            "/api/v1/organizations/{ORG}/tenants/{TENANT}/hostname"
        ))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(alias["value"], hostnames["uuid_subdomain"]);
}

/// A nested deployment aliases custom traffic to the tenant's permanent
/// random root, the name served by its authoritative DNS. The traffic
/// record points to that tenant-specific hostname.
#[tokio::test]
async fn nested_domain_instructions_use_the_random_root() {
    let mut settings = settings();
    settings.platform_addressing = PlatformAddressing::Nested;
    let server = TestServer::new(router_with(adapters(), settings)).unwrap();
    let hostnames: Value = server
        .get(&format!(
            "/api/v1/organizations/{ORG}/tenants/{TENANT}/hostname"
        ))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    let response = server
        .post(&domains(""))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"domain": "login.acme.com"}))
        .await;
    response.assert_status(StatusCode::CREATED);
    let body: Value = response.json();
    assert_eq!(
        body["traffic_records"]["subdomain"]["value"],
        hostnames["uuid_subdomain"]
    );
}

/// Ann registers a domain and gets it back pending, with its challenge.
#[tokio::test]
async fn a_registered_domain_starts_pending() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post(&domains(""))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"domain": "login.acme.com"}))
        .await;

    response.assert_status(StatusCode::CREATED);
    let domain: Value = response.json();
    assert_eq!(domain["domain"], "login.acme.com");
    assert_eq!(domain["verification_status"], "Pending");
    assert!(domain["dns_record_value"].is_string());
}

/// A name that is no domain is refused before the app sees it.
#[tokio::test]
async fn an_invalid_domain_is_refused() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post(&domains(""))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"domain": "not a domain"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// An unknown connection is refused by name.
#[tokio::test]
async fn an_unknown_connection_is_refused() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post(&domains(""))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"domain": "login.acme.com", "connection": "Teleported"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Listing domains without tenant authority returns 403.
#[tokio::test]
async fn a_caller_the_app_refuses_is_forbidden() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&domains(""))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A domain this tenant never registered cannot be verified.
#[tokio::test]
async fn verifying_an_unknown_domain_is_not_found() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post(&domains(&format!("/{}/verify", uuid::Uuid::now_v7())))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// A server whose test tenant holds the verified `app.acme.com`, reading
/// every uploaded chain as a certificate for it, with the domain's id.
fn verified_domain_taking_uploads() -> (TestServer, String) {
    let domain = DomainSeed::verified("app.acme.com").build();
    let id = domain.id().as_uuid().to_string();
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        registered_domain_store: Arc::new(FakeDomainStore::holding(
            test_ctx().tenant_id(),
            [domain],
        )),
        certificate_store: Arc::new(FakeCertificateStore::empty()),
        certificate_parser: Arc::new(FakeCertificateParser::reading(parsed_for(
            "app.acme.com",
            90,
        ))),
        ..adapters()
    }))
    .unwrap();
    (server, id)
}

/// The test chain and key, as a tenant uploads them.
fn upload() -> Value {
    json!({
        "certificate_pem": TEST_CERTIFICATE_PEM,
        "private_key_pem": TEST_PRIVATE_KEY_PEM,
    })
}

/// A domain read on its own before it serves a certificate answers with
/// none.
#[tokio::test]
async fn a_domain_without_a_certificate_reads_back_with_none() {
    let (server, id) = verified_domain_taking_uploads();

    let response = server
        .get(&domains(&format!("/{id}")))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let domain: Value = response.json();
    assert_eq!(domain["domain"], "app.acme.com");
    assert!(domain["certificate"].is_null());
}

/// Ann uploads her own certificate. It serves the domain, reads back as
/// uploaded and renewed by her, and its key is never answered.
#[tokio::test]
async fn an_uploaded_certificate_serves_the_domain() {
    let (server, id) = verified_domain_taking_uploads();

    let uploaded = server
        .put(&domains(&format!("/{id}/certificate")))
        .authorization_bearer(TENANT_USER)
        .json(&upload())
        .await;
    uploaded.assert_status_ok();
    assert_eq!(uploaded.json::<Value>()["source"], "Uploaded");

    let domain: Value = server
        .get(&domains(&format!("/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(domain["tls_status"], "Active");
    assert_eq!(domain["certificate"]["renewal"], "ByTenant");
    assert_eq!(domain["certificate"]["subject_names"][0], "app.acme.com");
    assert!(!domain.to_string().contains("PRIVATE KEY"));
}

/// Removing the uploaded certificate leaves the domain serving none, and
/// says so.
#[tokio::test]
async fn a_removed_certificate_leaves_no_certificate() {
    let (server, id) = verified_domain_taking_uploads();
    server
        .put(&domains(&format!("/{id}/certificate")))
        .authorization_bearer(TENANT_USER)
        .json(&upload())
        .await
        .assert_status_ok();

    server
        .delete(&domains(&format!("/{id}/certificate")))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let domain: Value = server
        .get(&domains(&format!("/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(domain["tls_status"], "NoCertificate");
    assert!(domain["certificate"].is_null());
}

/// Uploading an unreadable certificate chain returns 422.
#[tokio::test]
async fn an_unreadable_certificate_is_refused() {
    let domain = DomainSeed::verified("app.acme.com").build();
    let id = domain.id().as_uuid().to_string();
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        registered_domain_store: Arc::new(FakeDomainStore::holding(
            test_ctx().tenant_id(),
            [domain],
        )),
        certificate_parser: Arc::new(FakeCertificateParser::refusing()),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .put(&domains(&format!("/{id}/certificate")))
        .authorization_bearer(TENANT_USER)
        .json(&upload())
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

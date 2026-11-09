//! The live streams: who the app admits to each, and who is turned away
//! before any socket opens.
//!
//! The test server has no real connection to upgrade, so an admitted
//! request stops at the WebSocket handshake (`400`), while a refused one
//! gets the app's answer.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{OPERATOR, ORG, ORG_MEMBER, TENANT, TENANT_USER, adapters, router};
use ianua_app::test_support::acting::{
    FakeOperatorAuthorities, FakeOrgActors, FakeTenantAuthorities, Refusal,
};
use ianua_app::test_support::test_ctx;
use ianua_assembly::deps::Adapters;

/// A server over the default test adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// An operator whose key still counts is admitted to their notifications
/// and to the platform dashboard.
#[tokio::test]
async fn an_operator_is_admitted_to_their_streams() {
    let server = server();

    for path in ["/api/v1/ws/notifications", "/api/v1/ws/dashboard"] {
        server
            .get(path)
            .authorization_bearer(OPERATOR)
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
}

/// A revoked operator receives 401 from the dashboard stream endpoint.
#[tokio::test]
async fn an_operator_the_app_no_longer_honours_is_unauthenticated() {
    let server = TestServer::new(router(Adapters {
        operator_authorities: Arc::new(FakeOperatorAuthorities::refusing(Refusal::SignedOut)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get("/api/v1/ws/dashboard")
        .authorization_bearer(OPERATOR)
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// A tenant credential receives 403 from the platform dashboard endpoint.
#[tokio::test]
async fn a_tenant_user_is_kept_off_the_platform_dashboard() {
    let response = server()
        .get("/api/v1/ws/dashboard")
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// The notification stream requires authentication and otherwise returns 401.
#[tokio::test]
async fn a_stream_without_a_caller_is_unauthenticated() {
    let response = server().get("/api/v1/ws/notifications").await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// A member is admitted to their notifications and to the provisioning
/// progress of the tenants they see.
#[tokio::test]
async fn a_member_is_admitted_to_their_streams() {
    let server = server();
    let tenant = test_ctx().tenant_id();

    for path in [
        format!("/api/v1/organizations/{ORG}/ws/notifications"),
        format!("/api/v1/organizations/{ORG}/ws/workflows"),
        format!("/api/v1/organizations/{ORG}/ws/workflow/{tenant}"),
    ] {
        server
            .get(&path)
            .authorization_bearer(ORG_MEMBER)
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
}

/// Provisioning progress for an unknown tenant returns 404.
#[tokio::test]
async fn an_unknown_tenants_progress_is_not_found() {
    let response = server()
        .get(&format!(
            "/api/v1/organizations/{ORG}/ws/workflow/{}",
            uuid::Uuid::now_v7()
        ))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// Denied organization authority returns 403 from the workflow stream endpoint.
#[tokio::test]
async fn a_member_the_app_refuses_is_forbidden() {
    let server = TestServer::new(router(Adapters {
        org_actors: Arc::new(FakeOrgActors::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&format!("/api/v1/organizations/{ORG}/ws/workflows"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// The test tenant's notification stream.
fn tenant_stream() -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/ws/notifications")
}

/// A tenant user whose session still counts is admitted to their own
/// notifications in the tenant.
#[tokio::test]
async fn a_tenant_user_is_admitted_to_their_notifications() {
    let response = server()
        .get(&tenant_stream())
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
}

/// A signed-out tenant session receives 401 from its notification stream.
#[tokio::test]
async fn a_signed_out_tenant_user_gets_no_notification_stream() {
    let server = TestServer::new(router(Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&tenant_stream())
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// An anonymous tenant notification-stream request returns 401.
#[tokio::test]
async fn a_tenant_stream_without_a_caller_is_unauthenticated() {
    let response = server().get(&tenant_stream()).await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

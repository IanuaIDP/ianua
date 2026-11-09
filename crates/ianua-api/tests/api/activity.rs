//! The activity endpoints: the contribution calendar of an organization and
//! of one tenant, and in what shape they answer.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, ORG_MEMBER, TENANT, TENANT_USER, adapters, router};
use ianua_app::test_support::acting::{FakeOrgActors, Refusal};
use serde_json::Value;

/// A server over the default fake adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// A week of a quiet organization answers seven days, each at level 0.
#[tokio::test]
async fn a_quiet_week_answers_every_day() {
    let server = server();

    let response = server
        .get(&format!(
            "/api/v1/organizations/{ORG}/activity?from=2026-03-01&to=2026-03-07"
        ))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status_ok();
    let calendar: Value = response.json();
    assert_eq!(calendar["from"], "2026-03-01");
    assert_eq!(calendar["to"], "2026-03-07");
    assert_eq!(calendar["total"], 0);
    assert_eq!(calendar["days"].as_array().unwrap().len(), 7);
    assert_eq!(calendar["days"][0]["level"], 0);
}

/// The tenant calendar answers the same shape for someone acting in it.
#[tokio::test]
async fn a_tenant_calendar_answers_the_same_shape() {
    let server = server();

    let response = server
        .get(&format!(
            "/api/v1/organizations/{ORG}/tenants/{TENANT}/activity?from=2026-03-01&to=2026-03-02"
        ))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    assert_eq!(
        response.json::<Value>()["days"].as_array().unwrap().len(),
        2
    );
}

/// A reversed window is refused before the app sees it.
#[tokio::test]
async fn a_reversed_window_is_refused() {
    let server = server();

    let response = server
        .get(&format!(
            "/api/v1/organizations/{ORG}/activity?from=2026-03-07&to=2026-03-01"
        ))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Denied organization authority returns 403 from the activity endpoint.
#[tokio::test]
async fn a_member_the_app_refuses_is_forbidden() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        org_actors: Arc::new(FakeOrgActors::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&format!("/api/v1/organizations/{ORG}/activity"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

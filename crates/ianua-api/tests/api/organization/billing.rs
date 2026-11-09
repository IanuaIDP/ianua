//! What the organization pays for: the plans on sale, its subscription and
//! usage, the checkout, the payment provider's notices, and the plan an
//! operator arranges.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{OPERATOR, ORG, ORG_MEMBER, adapters, router};
use ianua_app::test_support::organization::{
    FakeOrgSubscriptionStore, SubscriptionShape, TEST_CHECKOUT_URL, test_subscription,
};
use ianua_app::test_support::test_org_caller;
use ianua_domain::domains::organization::billing::plan::PlanLimits;
use serde_json::{Value, json};

/// The test organization's address, followed by `rest`.
fn org_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}{rest}")
}

/// A server over the default fake adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// A server whose test organization is on Free, paid up.
fn with_a_free_subscription() -> TestServer {
    let subscription = test_subscription(
        test_org_caller().organization_id(),
        SubscriptionShape::free(),
    );
    TestServer::new(router(ianua_assembly::deps::Adapters {
        org_subscription_store: Arc::new(FakeOrgSubscriptionStore::holding([subscription])),
        ..adapters()
    }))
    .unwrap()
}

/// The pricing page reads every plan on sale without signing in, in the
/// shape it renders.
#[tokio::test]
async fn the_plans_are_public() {
    let response = server().get("/api/v1/plans").await;

    response.assert_status_ok();
    let catalog: Value = response.json();
    assert_eq!(catalog["currency"], "USD");
    assert_eq!(catalog["plans"][0]["plan"], "Free");
    assert_eq!(catalog["plans"][0]["call_to_action"], "sign_up");
    assert!(catalog["plans"][0]["limits"]["max_users"].is_number());
}

/// Ann reads her organization's subscription: on Free, monthly, paid up.
#[tokio::test]
async fn a_member_reads_the_subscription() {
    let response = with_a_free_subscription()
        .get(&org_path("/subscription"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status_ok();
    let subscription: Value = response.json();
    assert_eq!(subscription["plan"], "Free");
    assert_eq!(subscription["cycle"], "monthly");
    assert_eq!(subscription["state"], "active");
    assert_eq!(subscription["payment_method_on_file"], false);
}

/// Reading a missing organization subscription returns 404.
#[tokio::test]
async fn an_organization_without_a_subscription_is_not_found() {
    let response = server()
        .get(&org_path("/subscription"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// The billing page reads what the organization uses next to its limits.
#[tokio::test]
async fn usage_reads_against_the_limits() {
    let response = server()
        .get(&org_path("/usage"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status_ok();
    let report: Value = response.json();
    assert!(report["usage"]["users"].is_number());
    assert!(report["limits"]["max_users"].is_number());
}

/// A checkout sends the member to the payment provider's page.
#[tokio::test]
async fn a_checkout_answers_the_providers_page() {
    let response = server()
        .post(&org_path("/subscription/checkout"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status_ok();
    response.assert_json(&json!({"checkout_url": TEST_CHECKOUT_URL}));
}

/// An unsigned payment notice returns 403.
#[tokio::test]
async fn an_unsigned_payment_notice_is_refused() {
    let response = server()
        .post("/api/v1/billing/payment-notices")
        .text("{\"type\":\"invoice.paid\"}")
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A negotiated user limit below the minimum returns 422.
#[tokio::test]
async fn negotiated_limits_below_the_free_plan_are_refused() {
    let limits = serde_json::to_value(PlanLimits {
        max_users: 1,
        ..PlanLimits::free()
    })
    .unwrap();

    let response = server()
        .post(&org_path("/plan"))
        .authorization_bearer(OPERATOR)
        .json(&json!({"plan": "Custom", "limits": limits}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Selecting an unsupported weekly billing cycle returns 422.
#[tokio::test]
async fn an_unknown_billing_cycle_is_refused() {
    let response = server()
        .put(&org_path("/subscription"))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({"plan": "Starter", "cycle": "weekly"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

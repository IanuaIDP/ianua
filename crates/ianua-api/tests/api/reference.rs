//! The reference data endpoints: the locales and timezones the platform
//! accepts, public to anyone.

use axum_test::TestServer;
use ianua_api::test_support::{adapters, router};

/// Anyone, signed in or not, reads the locales a preference may name.
#[tokio::test]
async fn the_locales_are_public() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server.get("/api/v1/locales").await;

    response.assert_status_ok();
    let locales: Vec<String> = response.json();
    assert!(locales.iter().any(|locale| locale == "en-US"));
    assert!(locales.iter().any(|locale| locale == "de-DE"));
}

/// Anyone, signed in or not, reads the timezones a preference may name.
#[tokio::test]
async fn the_timezones_are_public() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server.get("/api/v1/timezones").await;

    response.assert_status_ok();
    let timezones: Vec<String> = response.json();
    assert!(timezones.iter().any(|zone| zone == "Europe/Berlin"));
    assert!(timezones.iter().any(|zone| zone == "UTC"));
}

/// An unknown path containing script markup returns a JSON not-found
/// problem without echoing the script.
#[tokio::test]
async fn an_address_nobody_serves_is_answered_with_a_problem_body() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .get("/api/v1/%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
        .await;

    response.assert_status_not_found();
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "not_found");
    assert!(!response.text().contains("script"));
}

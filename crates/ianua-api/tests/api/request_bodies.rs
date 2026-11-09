//! A JSON body, a query string or a form the API cannot take is answered
//! with the platform's problem body, under the status that says why, never
//! with a plain-text page.

use axum::body::Bytes;
use axum::http::StatusCode;
use axum_test::{TestResponse, TestServer};
use ianua_api::test_support::{ORG, TENANT, TENANT_USER, adapters, router};
use serde_json::Value;

/// The public listener, as the dashboard and scripts reach it.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// `body` posted to the sign-in endpoint as JSON.
async fn sign_in_with(body: impl Into<Bytes>) -> TestResponse {
    server()
        .post("/api/v1/login")
        .content_type("application/json")
        .bytes(body.into())
        .await
}

/// The problem body's `error` code, failing when the answer is not one.
fn error_code(response: &TestResponse) -> String {
    let body: Value = response.json();
    assert!(body["message"].is_string(), "{body}");
    body["error"].as_str().unwrap().to_owned()
}

/// Truncated sign-in JSON returns a 400 malformed-body problem.
#[tokio::test]
async fn a_sign_in_with_json_cut_off_is_a_bad_request() {
    let response = sign_in_with(r#"{"email": "ann@acme.test", "pass"#).await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(error_code(&response), "malformed_body");
}

/// A text sign-in body returns a 415 unsupported-media-type problem.
#[tokio::test]
async fn a_sign_in_not_sent_as_json_is_an_unsupported_media_type() {
    let response = server()
        .post("/api/v1/login")
        .text(r#"{"email": "ann@acme.test", "password": "a long passphrase"}"#)
        .await;

    response.assert_status(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(error_code(&response), "unsupported_media_type");
}

/// A two-megabyte sign-in body exceeds the listener limit and returns 413.
#[tokio::test]
async fn a_sign_in_over_the_size_limit_is_too_large() {
    let padding = "a".repeat(2 * 1024 * 1024);

    let response = sign_in_with(format!(r#"{{"email": "{padding}"}}"#)).await;

    response.assert_status(StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(error_code(&response), "body_too_large");
}

/// A numeric email produces a 422 invalid-body problem at sign-in.
#[tokio::test]
async fn a_sign_in_of_the_wrong_shape_is_unprocessable() {
    let response = sign_in_with(r#"{"email": 7, "password": "a long passphrase"}"#).await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error_code(&response), "invalid_body");
}

/// Rejecting a numeric password returns 422 without quoting its value.
#[tokio::test]
async fn a_refused_body_is_never_quoted_back() {
    let response = sign_in_with(r#"{"email": "ann@acme.test", "password": 12345678}"#).await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!response.text().contains("12345678"));
}

/// The test tenant's address, followed by `rest`.
fn tenant_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}{rest}")
}

/// A nonnumeric role-list limit returns an invalid-query problem without
/// quoting the submitted value.
#[tokio::test]
async fn a_query_of_the_wrong_shape_is_unprocessable() {
    let response = server()
        .get(&tenant_path("/authorization/roles?limit=many"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error_code(&response), "invalid_query");
    assert!(!response.text().contains("many"));
}

/// Duplicate sign-out query state produces a 422 invalid-query problem.
#[tokio::test]
async fn a_query_a_handler_reads_is_refused_with_the_problem_body() {
    let response = server()
        .get(&tenant_path("/oauth/logout?state=one&state=two"))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error_code(&response), "invalid_query");
}

/// Duplicate sign-out form state returns a 422 invalid-body problem without
/// exposing the submitted state value.
#[tokio::test]
async fn a_form_of_the_wrong_shape_is_unprocessable() {
    let response = server()
        .post(&tenant_path("/oauth/logout"))
        .content_type("application/x-www-form-urlencoded")
        .bytes(Bytes::from_static(
            b"state=first%20value&state=second%20value",
        ))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error_code(&response), "invalid_body");
    assert!(!response.text().contains("first value"));
}

/// JSON posted to the form-based sign-out route returns 415.
#[tokio::test]
async fn a_form_not_sent_as_one_is_an_unsupported_media_type() {
    let response = server()
        .post(&tenant_path("/oauth/logout"))
        .content_type("application/json")
        .bytes(Bytes::from_static(br#"{"state": "s1"}"#))
        .await;

    response.assert_status(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(error_code(&response), "unsupported_media_type");
}

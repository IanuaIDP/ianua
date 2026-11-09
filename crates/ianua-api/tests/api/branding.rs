//! The branding endpoints: a tenant's look and its own versions of the
//! platform's emails, and in what shape they answer.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use axum_test::multipart::{MultipartForm, Part};
use ianua_api::test_support::{ORG, TENANT, TENANT_USER, adapters, router};
use ianua_app::test_support::acting::{FakeTenantAuthorities, Refusal};
use ianua_app::test_support::authentication::REENTERED_PASSWORD;
use ianua_app::test_support::branding::{FakeMailProviderTransport, PLATFORM_SUBJECT, acme_logo};
use serde_json::{Value, json};

/// The test tenant's branding address, followed by `rest`.
fn branding(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/branding{rest}")
}

/// A server over the default fake adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// A tenant that never customized anything reads every part as `null`.
#[tokio::test]
async fn an_uncustomized_tenant_reads_the_defaults() {
    let server = server();

    let response = server
        .get(&branding(""))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_json(&json!({
        "logo_url": null,
        "primary_color": null,
        "background_color": null,
        "custom_css": null,
        "email_from_name": null,
        "email_from_address": null,
    }));
}

/// Ann sets the primary color and reads it back, stored in upper case.
#[tokio::test]
async fn a_set_color_reads_back() {
    let server = server();

    server
        .patch(&branding(""))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"primary_color": "#ff5733"}))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let current: Value = server
        .get(&branding(""))
        .authorization_bearer(TENANT_USER)
        .await
        .json();

    assert_eq!(current["primary_color"], "#FF5733");
}

/// A color that is no color is refused before the app sees it.
#[tokio::test]
async fn an_invalid_color_is_refused() {
    let server = server();

    let response = server
        .patch(&branding(""))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"primary_color": "orange"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A tenant with no email of its own lists none.
#[tokio::test]
async fn no_customized_email_lists_an_empty_page() {
    let server = server();

    let response = server
        .get(&branding("/email-templates"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    assert_eq!(
        response.json::<Value>()["items"].as_array().map(Vec::len),
        Some(0)
    );
}

/// Resetting an email the tenant never customized finds nothing to reset.
#[tokio::test]
async fn resetting_an_uncustomized_email_is_not_found() {
    let server = server();

    let response = server
        .delete(&branding("/email-templates/PasswordReset"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// Changing branding without tenant authority returns 403.
#[tokio::test]
async fn a_change_the_app_refuses_is_forbidden() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .patch(&branding(""))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"primary_color": "#ff5733"}))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// Ann writes the German version of the verification email; the list
/// shows it with its locale.
#[tokio::test]
async fn a_template_for_one_locale_lists_with_its_locale() {
    let server = server();

    server
        .put(&branding("/email-templates/Verification?locale=de-DE"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"subject": "Bitte bestätigen"}))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let page: Value = server
        .get(&branding("/email-templates"))
        .authorization_bearer(TENANT_USER)
        .await
        .json();

    assert_eq!(page["items"][0]["locale"], "de-DE");
    assert_eq!(page["items"][0]["subject"], "Bitte bestätigen");
}

/// A locale that is no BCP 47 tag is refused before the app sees it.
#[tokio::test]
async fn a_malformed_locale_is_refused() {
    let response = server()
        .put(&branding(
            "/email-templates/Verification?locale=not%20a%20locale",
        ))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"subject": "Hello"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// The preview of an email the tenant never wrote reads as the platform's.
#[tokio::test]
async fn a_saved_preview_reads_the_platforms_email() {
    let response = server()
        .post(&branding("/email-templates/Verification/preview"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({}))
        .await;

    response.assert_status_ok();
    assert_eq!(response.json::<Value>()["subject"], PLATFORM_SUBJECT);
}

/// A draft previews with its own subject, and nothing is saved.
#[tokio::test]
async fn a_draft_preview_reads_the_draft() {
    let server = server();

    let response = server
        .post(&branding("/email-templates/Verification/preview"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"draft": {"subject": "Confirm your address"}}))
        .await;

    response.assert_status_ok();
    assert_eq!(response.json::<Value>()["subject"], "Confirm your address");
    let page: Value = server
        .get(&branding("/email-templates"))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(page["items"].as_array().map(Vec::len), Some(0));
}

/// A test send goes to the caller through the platform's mail while the
/// tenant names no provider of its own.
#[tokio::test]
async fn a_test_send_goes_to_the_caller() {
    let transport = Arc::new(FakeMailProviderTransport::delivering());
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        mail_provider_transport: transport.clone(),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .post(&branding("/email-templates/Verification/test-send"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({}))
        .await;

    response.assert_status(StatusCode::NO_CONTENT);
    assert_eq!(transport.delivered().len(), 1);
}

/// A tenant that never named a provider reads the platform's mail.
#[tokio::test]
async fn an_unnamed_provider_reads_as_the_platforms_mail() {
    let response = server()
        .get(&branding("/mail-provider"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let provider: Value = response.json();
    assert_eq!(provider["kind"], "platform");
    assert_eq!(provider["check"], "unverified");
    assert_eq!(provider["delivers_through"], "platform");
}

/// An SMTP server named by its address and port.
fn smtp_switch(password: &str) -> Value {
    json!({
        "provider": {
            "kind": "smtp",
            "host": "smtp.example.com",
            "port": 587,
            "security": "starttls",
            "username": "mailer",
            "password": "smtp-secret",
        },
        "proof": {"password": password},
    })
}

/// Ann names an SMTP server with her password typed again. It reads back
/// without its password, unverified, and the mail still goes out through
/// the platform.
#[tokio::test]
async fn a_named_smtp_server_reads_back_unverified() {
    let server = server();

    server
        .put(&branding("/mail-provider"))
        .authorization_bearer(TENANT_USER)
        .json(&smtp_switch(REENTERED_PASSWORD))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let provider: Value = server
        .get(&branding("/mail-provider"))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(provider["kind"], "smtp");
    assert_eq!(provider["host"], "smtp.example.com");
    assert_eq!(provider["check"], "unverified");
    assert_eq!(provider["delivers_through"], "platform");
    assert!(!provider.to_string().contains("smtp-secret"));
}

/// Switching the mail provider with an incorrect password returns 403.
#[tokio::test]
async fn a_switch_without_the_right_password_is_forbidden() {
    let response = server()
        .put(&branding("/mail-provider"))
        .authorization_bearer(TENANT_USER)
        .json(&smtp_switch("not the password"))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A tenant request to test the platform mail provider returns 409.
#[tokio::test]
async fn testing_the_platforms_mail_is_a_conflict() {
    let response = server()
        .post(&branding("/mail-provider/test"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::CONFLICT);
}

/// Ann uploads a PNG logo; it is served from the platform's host and is
/// now the tenant's logo.
#[tokio::test]
async fn an_uploaded_logo_becomes_the_tenants_logo() {
    let server = server();
    let form = MultipartForm::new().add_part(
        "logo",
        Part::bytes(acme_logo().bytes().to_vec())
            .file_name("logo.png")
            .mime_type("image/png"),
    );

    let response = server
        .post(&branding("/logo"))
        .authorization_bearer(TENANT_USER)
        .multipart(form)
        .await;

    response.assert_status_ok();
    let served: Value = response.json();
    let current: Value = server
        .get(&branding(""))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(current["logo_url"], served["logo_url"]);
}

/// SVG bytes uploaded with a PNG filename and content type return 422.
#[tokio::test]
async fn a_file_that_is_no_image_is_refused() {
    let form = MultipartForm::new().add_part(
        "logo",
        Part::bytes(b"<svg onload=alert(1)>".to_vec())
            .file_name("logo.png")
            .mime_type("image/png"),
    );

    let response = server()
        .post(&branding("/logo"))
        .authorization_bearer(TENANT_USER)
        .multipart(form)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A form without a `logo` field is refused.
#[tokio::test]
async fn a_form_without_a_logo_is_refused() {
    let form = MultipartForm::new().add_text("name", "logo");

    let response = server()
        .post(&branding("/logo"))
        .authorization_bearer(TENANT_USER)
        .multipart(form)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

//! Files handed out by address: an export downloaded through its link, a
//! tenant's logo, the files the platform publishes, and integrations'
//! pictures.

use std::borrow::Cow;
use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{adapters, router};
use ianua_app::ports::files::{PublishedCaching, PublishedContent, PublishedFile};
use ianua_app::test_support::files::{FakeLinkedFiles, FakePublicLogos, FakePublishedFiles};
use ianua_app::test_support::workflows::{FakeIntegrationCatalog, SHEETS, append_row};
use ianua_assembly::deps::Adapters;
use ianua_domain::domains::branding::logo::LogoImage;
use ianua_domain::types::ActionClass;

const TOKEN: &str = "sealed-ticket";
const CSV: &[u8] = b"id,event\n1,x\n";

/// The API with one download link opening [`CSV`] once.
fn downloads() -> TestServer {
    TestServer::new(router(Adapters {
        linked_files: Arc::new(FakeLinkedFiles::opening(TOKEN, CSV)),
        ..adapters()
    }))
    .unwrap()
}

/// The first bytes of a PNG 64 pixels square: its signature and header.
fn png() -> Vec<u8> {
    let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    bytes.extend_from_slice(&[0, 0, 0, 13]);
    bytes.extend_from_slice(b"IHDR");
    bytes.extend_from_slice(&64_u32.to_be_bytes());
    bytes.extend_from_slice(&64_u32.to_be_bytes());
    bytes.extend_from_slice(&[8, 6, 0, 0, 0]);
    bytes
}

/// Olivia follows the link to her export and is handed the file as an
/// attachment, never cached, with its length.
#[tokio::test]
async fn a_link_downloads_its_file() {
    let response = downloads()
        .get(&format!("/api/v1/files/download/{TOKEN}"))
        .await;

    response.assert_status_ok();
    assert_eq!(response.as_bytes().as_ref(), CSV);
    assert_eq!(response.header("content-type"), "text/csv; charset=utf-8");
    assert_eq!(response.header("content-length"), "13");
    assert_eq!(response.header("cache-control"), "no-store");
    assert!(
        response
            .header("content-disposition")
            .to_str()
            .unwrap()
            .starts_with("attachment;")
    );
}

/// A forged download link returns 404.
#[tokio::test]
async fn a_forged_link_answers_not_found() {
    let response = downloads().get("/api/v1/files/download/forged").await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// A download link succeeds once and returns 404 when reused.
#[tokio::test]
async fn a_used_link_answers_not_found() {
    let server = downloads();
    server
        .get(&format!("/api/v1/files/download/{TOKEN}"))
        .await
        .assert_status_ok();

    let again = server.get(&format!("/api/v1/files/download/{TOKEN}")).await;

    again.assert_status(StatusCode::NOT_FOUND);
}

/// A mail client fetches a tenant's logo with no credentials, and may keep
/// it for good.
#[tokio::test]
async fn a_logo_is_served_publicly_and_cached() {
    let logo = LogoImage::new(png()).unwrap();
    let server = TestServer::new(router(Adapters {
        public_logos: Arc::new(FakePublicLogos::serving("acme", logo)),
        ..adapters()
    }))
    .unwrap();

    let response = server.get("/api/v1/files/logos/acme").await;

    response.assert_status_ok();
    assert_eq!(response.header("content-type"), "image/png");
    assert_eq!(
        response.header("cache-control"),
        "public, max-age=31536000, immutable"
    );
    assert_eq!(response.as_bytes().as_ref(), png().as_slice());
}

/// The API serving `content` as `file`.
fn publishing(file: PublishedFile, content: PublishedContent) -> TestServer {
    TestServer::new(router(Adapters {
        published_files: Arc::new(FakePublishedFiles::serving(file, content)),
        ..adapters()
    }))
    .unwrap()
}

/// A mail client fetches the platform's logo with no credentials, as a
/// PNG it may keep for a week, and is not offered it as a download.
#[tokio::test]
async fn the_email_logo_is_served_publicly_for_a_week() {
    let server = publishing(
        PublishedFile::EmailLogo,
        PublishedContent {
            content_type: "image/png",
            caching: PublishedCaching::WeekUnchanged,
            download_name: None,
            bytes: Cow::Owned(png()),
        },
    );

    let response = server.get("/email-logo.png").await;

    response.assert_status_ok();
    assert_eq!(response.as_bytes().as_ref(), png().as_slice());
    assert_eq!(response.header("content-type"), "image/png");
    assert_eq!(
        response.header("cache-control"),
        "public, max-age=604800, immutable"
    );
    assert!(response.maybe_header("content-disposition").is_none());
}

/// Paul, about to make the role in his AWS account, opens the template
/// with no credentials and reads it inline under its name; it is kept for
/// an hour.
#[tokio::test]
async fn the_aws_template_is_served_publicly_inline_under_its_name() {
    let template: &[u8] = b"AWSTemplateFormatVersion: '2010-09-09'\n";
    let server = publishing(
        PublishedFile::AwsTrustTemplate,
        PublishedContent {
            content_type: "application/x-yaml; charset=utf-8",
            caching: PublishedCaching::Hour,
            download_name: Some("ianua-connect.yaml"),
            bytes: Cow::Borrowed(template),
        },
    );

    let response = server.get("/.well-known/ianua/aws-connect.yaml").await;

    response.assert_status_ok();
    assert_eq!(response.as_bytes().as_ref(), template);
    assert_eq!(
        response.header("content-type"),
        "application/x-yaml; charset=utf-8"
    );
    assert_eq!(
        response.header("content-disposition"),
        "inline; filename=\"ianua-connect.yaml\""
    );
    assert_eq!(response.header("cache-control"), "public, max-age=3600");
}

/// An address naming no logo answers `404`.
#[tokio::test]
async fn an_address_naming_no_logo_answers_not_found() {
    let response = TestServer::new(router(adapters()))
        .unwrap()
        .get("/api/v1/files/logos/nobody")
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// The API with the Sheets integration installed.
fn with_sheets() -> TestServer {
    TestServer::new(router(Adapters {
        integration_catalog: Arc::new(FakeIntegrationCatalog::offering(vec![append_row(
            ActionClass::Write,
        )])),
        ..adapters()
    }))
    .unwrap()
}

/// The dashboard draws an integration from its own picture, fetched with
/// no credentials: SVG, never sniffed as anything else, never run as a page
/// even when opened alone, and kept for an hour.
#[tokio::test]
async fn an_integration_s_picture_is_served_so_nothing_in_it_runs() {
    let response = with_sheets()
        .get(&format!("/api/v1/files/integrations/{SHEETS}/picture.svg"))
        .await;

    response.assert_status_ok();
    assert!(response.text().starts_with("<svg"));
    assert_eq!(response.header("content-type"), "image/svg+xml");
    assert_eq!(response.header("x-content-type-options"), "nosniff");
    assert_eq!(
        response.header("content-security-policy"),
        "default-src 'none'; sandbox"
    );
    assert_eq!(response.header("cache-control"), "public, max-age=3600");
}

/// An uninstalled integration's picture returns 404; a traversal-shaped
/// integration name returns 422.
#[tokio::test]
async fn only_an_installed_integration_has_a_picture() {
    let server = with_sheets();

    let missing = server
        .get("/api/v1/files/integrations/gitea/picture.svg")
        .await;
    let climbing = server
        .get("/api/v1/files/integrations/..%2F..%2Fetc/picture.svg")
        .await;

    missing.assert_status(StatusCode::NOT_FOUND);
    climbing.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

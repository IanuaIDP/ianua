//! Answers handing out a file: an export streamed to whoever holds its
//! download link, a tenant's logo, public and cached, a file the platform
//! publishes, and an integration's picture.

use axum::body::Body;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use ianua_app::ports::files::{OpenedFile, PublishedCaching, PublishedContent};
use ianua_domain::domains::branding::logo::LogoImage;
use ianua_domain::domains::workflows::integration::profile::IntegrationPicture;

/// The headers every download is served with, besides its type, length
/// and name: never sniffed, never cached, and never run as a page.
const DOWNLOAD_HEADERS: [(header::HeaderName, &str); 3] = [
    (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
    (header::CACHE_CONTROL, "no-store"),
    (
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; sandbox",
    ),
];

/// The headers every logo is served with, besides its type: never sniffed,
/// never run as a page, shown on any site's mail and pages, and cached for
/// good, since a new logo gets a new address.
const LOGO_HEADERS: [(header::HeaderName, &str); 4] = [
    (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
    (
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; sandbox",
    ),
    (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
    (
        header::HeaderName::from_static("cross-origin-resource-policy"),
        "cross-origin",
    ),
];

/// The headers every integration picture is served with, besides its
/// type: never sniffed, never run as a page or a script even when opened
/// alone, shown on any site, and cached for an hour, since a new build may
/// bring a new one at the same address.
const PICTURE_HEADERS: [(header::HeaderName, &str); 4] = [
    (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
    (
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; sandbox",
    ),
    (header::CACHE_CONTROL, "public, max-age=3600"),
    (
        header::HeaderName::from_static("cross-origin-resource-policy"),
        "cross-origin",
    ),
];

/// An export file, streamed as an attachment a part at a time, never held
/// whole in memory.
pub(crate) struct FileDownload(pub OpenedFile);

impl IntoResponse for FileDownload {
    fn into_response(self) -> Response {
        let file = self.0;
        let disposition =
            HeaderValue::from_str(&format!("attachment; filename=\"{}\"", file.saved_as))
                .unwrap_or(HeaderValue::from_static("attachment"));
        let mut response = Body::from_stream(file.bytes).into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(file.content_type),
        );
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(file.length));
        headers.insert(header::CONTENT_DISPOSITION, disposition);
        for (name, value) in DOWNLOAD_HEADERS {
            headers.insert(name, HeaderValue::from_static(value));
        }
        response
    }
}

/// A file the platform publishes, in its own type, cached as long as it
/// allows, and shown inline under its name when it has one.
pub(crate) struct PublishedAnswer(pub PublishedContent);

impl IntoResponse for PublishedAnswer {
    fn into_response(self) -> Response {
        let file = self.0;
        let mut response = file.bytes.into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(file.content_type),
        );
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(cache_control(file.caching)),
        );
        if let Some(name) = file.download_name {
            headers.insert(header::CONTENT_DISPOSITION, inline_as(name));
        }
        response
    }
}

/// The `Cache-Control` a published file is served with.
fn cache_control(caching: PublishedCaching) -> &'static str {
    match caching {
        PublishedCaching::WeekUnchanged => "public, max-age=604800, immutable",
        PublishedCaching::Hour => "public, max-age=3600",
    }
}

/// The `Content-Disposition` showing a file inline, saved as `name`.
fn inline_as(name: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("inline; filename=\"{name}\""))
        .unwrap_or(HeaderValue::from_static("inline"))
}

/// A tenant's logo, in its own image type.
pub(crate) struct LogoAnswer(pub LogoImage);

impl IntoResponse for LogoAnswer {
    fn into_response(self) -> Response {
        let content_type = self.0.format().content_type();
        let mut response = self.0.bytes().to_vec().into_response();
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        for (name, value) in LOGO_HEADERS {
            headers.insert(name, HeaderValue::from_static(value));
        }
        response
    }
}

/// An integration's own picture, as SVG.
pub(crate) struct PictureAnswer(pub IntegrationPicture);

impl IntoResponse for PictureAnswer {
    fn into_response(self) -> Response {
        let mut response = self.0.as_str().to_owned().into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("image/svg+xml"),
        );
        for (name, value) in PICTURE_HEADERS {
            headers.insert(name, HeaderValue::from_static(value));
        }
        response
    }
}

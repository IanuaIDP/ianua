//! The logo a branding request uploads, read from its multipart form.

use axum::body::Bytes;
use axum::extract::multipart::MultipartError;
use axum::extract::{FromRequest, FromRequestParts, Multipart, Path, Request};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use ianua_app::error::AppError;
use ianua_domain::domains::branding::logo::LogoImage;
use ianua_domain::message;

use crate::dto::branding::templates::TemplateLocaleParams;
use crate::error::ApiError;
use crate::extractors::form::{FormRefusal, FormRejection};
use crate::extractors::paths::branding::TemplatePath;
use crate::extractors::query::Query;

/// The form field the logo file is sent in.
const LOGO_FIELD: &str = "logo";

/// The template and optional locale selected before reading a template body.
pub(crate) struct TemplateSelection {
    /// The template type from the route.
    pub path: TemplatePath,
    /// The locale query, validated when the body is mapped to its request.
    pub locale: TemplateLocaleParams,
}

impl<S: Send + Sync> FromRequestParts<S> for TemplateSelection {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Path(path) = Path::<TemplatePath>::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;
        let Query(locale) = Query::<TemplateLocaleParams>::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;
        Ok(Self { path, locale })
    }
}

/// The logo a `multipart/form-data` request carries in its `logo` field,
/// checked as an image the way the domain reads one: a PNG or a JPEG from
/// its own bytes, whatever the request says it is, of a logo's size.
///
/// The request body is bounded by the server's body limit, so the file is
/// never read past it: an upload past the limit is answered as too large,
/// any other unreadable form as a validation error.
pub(crate) struct LogoUpload(pub LogoImage);

impl<S: Send + Sync> FromRequest<S> for LogoUpload {
    type Rejection = FormRefusal;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let mut form = Multipart::from_request(request, state)
            .await
            .map_err(ApiError::rejected)?;
        let bytes = logo_bytes(&mut form).await?;
        let image = LogoImage::new(bytes.to_vec())
            .map_err(|refused| ApiError(AppError::from_domain(refused)))?;
        Ok(Self(image))
    }
}

/// The bytes of the form's `logo` field.
///
/// # Errors
///
/// [`FormRefusal`]: too large past the server's body limit, a validation
/// error when the form cannot be read or has no `logo` field.
async fn logo_bytes(form: &mut Multipart) -> Result<Bytes, FormRefusal> {
    while let Some(field) = form.next_field().await.map_err(unreadable)? {
        if field.name() == Some(LOGO_FIELD) {
            return field.bytes().await.map_err(unreadable);
        }
    }
    Err(ApiError::validation(message!(
        "api-the-form-has-no-logo-file",
        "the form has no `logo` file"
    ))
    .into())
}

/// How a form that could not be read is refused.
fn unreadable(error: MultipartError) -> FormRefusal {
    if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
        return FormRejection::TooLarge.into();
    }
    ApiError::rejected(error).into()
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::extract::DefaultBodyLimit;
    use axum::http::header::CONTENT_TYPE;
    use axum::routing::post;
    use tower::ServiceExt as _;

    use super::*;

    /// The form boundary of the test uploads.
    const BOUNDARY: &str = "logo-test";

    /// Answers the format of the logo it was sent.
    async fn format_of(LogoUpload(logo): LogoUpload) -> String {
        logo.format().as_str().to_owned()
    }

    /// The status an upload of `bytes` in the `logo` field is answered
    /// with, under a limit of `limit` bytes.
    async fn status_of(bytes: &[u8], limit: usize) -> StatusCode {
        let app = Router::new()
            .route("/logo", post(format_of))
            .layer(DefaultBodyLimit::max(limit));
        let mut body = format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"logo\"; \
             filename=\"a.png\"\r\n\r\n"
        )
        .into_bytes();
        body.extend_from_slice(bytes);
        body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
        let request = axum::http::Request::post("/logo")
            .header(
                CONTENT_TYPE,
                format!("multipart/form-data; boundary={BOUNDARY}"),
            )
            .body(Body::from(body))
            .unwrap();
        app.oneshot(request).await.unwrap().status()
    }

    /// An upload past the server's body limit is answered as too large,
    /// as the endpoint promises, not as a form that could not be read.
    #[tokio::test]
    async fn an_upload_past_the_body_limit_is_too_large() {
        assert_eq!(
            status_of(&[0; 4096], 512).await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    /// A file within the limit that is no image is refused as no logo.
    #[tokio::test]
    async fn a_file_that_is_no_image_is_refused_as_no_logo() {
        assert_eq!(
            status_of(b"<svg></svg>", 4096).await,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
}

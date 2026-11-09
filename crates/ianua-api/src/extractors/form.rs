//! The form every handler and extractor takes
//! (`application/x-www-form-urlencoded`), as browsers and identity providers
//! post it.
//!
//! A form that cannot be taken is answered with the platform's problem body
//! (`{"error": ..., "message": ...}`) rather than the framework's plain-text
//! page, under the status that says why: `400` for a form that cannot be
//! read, `415` for a body not sent as a form, `413` for one over the size
//! limit, and `422` for a form that is not the shape the endpoint takes. The
//! message is fixed for each: the parser's own wording quotes the fields
//! and their values, which may be a signed assertion, so it is never sent
//! back or logged.

use axum::extract::rejection::FormRejection as FrameworkRejection;
use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ianua_domain::message;
use ianua_domain::shared::errors::Refusal;
use serde::de::DeserializeOwned;

use crate::error::{ApiError, ErrorCode, answered};

/// A form taken from a request.
///
/// A form that cannot be taken is refused with a [`FormRejection`].
pub(crate) struct Form<T>(pub T);

impl<T, S> FromRequest<S> for Form<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = FormRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let axum::extract::Form(form) =
            <axum::extract::Form<T> as FromRequest<S>>::from_request(req, state).await?;
        Ok(Self(form))
    }
}

/// Why a form could not be taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FormRejection {
    /// The form could not be read at all.
    Malformed,
    /// The form reads, but is not the shape the endpoint takes.
    Invalid,
    /// The body was sent without a form `Content-Type`.
    NotForm,
    /// The body is larger than the server takes.
    TooLarge,
}

impl From<FrameworkRejection> for FormRejection {
    fn from(rejection: FrameworkRejection) -> Self {
        match rejection.status() {
            StatusCode::UNPROCESSABLE_ENTITY => Self::Invalid,
            StatusCode::UNSUPPORTED_MEDIA_TYPE => Self::NotForm,
            StatusCode::PAYLOAD_TOO_LARGE => Self::TooLarge,
            _ => Self::Malformed,
        }
    }
}

impl FormRejection {
    /// The status, code and message the caller is answered with.
    #[must_use]
    pub(crate) fn answer(self) -> (StatusCode, ErrorCode, Refusal) {
        let (status, code) = match self {
            Self::Malformed => (StatusCode::BAD_REQUEST, ErrorCode::MalformedBody),
            Self::Invalid => (StatusCode::UNPROCESSABLE_ENTITY, ErrorCode::InvalidBody),
            Self::NotForm => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                ErrorCode::UnsupportedMediaType,
            ),
            Self::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, ErrorCode::BodyTooLarge),
        };
        (status, code, self.message())
    }

    /// Describes the refusal without echoing submitted field values.
    fn message(self) -> Refusal {
        match self {
            Self::Malformed => message!(
                "api-the-body-could-not-be-read-2",
                "The body could not be read as a form"
            ),
            Self::Invalid => message!(
                "api-the-body-is-not-what-this",
                "The body is not what this endpoint takes"
            ),
            Self::NotForm => message!(
                "api-the-body-must-be-sent-as-2",
                "The body must be sent as application/x-www-form-urlencoded"
            ),
            Self::TooLarge => message!(
                "api-the-body-is-larger-than-the",
                "The body is larger than the server takes"
            ),
        }
    }
}

impl IntoResponse for FormRejection {
    fn into_response(self) -> Response {
        let (status, error, refusal) = self.answer();
        tracing::debug!(status = status.as_u16(), "form refused");
        answered(status, error, refusal)
    }
}

/// Why an extractor that reads a form and then checks what it says refused
/// it: the form cannot be taken, answered as [`FormRejection`], or what it
/// says is refused, answered as the [`ApiError`].
pub(crate) enum FormRefusal {
    /// The form cannot be taken.
    Unreadable(FormRejection),
    /// The form reads, but what it says is refused.
    Refused(ApiError),
}

impl From<FormRejection> for FormRefusal {
    fn from(rejection: FormRejection) -> Self {
        Self::Unreadable(rejection)
    }
}

impl From<ApiError> for FormRefusal {
    fn from(error: ApiError) -> Self {
        Self::Refused(error)
    }
}

impl IntoResponse for FormRefusal {
    fn into_response(self) -> Response {
        match self {
            Self::Unreadable(rejection) => rejection.into_response(),
            Self::Refused(error) => error.into_response(),
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::extract::DefaultBodyLimit;
    use axum::http::header::CONTENT_TYPE;
    use axum::routing::post;
    use serde::Deserialize;
    use tower::ServiceExt as _;

    use super::*;

    const FORM: &str = "application/x-www-form-urlencoded";

    /// What the test endpoint takes.
    #[derive(Deserialize)]
    struct Logout {
        state: u32,
    }

    /// Answers the state it was sent.
    async fn echo(Form(logout): Form<Logout>) -> String {
        logout.state.to_string()
    }

    /// The status and body `body` sent as `content_type` is answered with,
    /// under a 64-byte limit.
    async fn send(content_type: Option<&str>, body: &str) -> (StatusCode, String) {
        let app = Router::new()
            .route("/logout", post(echo))
            .layer(DefaultBodyLimit::max(64));
        let mut request = axum::http::Request::post("/logout");
        if let Some(content_type) = content_type {
            request = request.header(CONTENT_TYPE, content_type);
        }
        let response = app
            .oneshot(request.body(Body::from(body.to_owned())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    /// The problem body's `error` code.
    fn code(body: &str) -> String {
        let value: serde_json::Value = serde_json::from_str(body).unwrap();
        value["error"].as_str().unwrap().to_owned()
    }

    /// A form of the right shape reaches the handler.
    #[tokio::test]
    async fn a_form_of_the_right_shape_reaches_the_handler() {
        let (status, body) = send(Some(FORM), "state=7").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "7");
    }

    /// A nonnumeric state returns 422 with an invalid-body problem.
    #[tokio::test]
    async fn a_form_of_the_wrong_shape_is_unprocessable_with_a_problem_body() {
        let (status, body) = send(Some(FORM), "state=seven").await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(code(&body), "invalid_body");
    }

    /// A JSON content type returns 415 with an unsupported-media-type problem.
    #[tokio::test]
    async fn a_body_not_sent_as_a_form_is_an_unsupported_media_type() {
        let (status, body) = send(Some("application/json"), r#"{"state":7}"#).await;

        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(code(&body), "unsupported_media_type");
    }

    /// A form exceeding the body limit returns 413 with a body-too-large problem.
    #[tokio::test]
    async fn a_form_over_the_limit_is_too_large() {
        let long = format!("state={}", "7".repeat(128));

        let (status, body) = send(Some(FORM), &long).await;

        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(code(&body), "body_too_large");
    }

    /// Form rejection omits both the state field and its signed assertion value.
    #[tokio::test]
    async fn a_refusal_never_quotes_the_form() {
        let (_, body) = send(Some(FORM), "state=signed%20assertion").await;

        assert!(!body.contains("signed assertion"));
        assert!(!body.contains("state"));
    }
}

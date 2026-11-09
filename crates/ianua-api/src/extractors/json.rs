//! The JSON body every handler takes, and the JSON it answers with.
//!
//! A body that cannot be taken is answered with the platform's problem body
//! (`{"error": ..., "message": ...}`) rather than the framework's plain-text
//! page, under the status that says why: `400` for JSON that cannot be
//! read, `415` for a body not sent as JSON, `413` for one over the size
//! limit, and `422` for JSON that is not the shape the endpoint takes. The
//! message is fixed for each: the parser's own wording quotes the body's
//! values and keys, which may be a password, so it is never sent back or
//! logged.

use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, OptionalFromRequest, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ianua_domain::message;
use ianua_domain::shared::errors::Refusal;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{ErrorCode, answered};

/// A JSON body taken from a request, or JSON written into an answer.
///
/// Taken from a request, a body that cannot be read is refused with a
/// [`BodyRejection`]. As an optional extractor, a request with no
/// `Content-Type` carries no body, and one with a body is read as above.
/// A body left out is often read as its default, so it has one.
#[derive(Default)]
pub(crate) struct Json<T>(pub T);

impl<T, S> FromRequest<S> for Json<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = BodyRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let axum::Json(body) = <axum::Json<T> as FromRequest<S>>::from_request(req, state).await?;
        Ok(Self(body))
    }
}

impl<T, S> OptionalFromRequest<S> for Json<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = BodyRejection;

    async fn from_request(req: Request, state: &S) -> Result<Option<Self>, Self::Rejection> {
        let body = <axum::Json<T> as OptionalFromRequest<S>>::from_request(req, state).await?;
        Ok(body.map(|axum::Json(body)| Self(body)))
    }
}

impl<T: Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}

/// Why a JSON body could not be taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyRejection {
    /// The body is not JSON that can be read, or could not be read at all.
    Malformed,
    /// The body is JSON, but not the shape the endpoint takes.
    Invalid,
    /// The body was sent without a JSON `Content-Type`.
    NotJson,
    /// The body is larger than the server takes.
    TooLarge,
}

impl From<JsonRejection> for BodyRejection {
    fn from(rejection: JsonRejection) -> Self {
        match rejection.status() {
            StatusCode::UNPROCESSABLE_ENTITY => Self::Invalid,
            StatusCode::UNSUPPORTED_MEDIA_TYPE => Self::NotJson,
            StatusCode::PAYLOAD_TOO_LARGE => Self::TooLarge,
            _ => Self::Malformed,
        }
    }
}

impl BodyRejection {
    /// The status, code and message the caller is answered with.
    #[must_use]
    pub(crate) fn answer(self) -> (StatusCode, ErrorCode, Refusal) {
        let (status, code) = match self {
            Self::Malformed => (StatusCode::BAD_REQUEST, ErrorCode::MalformedBody),
            Self::Invalid => (StatusCode::UNPROCESSABLE_ENTITY, ErrorCode::InvalidBody),
            Self::NotJson => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                ErrorCode::UnsupportedMediaType,
            ),
            Self::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, ErrorCode::BodyTooLarge),
        };
        (status, code, self.message())
    }

    /// Describes the refusal without echoing submitted JSON values.
    fn message(self) -> Refusal {
        match self {
            Self::Malformed => message!(
                "api-the-body-could-not-be-read",
                "The body could not be read as JSON"
            ),
            Self::Invalid => message!(
                "api-the-body-is-not-what-this",
                "The body is not what this endpoint takes"
            ),
            Self::NotJson => message!(
                "api-the-body-must-be-sent-as",
                "The body must be sent as application/json"
            ),
            Self::TooLarge => message!(
                "api-the-body-is-larger-than-the",
                "The body is larger than the server takes"
            ),
        }
    }
}

impl IntoResponse for BodyRejection {
    fn into_response(self) -> Response {
        let (status, error, refusal) = self.answer();
        tracing::debug!(status = status.as_u16(), "request body refused");
        answered(status, error, refusal)
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

    /// What the test endpoint takes.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Login {
        email: String,
    }

    /// Answers the email it was sent.
    async fn echo(Json(login): Json<Login>) -> String {
        login.email
    }

    /// Answers whether a body was sent.
    async fn maybe(body: Option<Json<Login>>) -> &'static str {
        match body {
            Some(_) => "body",
            None => "none",
        }
    }

    /// The status and problem body `body` sent as `content_type` is
    /// answered with, under a 64-byte limit.
    async fn send(path: &str, content_type: Option<&str>, body: &str) -> (StatusCode, String) {
        let app = Router::new()
            .route("/login", post(echo))
            .route("/maybe", post(maybe))
            .layer(DefaultBodyLimit::max(64));
        let mut request = axum::http::Request::post(path);
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

    /// The problem body's `error` code and message.
    fn problem(body: &str) -> (String, String) {
        let value: serde_json::Value = serde_json::from_str(body).unwrap();
        (
            value["error"].as_str().unwrap().to_owned(),
            value["message"].as_str().unwrap().to_owned(),
        )
    }

    /// A readable body reaches the handler.
    #[tokio::test]
    async fn a_body_of_the_right_shape_reaches_the_handler() {
        let (status, body) = send(
            "/login",
            Some("application/json"),
            r#"{"email":"ann@example.test"}"#,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ann@example.test");
    }

    /// Truncated JSON returns 400 with a malformed-body problem.
    #[tokio::test]
    async fn json_cut_off_is_a_bad_request_with_a_problem_body() {
        let (status, body) = send("/login", Some("application/json"), r#"{"email":"ann@"#).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(problem(&body).0, "malformed_body");
    }

    /// A text content type returns 415 with an unsupported-media-type problem.
    #[tokio::test]
    async fn a_body_not_sent_as_json_is_an_unsupported_media_type() {
        let (status, body) = send("/login", Some("text/plain"), r#"{"email":"a"}"#).await;

        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(problem(&body).0, "unsupported_media_type");
    }

    /// A body with no content type at all is refused the same way.
    #[tokio::test]
    async fn a_body_without_a_content_type_is_an_unsupported_media_type() {
        let (status, body) = send("/login", None, r#"{"email":"a"}"#).await;

        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(problem(&body).0, "unsupported_media_type");
    }

    /// JSON exceeding the body limit returns 413 with a body-too-large problem.
    #[tokio::test]
    async fn a_body_over_the_limit_is_too_large() {
        let long = format!(r#"{{"email":"{}"}}"#, "a".repeat(128));

        let (status, body) = send("/login", Some("application/json"), &long).await;

        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(problem(&body).0, "body_too_large");
    }

    /// A numeric email fails deserialization with a 422 invalid-body problem.
    #[tokio::test]
    async fn json_of_the_wrong_shape_is_unprocessable() {
        let (status, body) = send("/login", Some("application/json"), r#"{"email":7}"#).await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(problem(&body).0, "invalid_body");
    }

    /// The fixed rejection message contains neither the password field nor its value.
    #[tokio::test]
    async fn a_refusal_never_quotes_the_body() {
        let (_, body) = send(
            "/login",
            Some("application/json"),
            r#"{"email":"a","password":"hunter two"}"#,
        )
        .await;

        let (_, message) = problem(&body);
        assert!(!body.contains("hunter two"));
        assert!(!body.contains("password"));
        assert_eq!(message, "The body is not what this endpoint takes");
    }

    /// An optional body left out, with no content type, reaches the
    /// handler as none.
    #[tokio::test]
    async fn an_optional_body_left_out_is_none() {
        let (status, body) = send("/maybe", None, "").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "none");
    }

    /// An optional body that contains malformed JSON still returns 400.
    #[tokio::test]
    async fn an_optional_body_sent_broken_is_refused() {
        let (status, body) = send("/maybe", Some("application/json"), "{").await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(problem(&body).0, "malformed_body");
    }
}

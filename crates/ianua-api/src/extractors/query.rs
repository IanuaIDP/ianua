//! The query string every handler and extractor takes.
//!
//! A query string that is not the shape the endpoint takes is answered with
//! the platform's problem body (`{"error": ..., "message": ...}`) under
//! `422`, rather than the framework's plain-text page. The message is
//! fixed: the parser's own wording quotes the parameters and their values,
//! which may be a code or a token, so it is never sent back or logged.

use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use ianua_domain::message;
use ianua_domain::shared::errors::Refusal;
use serde::de::DeserializeOwned;

use crate::error::{ApiError, ErrorCode, answered};

/// A query string taken from a request.
///
/// A query string that does not read as `T` is refused with a
/// [`QueryRejection`].
pub(crate) struct Query<T>(pub T);

impl<T, S> FromRequestParts<S> for Query<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = QueryRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let axum::extract::Query(query) =
            <axum::extract::Query<T> as FromRequestParts<S>>::from_request_parts(parts, state)
                .await
                .map_err(|_| QueryRejection)?;
        Ok(Self(query))
    }
}

/// Why a query string could not be taken: it is not the shape the endpoint
/// takes. A query string always reads, so this is the only reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QueryRejection;

impl QueryRejection {
    /// The status, code and message the caller is answered with.
    #[must_use]
    pub(crate) fn answer(self) -> (StatusCode, ErrorCode, Refusal) {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            ErrorCode::InvalidQuery,
            message!(
                "api-the-query-string-is-not-what",
                "The query string is not what this endpoint takes"
            ),
        )
    }
}

impl IntoResponse for QueryRejection {
    fn into_response(self) -> Response {
        let (status, error, refusal) = self.answer();
        tracing::debug!(status = status.as_u16(), "query string refused");
        answered(status, error, refusal)
    }
}

/// Why an extractor that reads the query and then checks what it says
/// refused it: the query is not the shape it takes, answered as
/// [`QueryRejection`], or what it says is refused, answered as the
/// [`ApiError`].
pub(crate) enum QueryRefusal {
    /// The query is not the shape the extractor takes.
    Unreadable(QueryRejection),
    /// The query reads, but what it says is refused.
    Refused(ApiError),
}

impl From<QueryRejection> for QueryRefusal {
    fn from(rejection: QueryRejection) -> Self {
        Self::Unreadable(rejection)
    }
}

impl From<ApiError> for QueryRefusal {
    fn from(error: ApiError) -> Self {
        Self::Refused(error)
    }
}

impl IntoResponse for QueryRefusal {
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
    use axum::routing::get;
    use serde::Deserialize;
    use tower::ServiceExt as _;

    use super::*;

    /// What the test endpoint takes.
    #[derive(Deserialize)]
    struct Page {
        limit: u32,
    }

    /// Answers the limit it was sent.
    async fn echo(Query(page): Query<Page>) -> String {
        page.limit.to_string()
    }

    /// The status and body `query` is answered with.
    async fn send(query: &str) -> (StatusCode, String) {
        let app = Router::new().route("/items", get(echo));
        let request = axum::http::Request::get(format!("/items{query}"))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    /// A query of the right shape reaches the handler.
    #[tokio::test]
    async fn a_query_of_the_right_shape_reaches_the_handler() {
        let (status, body) = send("?limit=20").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "20");
    }

    /// A nonnumeric query limit returns 422 with an invalid-query problem body.
    #[tokio::test]
    async fn a_query_of_the_wrong_shape_is_unprocessable_with_a_problem_body() {
        let (status, body) = send("?limit=many").await;

        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(value["error"], "invalid_query");
    }

    /// Query rejection omits the submitted code and malformed limit from its message.
    #[tokio::test]
    async fn a_refusal_never_quotes_the_query() {
        let (_, body) = send("?limit=secret%20code").await;

        assert!(!body.contains("secret"));
        assert!(!body.contains("limit"));
    }

    /// A query left out where one is needed is refused the same way.
    #[tokio::test]
    async fn a_missing_query_is_refused() {
        let (status, _) = send("").await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }
}

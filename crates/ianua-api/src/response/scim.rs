//! SCIM responses: bodies sent as `application/scim+json`, as RFC 7644
//! asks, a resource's version sent as its `ETag`, and `304 Not Modified`
//! to a directory that already holds that version.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::error::scim::ScimApiError;
use crate::extractors::scim::IfNoneMatch;

/// What a SCIM endpoint answers: a SCIM body, or a SCIM error.
pub(crate) type ScimResult<T> = Result<ScimJson<T>, ScimApiError>;

/// A resource that carries its version, `meta.version`.
pub(crate) trait ScimVersioned {
    /// The version, a weak entity tag such as `W/"9f2c..."`.
    fn version(&self) -> &str;
}

/// A SCIM body, sent as `application/scim+json`, or no body at all when
/// the directory already holds the version asked for.
pub(crate) struct ScimJson<T: Serialize> {
    status: StatusCode,
    body: Option<T>,
    etag: Option<String>,
}

impl<T: Serialize> ScimJson<T> {
    /// A `200 OK` SCIM body.
    pub(crate) fn ok(body: T) -> Self {
        Self::with_status(StatusCode::OK, body)
    }

    /// A SCIM body with `status`.
    pub(crate) fn with_status(status: StatusCode, body: T) -> Self {
        Self {
            status,
            body: Some(body),
            etag: None,
        }
    }
}

impl<T: Serialize + ScimVersioned> ScimJson<T> {
    /// A resource with `status`, its version sent as the `ETag`.
    pub(crate) fn resource(status: StatusCode, body: T) -> Self {
        Self {
            etag: Some(body.version().to_owned()),
            ..Self::with_status(status, body)
        }
    }

    /// A resource read with `200 OK` and its `ETag`, or `304 Not Modified`
    /// with no body when `held` names its version already.
    pub(crate) fn read(body: T, held: &IfNoneMatch) -> Self {
        if !held.holds(body.version()) {
            return Self::resource(StatusCode::OK, body);
        }
        Self {
            status: StatusCode::NOT_MODIFIED,
            etag: Some(body.version().to_owned()),
            body: None,
        }
    }
}

impl<T: Serialize> IntoResponse for ScimJson<T> {
    fn into_response(self) -> Response {
        let mut response = match self.body {
            Some(body) => with_scim_type((self.status, axum::Json(body)).into_response()),
            None => self.status.into_response(),
        };
        let etag = self.etag.and_then(|etag| HeaderValue::from_str(&etag).ok());
        if let Some(etag) = etag {
            response.headers_mut().insert(header::ETAG, etag);
        }
        response
    }
}

/// `response`, marked `application/scim+json`.
fn with_scim_type(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/scim+json"),
    );
    response
}

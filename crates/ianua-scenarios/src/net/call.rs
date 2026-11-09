//! One request to the platform, as data: what to send, not who sends it,
//! so the same call can be sent by every actor of a matrix.

use std::fmt;

use reqwest::Method;
use serde::Serialize;

use super::redaction;

/// A request: its method, its path under the dashboard's address, its
/// JSON body and its extra headers. `Debug` shows the body redacted.
#[derive(Clone)]
pub struct Call {
    pub(crate) method: Method,
    pub(crate) path: String,
    pub(crate) body: Option<CallBody>,
    pub(crate) headers: Vec<(String, String)>,
}

/// What a call carries: JSON, as every client sends, or bytes as an
/// attacker writes them, such as JSON cut off or a body past every limit.
#[derive(Clone)]
pub(crate) enum CallBody {
    /// A JSON value.
    Json(serde_json::Value),
    /// Text sent as it is, under its content type.
    Raw(RawBody),
    /// Bytes sent as they are, under their content type, such as an image
    /// uploaded in a form.
    Bytes(BytesBody),
}

/// Bytes sent as they are.
#[derive(Clone)]
pub(crate) struct BytesBody {
    /// The `Content-Type` they are sent under.
    pub(crate) content_type: String,
    /// The bytes themselves.
    pub(crate) bytes: Vec<u8>,
}

/// A body sent as it is.
#[derive(Clone)]
pub(crate) struct RawBody {
    /// The `Content-Type` it is sent under.
    pub(crate) content_type: String,
    /// The text itself.
    pub(crate) text: String,
}

impl CallBody {
    /// The body as a request log shows it: JSON redacted, raw text by its
    /// size alone, since it may hold anything.
    pub(crate) fn redacted(&self) -> String {
        match self {
            Self::Json(value) => redaction::json(value),
            Self::Raw(raw) => format!("[{} bytes of {}]", raw.text.len(), raw.content_type),
            Self::Bytes(sent) => format!("[{} bytes of {}]", sent.bytes.len(), sent.content_type),
        }
    }
}

impl fmt::Debug for Call {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Call")
            .field("method", &self.method)
            .field("path", &redaction::path(&self.path))
            .field("body", &self.body.as_ref().map(CallBody::redacted))
            .finish_non_exhaustive()
    }
}

impl Call {
    /// A `GET` of `path`, such as `/api/v1/organizations/acme/users`.
    #[must_use]
    pub fn get(path: impl Into<String>) -> Self {
        Self::of(Method::GET, path)
    }

    /// A `POST` to `path`.
    #[must_use]
    pub fn post(path: impl Into<String>) -> Self {
        Self::of(Method::POST, path)
    }

    /// A `PUT` to `path`.
    #[must_use]
    pub fn put(path: impl Into<String>) -> Self {
        Self::of(Method::PUT, path)
    }

    /// A `PATCH` to `path`.
    #[must_use]
    pub fn patch(path: impl Into<String>) -> Self {
        Self::of(Method::PATCH, path)
    }

    /// A `DELETE` of `path`.
    #[must_use]
    pub fn delete(path: impl Into<String>) -> Self {
        Self::of(Method::DELETE, path)
    }

    /// A `HEAD` of `path`, as a service checks an address before it sends
    /// to it.
    #[must_use]
    pub fn head(path: impl Into<String>) -> Self {
        Self::of(Method::HEAD, path)
    }

    /// An `OPTIONS` of `path`, as a browser sends before a cross-origin
    /// request.
    #[must_use]
    pub fn options(path: impl Into<String>) -> Self {
        Self::of(Method::OPTIONS, path)
    }

    /// This call carrying `body` as JSON.
    ///
    /// # Panics
    ///
    /// When `body` does not serialize to JSON, which a wire type of this
    /// crate always does.
    /// Serialization failure means the scenario constructed an unusable request.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn json(mut self, body: &impl Serialize) -> Self {
        let value = serde_json::to_value(body).expect("a request body serializes to JSON");
        self.body = Some(CallBody::Json(value));
        self
    }

    /// This call carrying `text` exactly as given, under `content_type`:
    /// what a careless or hostile client sends, such as JSON cut off half
    /// way or a body larger than the platform takes.
    #[must_use]
    pub fn raw(mut self, content_type: &str, text: impl Into<String>) -> Self {
        self.body = Some(CallBody::Raw(RawBody {
            content_type: content_type.to_owned(),
            text: text.into(),
        }));
        self
    }

    /// This call carrying `bytes` exactly as given, under `content_type`,
    /// such as a form holding an image file.
    #[must_use]
    pub fn bytes(mut self, content_type: &str, bytes: Vec<u8>) -> Self {
        self.body = Some(CallBody::Bytes(BytesBody {
            content_type: content_type.to_owned(),
            bytes,
        }));
        self
    }

    /// This call carrying the header `name: value` too.
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// `method` on `path`, for a method no client of the platform sends,
    /// such as `TRACE`.
    #[must_use]
    pub fn with_method(method: Method, path: impl Into<String>) -> Self {
        Self::of(method, path)
    }

    fn of(method: Method, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            body: None,
            headers: Vec::new(),
        }
    }
}

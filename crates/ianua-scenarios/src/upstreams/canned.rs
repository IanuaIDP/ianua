//! An app that serves fixed answers, one per path, and keeps every request
//! whole: a records system behind the gateway with a JSON record full of
//! personal fields, or a stand-in for an outside service such as GitHub or
//! Slack that workflow steps call. A path may be answered for one method
//! apart, such as `POST /graphql` beside `GET /graphql`. Every other path
//! is not found.

use std::collections::HashMap;
use std::convert::Infallible;
use std::io;
use std::sync::Arc;

use bytes::Bytes;
use http::header::{CONTENT_ENCODING, CONTENT_TYPE, HeaderValue, LOCATION};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use serde_json::Value;

use super::serving::{Listening, Record};

/// One fixed answer: its status, its type, its encoding, where it sends
/// the caller on, and its bytes.
#[derive(Debug, Clone)]
pub struct Canned {
    status: StatusCode,
    content_type: &'static str,
    encoding: Option<&'static str>,
    location: Option<HeaderValue>,
    body: Bytes,
}

impl Canned {
    /// `record` as a JSON answer.
    #[must_use]
    pub fn json(record: &Value) -> Self {
        Self {
            status: StatusCode::OK,
            content_type: "application/json",
            encoding: None,
            location: None,
            body: Bytes::from(record.to_string()),
        }
    }

    /// `text` as a plain text answer.
    #[must_use]
    pub fn text(text: &str) -> Self {
        Self {
            status: StatusCode::OK,
            content_type: "text/plain",
            encoding: None,
            location: None,
            body: Bytes::from(text.to_owned()),
        }
    }

    /// A `302 Found` sending the caller on to `location`, as a service
    /// that bounces a call somewhere else does.
    ///
    /// # Panics
    ///
    /// When `location` cannot be a header value.
    /// An invalid fixture address must fail the scenario before serving requests.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn redirect(location: &str) -> Self {
        Self {
            status: StatusCode::FOUND,
            location: Some(HeaderValue::from_str(location).expect("an address")),
            ..Self::text("")
        }
    }

    /// An empty JSON object answered with `status`, such as `401` for a
    /// token a service does not know.
    ///
    /// # Panics
    ///
    /// When `status` is no HTTP status.
    /// An invalid fixture status must fail the scenario before serving requests.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn refusing(status: u16) -> Self {
        Self {
            status: StatusCode::from_u16(status).expect("an HTTP status"),
            ..Self::json(&Value::Object(serde_json::Map::new()))
        }
    }

    /// `record` as a JSON answer the app says it compressed. The bytes are
    /// the record as it is: a gateway that reads them as compressed or
    /// passes them on unread is wrong either way.
    #[must_use]
    pub fn compressed_json(record: &Value) -> Self {
        Self {
            encoding: Some("gzip"),
            ..Self::json(record)
        }
    }

    /// `body` as a JSON answer, whatever it holds.
    #[must_use]
    pub fn raw_json(body: &str) -> Self {
        Self {
            status: StatusCode::OK,
            content_type: "application/json",
            encoding: None,
            location: None,
            body: Bytes::from(body.to_owned()),
        }
    }

    /// `body` as a file to download, such as a package's tarball.
    #[must_use]
    pub fn file(body: Vec<u8>) -> Self {
        Self {
            status: StatusCode::OK,
            content_type: "application/octet-stream",
            encoding: None,
            location: None,
            body: Bytes::from(body),
        }
    }

    /// The answer as the app sends it.
    pub(super) fn response(&self) -> Response<Full<Bytes>> {
        let mut answer = Response::new(Full::new(self.body.clone()));
        *answer.status_mut() = self.status;
        let headers = answer.headers_mut();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(self.content_type));
        if let Some(encoding) = self.encoding {
            headers.insert(CONTENT_ENCODING, HeaderValue::from_static(encoding));
        }
        if let Some(location) = &self.location {
            headers.insert(LOCATION, location.clone());
        }
        answer
    }
}

/// One request as it reached the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    /// HTTP verb observed by the fixture after forwarding.
    pub method: String,
    /// Request target used to select the canned response, without its query.
    pub path: String,
    /// What followed the `?` in its address, still escaped, such as the
    /// card's name Trello is sent in the query.
    pub query: Option<String>,
    /// Every header, each name lowercase, in the order received.
    pub headers: Vec<(String, String)>,
    /// Its body, as text.
    pub body: String,
}

impl Received {
    /// Each name and value of its query, unescaped, in the order sent.
    #[must_use]
    pub fn query_pairs(&self) -> Vec<(String, String)> {
        let query = self.query.as_deref().unwrap_or_default();
        url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect()
    }

    /// The first value of the header `name`, if it arrived.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(arrived, _)| arrived.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The body read as JSON, or null when it is not JSON.
    #[must_use]
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

/// The app serving fixed answers.
pub struct CannedApp {
    listening: Listening,
    asked: Record<Received>,
}

impl std::fmt::Debug for CannedApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CannedApp")
            .field("address", &self.listening.address())
            .finish_non_exhaustive()
    }
}

impl CannedApp {
    /// The app, listening on a port of loopback until dropped, answering
    /// each path in `answers` with its answer. A key may also name a method
    /// before the path, such as `POST /graphql`, which is answered before
    /// the path alone.
    ///
    /// # Errors
    ///
    /// When no port can be listened on.
    pub async fn start(answers: impl IntoIterator<Item = (&str, Canned)>) -> io::Result<Self> {
        let answers: Arc<HashMap<String, Canned>> = Arc::new(
            answers
                .into_iter()
                .map(|(path, canned)| (path.to_owned(), canned))
                .collect(),
        );
        let asked = Record::default();
        let kept = asked.clone();
        let listening = Listening::open(move |stream| {
            let answers = Arc::clone(&answers);
            let kept = kept.clone();
            async move {
                let service = service_fn(move |request| {
                    answered(request, Arc::clone(&answers), kept.clone())
                });
                let builder = auto::Builder::new(TokioExecutor::new());
                if let Err(error) = builder
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                {
                    tracing::debug!(%error, "a connection to the canned app ended early");
                }
            }
        })
        .await?;
        Ok(Self { listening, asked })
    }

    /// The address a service names to reach it.
    #[must_use]
    pub fn url(&self) -> String {
        self.listening.url()
    }

    /// How many requests for `path` reached it.
    #[must_use]
    pub fn asked_for(&self, path: &str) -> usize {
        self.asked
            .all()
            .iter()
            .filter(|asked| asked.path == path)
            .count()
    }

    /// Every request that reached it, oldest first.
    #[must_use]
    pub fn received(&self) -> Vec<Received> {
        self.asked.all()
    }
}

/// The fixed answer for `request`'s path, or not found; the request kept.
async fn answered(
    request: Request<Incoming>,
    answers: Arc<HashMap<String, Canned>>,
    kept: Record<Received>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let received = received(request).await;
    let answer = answer_for(&answers, &received.method, &received.path).map(Canned::response);
    kept.keep(received);
    let Some(answer) = answer else {
        let mut missing = Response::new(Full::new(Bytes::new()));
        *missing.status_mut() = StatusCode::NOT_FOUND;
        return Ok(missing);
    };
    Ok(answer)
}

/// What `request` brought, as it is kept: its method, address, headers
/// and body read whole.
pub(super) async fn received(request: Request<Incoming>) -> Received {
    let (parts, body) = request.into_parts();
    let body = body
        .collect()
        .await
        .map(|collected| String::from_utf8_lossy(&collected.to_bytes()).into_owned())
        .unwrap_or_default();
    let headers = parts
        .headers
        .iter()
        .map(|(name, value)| {
            let text = value.to_str().unwrap_or("[not text]");
            (name.as_str().to_owned(), text.to_owned())
        })
        .collect();
    Received {
        method: parts.method.to_string(),
        path: parts.uri.path().to_owned(),
        query: parts.uri.query().map(str::to_owned),
        headers,
        body,
    }
}

/// The answer kept for `method` and `path` together, such as
/// `POST /graphql`, or else for `path` alone.
pub(super) fn answer_for<'a>(
    answers: &'a HashMap<String, Canned>,
    method: &str,
    path: &str,
) -> Option<&'a Canned> {
    answers
        .get(&format!("{method} {path}"))
        .or_else(|| answers.get(path))
}

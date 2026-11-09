//! An app that answers every request with what reached it: the method, the
//! path and query, every header, and what it made of the gateway's
//! assertion, checked against the keys the tenant publishes on its host.

use std::convert::Infallible;
use std::io;

use bytes::Bytes;
use http::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use http::{Request, Response};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use super::assertion::{self, AssertionCheck};
use super::serving::{Listening, Record};
use crate::net;
use crate::stack::Stack;

/// The header the gateway hands its signed identity in.
pub const ASSERTION_HEADER: &str = "x-ianua-assertion";

/// The path the gateway serves a tenant's published assertion keys at, on
/// every host of the tenant.
pub const KEY_SET_PATH: &str = "/.well-known/ianua-assertion-keys.json";

/// The path the gateway's health checks ask by default. The app answers
/// them like any request, but keeps them apart: they are the gateway's own
/// asking, not a caller's request.
pub(crate) const HEALTH_PATH: &str = "/healthz";

/// One request as it reached the app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arrival {
    /// HTTP verb observed behind the gateway, echoed for forwarding assertions.
    pub method: String,
    /// Its path, as the app received it.
    pub path: String,
    /// Its query, if any.
    pub query: Option<String>,
    /// Every header, each name lowercase, in the order received.
    pub headers: Vec<(String, String)>,
    /// What the app made of the assertion it carried.
    pub assertion: AssertionCheck,
}

impl Arrival {
    /// Whether a header named `name`, in any spelling of its case, reached
    /// the app.
    #[must_use]
    pub fn has_header(&self, name: &str) -> bool {
        self.headers
            .iter()
            .any(|(arrived, _)| arrived.eq_ignore_ascii_case(name))
    }

    /// The first value of the header `name`, if it reached the app.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(arrived, _)| arrived.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Where the app reads the tenant's keys, and with what.
#[derive(Clone)]
pub(super) struct Keys {
    at: Url,
    http: reqwest::Client,
}

impl Keys {
    /// The keys the tenant publishes on `tenant_host`, fetched through
    /// `stack`'s gateway as any app fetches them.
    ///
    /// # Errors
    ///
    /// When the address of the keys is no URL, or no client can be made.
    pub(super) fn of(stack: &Stack, tenant_host: &str) -> io::Result<Self> {
        let at = Url::parse(&format!("https://{tenant_host}{KEY_SET_PATH}"))
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let http = net::plain(stack).map_err(io::Error::other)?;
        Ok(Self { at, http })
    }
}

/// The echo app.
pub struct Echo {
    listening: Listening,
    arrivals: Record<Arrival>,
}

impl std::fmt::Debug for Echo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Echo")
            .field("address", &self.listening.address())
            .finish_non_exhaustive()
    }
}

impl Echo {
    /// The app, listening on a port of loopback until dropped, checking
    /// assertions against the keys the tenant publishes on `tenant_host`,
    /// fetched through `stack`'s gateway as any app fetches them.
    ///
    /// # Errors
    ///
    /// When no port can be listened on, or the address of the keys is no
    /// URL.
    pub async fn start(stack: &Stack, tenant_host: &str) -> io::Result<Self> {
        let keys = Keys::of(stack, tenant_host)?;
        let arrivals = Record::default();
        let kept = arrivals.clone();
        let listening = Listening::open(move |stream| {
            let keys = keys.clone();
            let kept = kept.clone();
            async move {
                let service =
                    service_fn(move |request| answered(request, keys.clone(), kept.clone()));
                let builder = auto::Builder::new(TokioExecutor::new());
                if let Err(error) = builder
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                {
                    tracing::debug!(%error, "a connection to the echo app ended early");
                }
            }
        })
        .await?;
        Ok(Self {
            listening,
            arrivals,
        })
    }

    /// The address a service names to reach it.
    #[must_use]
    pub fn url(&self) -> String {
        self.listening.url()
    }

    /// Every request a caller sent that reached it, oldest first: the
    /// gateway's health checks left out.
    #[must_use]
    pub fn arrivals(&self) -> Vec<Arrival> {
        self.arrivals
            .all()
            .into_iter()
            .filter(|arrival| arrival.path != HEALTH_PATH)
            .collect()
    }

    /// How many of the gateway's health checks reached it.
    #[must_use]
    pub fn health_checks(&self) -> usize {
        self.arrivals
            .all()
            .iter()
            .filter(|arrival| arrival.path == HEALTH_PATH)
            .count()
    }

    /// Forgets every request that reached it, so a step counts its own.
    pub fn forget(&self) {
        self.arrivals.clear();
    }
}

/// The answer to `request`: what reached the app, as JSON, kept too.
async fn answered(
    request: Request<Incoming>,
    keys: Keys,
    kept: Record<Arrival>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let assertion = assertion_of(request.headers(), &keys).await;
    let arrival = Arrival {
        method: request.method().to_string(),
        path: request.uri().path().to_owned(),
        query: request.uri().query().map(str::to_owned),
        headers: headers_of(request.headers()),
        assertion,
    };
    kept.keep(arrival.clone());
    let body = serde_json::to_vec(&arrival).unwrap_or_default();
    let mut answer = Response::new(Full::new(Bytes::from(body)));
    answer
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    Ok(answer)
}

/// What the app makes of the assertion in `headers`.
pub(super) async fn assertion_of(headers: &HeaderMap, keys: &Keys) -> AssertionCheck {
    let Some(token) = headers.get(ASSERTION_HEADER) else {
        return AssertionCheck::Absent;
    };
    let Ok(token) = token.to_str() else {
        return AssertionCheck::Refused {
            why: "the header is not text".to_owned(),
        };
    };
    match key_set(keys).await {
        Ok(set) => assertion::checked(token, &set),
        Err(why) => AssertionCheck::Refused { why },
    }
}

/// The tenant's published key set, fetched afresh.
async fn key_set(keys: &Keys) -> Result<Value, String> {
    let answer = keys
        .http
        .get(keys.at.clone())
        .send()
        .await
        .map_err(|error| format!("the key set could not be fetched: {error}"))?;
    if !answer.status().is_success() {
        return Err(format!("the key set answered {}", answer.status()));
    }
    answer
        .json()
        .await
        .map_err(|error| format!("the key set does not read: {error}"))
}

/// Every header in `headers`, as text.
pub(super) fn headers_of(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            let text = value.to_str().unwrap_or("[not text]");
            (name.as_str().to_owned(), text.to_owned())
        })
        .collect()
}

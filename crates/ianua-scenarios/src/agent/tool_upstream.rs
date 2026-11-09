//! The app a platform-run agent's tools call, reached at
//! `AGENT_PROXY_BASE_URL`, where the worker sends every tool call with the
//! run's task token.
//!
//! Until the gateway's start-up exists (gateway wave 3) nothing stands at
//! that address to authorize the call, so this app stands there itself:
//! it answers each call it was given an answer for, and keeps every call
//! it received, so a scenario can say what reached it and what never did.
//! Once the gateway stands there, this app moves behind it as an upstream
//! and the scenarios keep their checks. The run's own refusals, which this
//! part tests, are made by the worker before any call goes out.

use std::convert::Infallible;
use std::fmt;
use std::net::SocketAddr;

use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{Request, Response};
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::wire::Status;

/// The largest call body kept.
const LARGEST_BODY: usize = 256 * 1024;

/// How many orders may wait for the record at once.
const ORDERS: usize = 64;

/// One answer the app gives: to `method` at exactly `path`, `body` as
/// JSON with `status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answering {
    /// The method, such as `GET`.
    pub method: String,
    /// The path, without its query.
    pub path: String,
    /// HTTP outcome returned for requests matching this canned answer.
    pub status: Status,
    /// The JSON body.
    pub body: String,
}

impl Answering {
    /// `body` with `Status::OK` to `method` at `path`.
    #[must_use]
    pub fn ok(method: &str, path: &str, body: &serde_json::Value) -> Self {
        Self {
            method: method.to_owned(),
            path: path.to_owned(),
            status: Status::OK,
            body: body.to_string(),
        }
    }
}

/// One call the app received. Whether it bore a bearer token is kept, not
/// the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    /// HTTP verb observed at the upstream after the worker sent the call.
    pub method: String,
    /// Request target observed at the upstream, excluding its query.
    pub path: String,
    /// Its query, if any.
    pub query: Option<String>,
    /// Whether it carried `Authorization: Bearer`.
    pub bore_a_token: bool,
    /// Its body, as text.
    pub body: String,
}

/// What the record's task is told.
enum Order {
    /// Keep `call`.
    Keep(ToolCall),
    /// Answer every call kept so far.
    List(oneshot::Sender<Vec<ToolCall>>),
}

/// The app, listening on a port of loopback until dropped.
pub struct ToolUpstream {
    address: SocketAddr,
    orders: mpsc::Sender<Order>,
    accepting: JoinHandle<()>,
}

impl fmt::Debug for ToolUpstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolUpstream")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl ToolUpstream {
    /// The app giving `answers`, and `Status::NOT_FOUND` to every other call.
    ///
    /// # Errors
    ///
    /// When no port can be listened on.
    pub async fn start(answers: Vec<Answering>) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        let (orders, kept) = mpsc::channel(ORDERS);
        tokio::spawn(record(kept));
        let accepting = serve(listener, answers, orders.clone());
        Ok(Self {
            address,
            orders,
            accepting,
        })
    }

    /// Its address, for `AGENT_PROXY_BASE_URL`.
    #[must_use]
    pub fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }

    /// Every call received, in order.
    pub async fn calls(&self) -> Vec<ToolCall> {
        let (reply, answer) = oneshot::channel();
        if self.orders.send(Order::List(reply)).await.is_err() {
            return Vec::new();
        }
        answer.await.unwrap_or_default()
    }
}

impl Drop for ToolUpstream {
    /// Stops taking connections.
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

/// Keeps every call until every handle is dropped.
async fn record(mut orders: mpsc::Receiver<Order>) {
    let mut calls = Vec::new();
    while let Some(order) = orders.recv().await {
        match order {
            Order::Keep(call) => calls.push(call),
            Order::List(reply) => {
                let _ignored = reply.send(calls.clone());
            }
        }
    }
}

/// Takes connections on `listener`, each served as a task of its own.
fn serve(
    listener: TcpListener,
    answers: Vec<Answering>,
    orders: mpsc::Sender<Order>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let answers = answers.clone();
            let orders = orders.clone();
            tokio::spawn(async move {
                let service =
                    service_fn(move |request| answered(request, answers.clone(), orders.clone()));
                let served = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
                if let Err(error) = served {
                    tracing::debug!(%error, "a connection to the tool upstream ended early");
                }
            });
        }
    })
}

/// The answer to one call, the call kept first.
async fn answered(
    request: Request<Incoming>,
    answers: Vec<Answering>,
    orders: mpsc::Sender<Order>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let call = call_of(request).await;
    let found = answers
        .iter()
        .find(|answer| answer.method == call.method && answer.path == call.path)
        .cloned();
    let _kept = orders.send(Order::Keep(call)).await;
    let (status, body) = found.map_or_else(
        || {
            (
                Status::NOT_FOUND,
                r#"{"error":"no such tool endpoint"}"#.to_owned(),
            )
        },
        |answer| (answer.status, answer.body),
    );
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    Ok(response)
}

/// The call `request` makes, its body read up to the largest kept.
async fn call_of(request: Request<Incoming>) -> ToolCall {
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().map(str::to_owned);
    let bore_a_token = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("Bearer "));
    let body = Limited::new(request.into_body(), LARGEST_BODY)
        .collect()
        .await
        .map(|collected| String::from_utf8_lossy(&collected.to_bytes()).into_owned())
        .unwrap_or_default();
    ToolCall {
        method,
        path,
        query,
        bore_a_token,
        body,
    }
}

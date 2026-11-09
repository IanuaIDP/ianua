//! The outside HTTP service workflows deliver to: it takes the account's
//! credential and no other, answers as told to, and counts what reached
//! it and what it accepted, so a scenario reads from the service itself
//! whether a run really called it. It keeps the reply a call carries in
//! its `x-reply` header, so a scenario reads what text reached it.

// A stand-in that cannot bind a port or read its own counters fails the
// scenario using it, which is what a panic here means.
#![allow(clippy::expect_used)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{HeaderValue, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};

/// The credential the connected account holds for the service: a readable
/// sentence, so no scanner takes it for a key.
pub const OUTSIDE_CREDENTIAL: &str = "workflow account credential 4917";

/// What the service has seen, and how it answers now.
#[derive(Default)]
struct State {
    calls: AtomicUsize,
    delivered: AtomicUsize,
    status: AtomicU16,
    replies: Mutex<Vec<String>>,
}

/// The header a delivery may carry a reply in, which the service keeps
/// as it arrived.
const REPLY_HEADER: &str = "x-reply";

/// The outside service, listening on a port of its own for the scenario.
pub struct OutsideService {
    address: SocketAddr,
    state: Arc<State>,
    listener: JoinHandle<()>,
}

impl OutsideService {
    /// The service, listening on the loopback, answering success to every
    /// call that carries the credential.
    ///
    /// # Panics
    ///
    /// When no port can be listened on, which ends the scenario's setup.
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port for the outside service");
        let address = listener.local_addr().expect("the service's address");
        let state = Arc::new(State::default());
        state.status.store(200, Ordering::SeqCst);
        let served = Arc::clone(&state);
        let listener = tokio::spawn(serve_connections(listener, served));
        Self {
            address,
            state,
            listener,
        }
    }

    /// The origin the account's credential may be sent to, and no other.
    pub fn origin(&self) -> String {
        format!("http://{}", self.address)
    }

    /// The address the delivery step calls.
    pub fn url(&self) -> String {
        format!("{}/deliver", self.origin())
    }

    /// The account's credential as the `http` integration takes it: the
    /// origin it is bound to and the token sent there.
    pub fn credential(&self) -> String {
        json!({"origin": self.origin(), "token": OUTSIDE_CREDENTIAL}).to_string()
    }

    /// From now on every call is received and then refused with a server
    /// error, so a run fails after reaching the service.
    pub fn fail(&self) {
        self.state.status.store(500, Ordering::SeqCst);
    }

    /// From now on calls succeed again.
    pub fn recover(&self) {
        self.state.status.store(200, Ordering::SeqCst);
    }

    /// How many calls reached the service, accepted or not.
    pub fn calls(&self) -> usize {
        self.state.calls.load(Ordering::SeqCst)
    }

    /// How many calls carried the credential and were answered success.
    pub fn delivered(&self) -> usize {
        self.state.delivered.load(Ordering::SeqCst)
    }

    /// The replies calls carried in their `x-reply` header, in the order
    /// they arrived, exactly as the service received them.
    ///
    /// # Panics
    ///
    /// When the replies' lock was poisoned by a call that panicked.
    pub fn replies(&self) -> Vec<String> {
        self.state
            .replies
            .lock()
            .expect("the replies are readable")
            .clone()
    }
}

/// Accepts service connections until the listener closes, reaping completed handlers.
async fn serve_connections(listener: TcpListener, served: Arc<State>) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { break };
                let state = Arc::clone(&served);
                connections.spawn(async move {
                    let handler = service_fn(move |request| answered(request, Arc::clone(&state)));
                    let builder = auto::Builder::new(TokioExecutor::new());
                    let _closed = builder.serve_connection(TokioIo::new(stream), handler).await;
                });
            }
            _finished = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

impl Drop for OutsideService {
    /// Stops listening when the scenario lets it go.
    fn drop(&mut self) {
        self.listener.abort();
    }
}

/// Keeps the reply `request` carries in its reply header, if any.
fn keep_reply(request: &Request<Incoming>, state: &State) {
    let Some(reply) = request
        .headers()
        .get(REPLY_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return;
    };
    state
        .replies
        .lock()
        .expect("the replies are writable")
        .push(reply.to_owned());
}

/// The answer to `request`: success as the service stands now when the
/// request carries the credential, else unauthorized; the credential
/// itself is neither kept nor echoed.
async fn answered(
    request: Request<Incoming>,
    state: Arc<State>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    state.calls.fetch_add(1, Ordering::SeqCst);
    keep_reply(&request, &state);
    let authorized = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        == Some(&format!("Bearer {OUTSIDE_CREDENTIAL}"));
    let status = if authorized {
        StatusCode::from_u16(state.status.load(Ordering::SeqCst)).expect("a valid status")
    } else {
        StatusCode::UNAUTHORIZED
    };
    if status == StatusCode::OK {
        state.delivered.fetch_add(1, Ordering::SeqCst);
    }
    let mut response = Response::new(Full::new(Bytes::from_static(
        b"{\"delivered\":\"real outside service\"}",
    )));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
    Ok(response)
}

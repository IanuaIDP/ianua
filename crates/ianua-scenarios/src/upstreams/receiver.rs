//! A customer's service outside the platform, reached as a public one
//! would be: an HTTPS server on loopback standing at a public-looking
//! name the stack's name server answers, under an authority only this
//! stand-in holds, which the stack trusts through
//! `OUTBOUND_DELIVERY_CA_FILE`. Each path is answered as told, and every
//! request is kept whole, so a scenario reads exactly what reached it.
//! Answers can be scripted for the next few requests, such as two
//! refusals before the delivery that succeeds.

// A stand-in that cannot bind a port or make its certificate fails the
// scenario using it, which is what a panic here means.
#![allow(clippy::expect_used)]

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, PoisonError};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rcgen::{CertificateParams, KeyPair};
use tempfile::NamedTempFile;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use super::canned::{Canned, Received, answer_for, received};
use super::serving::{Listening, Record};
use crate::providers::oidc::tls_config;
use crate::stack::Stack;

/// The answers scripted for the next requests, in order.
type Scripted = Arc<Mutex<VecDeque<Canned>>>;

/// The answers kept for each path.
type Answers = Arc<HashMap<String, Canned>>;

/// The customer's service, stopped when dropped.
pub struct OutsideReceiver {
    listening: Listening,
    host: String,
    authority: NamedTempFile,
    asked: Record<Received>,
    scripted: Scripted,
}

impl std::fmt::Debug for OutsideReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutsideReceiver")
            .field("host", &self.host)
            .field("address", &self.listening.address())
            .finish_non_exhaustive()
    }
}

impl OutsideReceiver {
    /// The service, listening on a port of loopback at `host`, answering
    /// each path in `answers` with its answer, its certificate written to
    /// a file the stack trusts.
    ///
    /// # Panics
    ///
    /// When the port, certificate, TLS configuration or authority file
    /// cannot be made, which ends the scenario's setup.
    pub async fn start(host: &str, answers: impl IntoIterator<Item = (&str, Canned)>) -> Self {
        let (acceptor, authority) = certified(host);
        let asked = Record::default();
        let scripted = Scripted::default();
        let replies = Replies {
            answers: Arc::new(
                answers
                    .into_iter()
                    .map(|(path, canned)| (path.to_owned(), canned))
                    .collect(),
            ),
            asked: asked.clone(),
            scripted: Arc::clone(&scripted),
        };
        let listening =
            Listening::open(move |stream| connection(stream, acceptor.clone(), replies.clone()))
                .await
                .expect("a port for the receiver");
        Self {
            listening,
            host: host.to_owned(),
            authority,
            asked,
            scripted,
        }
    }

    /// The authority file the stack trusts the service's certificate by.
    ///
    /// # Panics
    ///
    /// When the temporary file's path is not UTF-8.
    #[must_use]
    pub fn authority_file(&self) -> &str {
        self.authority.path().to_str().expect("a UTF-8 path")
    }

    /// The host and port, as a deployment lists it, `jira.acme.example:8443`.
    #[must_use]
    pub fn host_and_port(&self) -> String {
        format!("{}:{}", self.host, self.listening.address().port())
    }

    /// The address of `path`, once `stack`'s name server points the
    /// service's name at loopback.
    #[must_use]
    pub fn url_on(&self, stack: &Stack, path: &str) -> String {
        stack.name_server().write_a(&self.host, Ipv4Addr::LOCALHOST);
        format!("https://{}{path}", self.host_and_port())
    }

    /// Answers the next requests with `answers`, in order, whatever their
    /// path; after them, each path is answered as usual.
    pub fn answer_next(&self, answers: impl IntoIterator<Item = Canned>) {
        self.scripted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(answers);
    }

    /// Every request that reached it, oldest first.
    #[must_use]
    pub fn received(&self) -> Vec<Received> {
        self.asked.all()
    }

    /// Every request with `method` at `path` that reached it, oldest first.
    #[must_use]
    pub fn received_at(&self, method: &str, path: &str) -> Vec<Received> {
        self.asked
            .all()
            .into_iter()
            .filter(|asked| asked.method == method && asked.path == path)
            .collect()
    }
}

/// What a connection answers with and where it keeps what it was asked.
#[derive(Clone)]
struct Replies {
    answers: Answers,
    asked: Record<Received>,
    scripted: Scripted,
}

/// A TLS acceptor for `host`, and the file a stack trusts its certificate by.
fn certified(host: &str) -> (TlsAcceptor, NamedTempFile) {
    let key = KeyPair::generate().expect("a server key");
    let certificate = CertificateParams::new(vec![host.to_owned()])
        .expect("parameters")
        .self_signed(&key)
        .expect("a server certificate");
    let acceptor = TlsAcceptor::from(Arc::new(tls_config(&key, &certificate)));
    let authority = NamedTempFile::new().expect("an authority file");
    std::fs::write(authority.path(), certificate.pem()).expect("write the authority");
    (acceptor, authority)
}

/// Serves one connection: its TLS, then HTTP, each request kept.
async fn connection(stream: TcpStream, tls: TlsAcceptor, replies: Replies) {
    let Ok(stream) = tls.accept(stream).await else {
        return;
    };
    let service = service_fn(move |request| answered(request, replies.clone()));
    let builder = auto::Builder::new(TokioExecutor::new());
    if let Err(error) = builder
        .serve_connection(TokioIo::new(stream), service)
        .await
    {
        tracing::debug!(%error, "a connection to the outside receiver ended early");
    }
}

/// The answer scripted next, or kept for `request`'s path, or not found;
/// the request kept.
async fn answered(
    request: Request<Incoming>,
    replies: Replies,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let received = received(request).await;
    let next = replies
        .scripted
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .pop_front();
    let answer =
        next.or_else(|| answer_for(&replies.answers, &received.method, &received.path).cloned());
    replies.asked.keep(received);
    let Some(answer) = answer else {
        let mut missing = Response::new(Full::new(Bytes::new()));
        *missing.status_mut() = StatusCode::NOT_FOUND;
        return Ok(missing);
    };
    Ok(answer.response())
}

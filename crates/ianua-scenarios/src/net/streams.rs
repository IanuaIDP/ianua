//! A connection of its own to the gateway, for a request or an answer
//! that moves a piece at a time: a scenario sees what the gateway passed
//! on before the rest was sent, which a client taking in whole messages
//! cannot show.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::header::HOST;
use http::{Method, Request, Response};
use http_body_util::BodyExt as _;
use hyper::body::{Body, Frame, Incoming};
use hyper::client::conn::http1::{self, SendRequest};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::pem::PemObject as _;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use crate::stack::Stack;
use crate::wire::Status;

/// The pieces of a body waiting to be sent at once: few, so a piece is
/// handed over only when the one before it has moved on.
const PIECES_WAITING: usize = 4;

/// Why a streamed exchange failed.
#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    /// The gateway took no connection.
    #[error("the gateway took no connection")]
    Connect(#[source] std::io::Error),
    /// The stack's authority does not read, or TLS could not be set up.
    #[error("TLS could not be set up")]
    Tls(#[source] tokio_rustls::rustls::Error),
    /// The stack's authority is not a certificate.
    #[error("the stack's authority does not read as PEM")]
    Authority(#[source] tokio_rustls::rustls::pki_types::pem::Error),
    /// The host is no server name.
    #[error("{0} is no server name")]
    Name(String),
    /// The request could not be built.
    #[error("the request could not be built")]
    Request(#[source] http::Error),
    /// The HTTP exchange failed.
    #[error("the exchange failed")]
    Exchange(#[source] hyper::Error),
    /// The task carrying the exchange ended early.
    #[error("the exchange's task ended early")]
    Task(#[source] tokio::task::JoinError),
    /// The gateway stopped reading the body.
    #[error("the gateway stopped reading the body")]
    Closed,
}

/// Where a request on a connection of its own goes, and the headers it
/// carries, such as the cookie of the person sending it.
#[derive(Debug, Clone)]
pub struct Target {
    host: String,
    path: String,
    headers: Vec<(String, String)>,
}

impl Target {
    /// `path` on `host`, carrying no headers yet.
    #[must_use]
    pub fn new(host: &str, path: &str) -> Self {
        Self {
            host: host.to_owned(),
            path: path.to_owned(),
            headers: Vec::new(),
        }
    }

    /// The same request also sending the header `name`.
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// The HTTP/1.1 request for `method` with `body`.
    fn request<B>(&self, method: Method, body: B) -> Result<Request<B>, StreamError> {
        let mut request = Request::builder()
            .method(method)
            .uri(self.path.as_str())
            .header(HOST, self.host.as_str());
        for (name, value) in &self.headers {
            request = request.header(name.as_str(), value.as_str());
        }
        request.body(body).map_err(StreamError::Request)
    }
}

/// An answer taken in whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Whole {
    /// What the far end answered with.
    pub status: Status,
    /// Everything it sent back, whole.
    pub body: Vec<u8>,
}

/// A request whose body is sent a piece at a time.
#[derive(Debug)]
pub struct Upload {
    pieces: mpsc::Sender<Bytes>,
    answer: JoinHandle<Result<Whole, StreamError>>,
}

impl Upload {
    /// Starts a `POST` to `target` through `stack`'s gateway, with none of
    /// its body sent yet.
    ///
    /// # Errors
    ///
    /// [`StreamError`] when the connection or the exchange cannot be made.
    pub async fn begin(stack: &Stack, target: &Target) -> Result<Self, StreamError> {
        let mut sender = connected(stack, &target.host).await?;
        let (pieces, body) = Pieces::channel(PIECES_WAITING);
        let request = target.request(Method::POST, body)?;
        let answer = tokio::spawn(async move {
            let response = sender
                .send_request(request)
                .await
                .map_err(StreamError::Exchange)?;
            whole(response).await
        });
        Ok(Self { pieces, answer })
    }

    /// Sends `piece` on.
    ///
    /// # Errors
    ///
    /// [`StreamError::Closed`] when the gateway stopped reading, as it
    /// does once it has answered.
    pub async fn send(&self, piece: Bytes) -> Result<(), StreamError> {
        self.pieces
            .send(piece)
            .await
            .map_err(|_| StreamError::Closed)
    }

    /// Ends the body and takes in the answer.
    ///
    /// # Errors
    ///
    /// [`StreamError`] when no whole answer came.
    pub async fn finish(self) -> Result<Whole, StreamError> {
        drop(self.pieces);
        self.answer.await.map_err(StreamError::Task)?
    }
}

/// An answer read a piece at a time.
pub struct Download {
    status: Status,
    body: Incoming,
    _sender: SendRequest<Pieces>,
}

impl std::fmt::Debug for Download {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Download")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl Download {
    /// Sends a `GET` to `target` through `stack`'s gateway and waits for
    /// the head of its answer alone.
    ///
    /// # Errors
    ///
    /// [`StreamError`] when no answer starts.
    pub async fn begin(stack: &Stack, target: &Target) -> Result<Self, StreamError> {
        let mut sender = connected(stack, &target.host).await?;
        let (ended, body) = Pieces::channel(1);
        drop(ended);
        let request = target.request(Method::GET, body)?;
        let response = sender
            .send_request(request)
            .await
            .map_err(StreamError::Exchange)?;
        let status = response.status();
        Ok(Self {
            status,
            body: response.into_body(),
            _sender: sender,
        })
    }

    /// The answer's status.
    #[must_use]
    pub fn status(&self) -> Status {
        self.status
    }

    /// The next piece of the body that arrives, `None` once it has ended.
    ///
    /// # Errors
    ///
    /// [`StreamError::Exchange`] when the body breaks off.
    pub async fn next_piece(&mut self) -> Result<Option<Bytes>, StreamError> {
        while let Some(frame) = self.body.frame().await {
            let frame = frame.map_err(StreamError::Exchange)?;
            let Ok(data) = frame.into_data() else {
                continue;
            };
            return Ok(Some(data));
        }
        Ok(None)
    }

    /// All of the body still to come.
    ///
    /// # Errors
    ///
    /// [`StreamError::Exchange`] when the body breaks off.
    pub async fn rest(mut self) -> Result<Vec<u8>, StreamError> {
        let mut taken = Vec::new();
        while let Some(piece) = self.next_piece().await? {
            taken.extend_from_slice(&piece);
        }
        Ok(taken)
    }
}

/// A body handed over a piece at a time, ending when its sender is
/// dropped; shared with the apps that stream an answer.
pub(crate) struct Pieces {
    receiver: mpsc::Receiver<Bytes>,
}

impl Pieces {
    /// A sender of pieces, at most `waiting` of them held at once, and the
    /// body it fills.
    pub(crate) fn channel(waiting: usize) -> (mpsc::Sender<Bytes>, Self) {
        let (sender, receiver) = mpsc::channel(waiting);
        (sender, Self { receiver })
    }
}

impl Body for Pieces {
    type Data = Bytes;
    type Error = Infallible;

    /// The next piece, once its sender has handed one over.
    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.get_mut()
            .receiver
            .poll_recv(context)
            .map(|piece| piece.map(|bytes| Ok(Frame::data(bytes))))
    }

    /// Whether the sender has gone and nothing is left, so a `GET` sends
    /// no body at all.
    fn is_end_stream(&self) -> bool {
        self.receiver.is_closed() && self.receiver.is_empty()
    }
}

/// `response` with all of its body read.
async fn whole(response: Response<Incoming>) -> Result<Whole, StreamError> {
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(StreamError::Exchange)?
        .to_bytes()
        .to_vec();
    Ok(Whole { status, body })
}

/// An HTTP/1.1 connection to the gateway for `host`, its work carried on
/// by a task of its own.
async fn connected(stack: &Stack, host: &str) -> Result<SendRequest<Pieces>, StreamError> {
    let line = tls_line(stack, host).await?;
    let (sender, connection) = http1::handshake(TokioIo::new(line))
        .await
        .map_err(StreamError::Exchange)?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "a streamed connection to the gateway ended early");
        }
    });
    Ok(sender)
}

/// A TLS connection to the gateway for `host`, trusting `stack`'s
/// authority alone and speaking only HTTP/1.1.
async fn tls_line(stack: &Stack, host: &str) -> Result<TlsStream<TcpStream>, StreamError> {
    let mut config = tls_config(stack)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name =
        ServerName::try_from(host.to_owned()).map_err(|_| StreamError::Name(host.to_owned()))?;
    let tcp = TcpStream::connect(stack.gateway())
        .await
        .map_err(StreamError::Connect)?;
    TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .map_err(StreamError::Connect)
}

/// A client's TLS settings trusting `stack`'s authority alone.
fn tls_config(stack: &Stack) -> Result<ClientConfig, StreamError> {
    let mut roots = RootCertStore::empty();
    for root in CertificateDer::pem_slice_iter(stack.root_certificate_pem().as_bytes()) {
        roots
            .add(root.map_err(StreamError::Authority)?)
            .map_err(StreamError::Tls)?;
    }
    let config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(StreamError::Tls)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(config)
}

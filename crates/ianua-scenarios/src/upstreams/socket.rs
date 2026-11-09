//! An app speaking WebSocket behind the gateway: it switches protocols on
//! a handshake, keeps what reached it of the handshake, checks the
//! gateway's assertion as [`Echo`](super::Echo) does, and answers every
//! text message with the same words after `heard: `.

use std::convert::Infallible;
use std::io;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::header::{CONNECTION, HeaderValue, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, UPGRADE};
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use sha1::{Digest as _, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use super::echo::{Arrival, Keys, assertion_of, headers_of};
use super::serving::{Listening, Record};
use crate::stack::Stack;

/// The value the accept header is worked out with, from RFC 6455.
const ACCEPT_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The first byte of a whole text message.
const WHOLE_TEXT: u8 = 0x81;

/// What a frame's first byte says is text, once its flags are taken off.
const TEXT_OPCODE: u8 = 0x1;

/// The most a frame's short length can say.
const SHORT_LENGTH: u8 = 125;

/// The short length saying a two-byte length follows.
const TWO_BYTE_LENGTH: u8 = 126;

/// What the app's connections share.
#[derive(Clone)]
struct Shared {
    keys: Keys,
    handshakes: Record<Arrival>,
    heard: Record<String>,
}

/// The WebSocket app.
pub struct SocketApp {
    listening: Listening,
    handshakes: Record<Arrival>,
    heard: Record<String>,
}

impl std::fmt::Debug for SocketApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocketApp")
            .field("address", &self.listening.address())
            .finish_non_exhaustive()
    }
}

impl SocketApp {
    /// The app, listening on a port of loopback until dropped, checking
    /// assertions against the keys the tenant publishes on `tenant_host`.
    ///
    /// # Errors
    ///
    /// When no port can be listened on, or the address of the keys is no
    /// URL.
    pub async fn start(stack: &Stack, tenant_host: &str) -> io::Result<Self> {
        let handshakes = Record::default();
        let heard = Record::default();
        let shared = Shared {
            keys: Keys::of(stack, tenant_host)?,
            handshakes: handshakes.clone(),
            heard: heard.clone(),
        };
        let listening = Listening::open(move |stream| serve(stream, shared.clone())).await?;
        Ok(Self {
            listening,
            handshakes,
            heard,
        })
    }

    /// The address a service names to reach it.
    #[must_use]
    pub fn url(&self) -> String {
        self.listening.url()
    }

    /// Every handshake that reached it, oldest first.
    #[must_use]
    pub fn handshakes(&self) -> Vec<Arrival> {
        self.handshakes.all()
    }

    /// Every message it heard, oldest first.
    #[must_use]
    pub fn heard(&self) -> Vec<String> {
        self.heard.all()
    }
}

/// Serves one connection, upgrades included.
async fn serve(stream: tokio::net::TcpStream, shared: Shared) {
    let service = service_fn(move |request| answered(request, shared.clone()));
    let builder = auto::Builder::new(TokioExecutor::new());
    if let Err(error) = builder
        .serve_connection_with_upgrades(TokioIo::new(stream), service)
        .await
    {
        tracing::debug!(%error, "a connection to the socket app ended early");
    }
}

/// The answer to `request`: a switch for a handshake, kept, with the
/// talk carried on by a task of its own; for anything else, that an
/// upgrade is required.
async fn answered(
    mut request: Request<Incoming>,
    shared: Shared,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let Some(key) = request.headers().get(SEC_WEBSOCKET_KEY).cloned() else {
        return Ok(plain(StatusCode::UPGRADE_REQUIRED));
    };
    let assertion = assertion_of(request.headers(), &shared.keys).await;
    shared.handshakes.keep(Arrival {
        method: request.method().to_string(),
        path: request.uri().path().to_owned(),
        query: request.uri().query().map(str::to_owned),
        headers: headers_of(request.headers()),
        assertion,
    });
    let upgrade = hyper::upgrade::on(&mut request);
    tokio::spawn(talk(upgrade, shared));
    Ok(switched(&key))
}

/// An empty answer with `status`.
fn plain(status: StatusCode) -> Response<Full<Bytes>> {
    let mut answer = Response::new(Full::new(Bytes::new()));
    *answer.status_mut() = status;
    answer
}

/// The switch answering the handshake that sent `key`.
fn switched(key: &HeaderValue) -> Response<Full<Bytes>> {
    let Ok(accept) = HeaderValue::from_str(&accept_for(key.as_bytes())) else {
        return plain(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let mut answer = plain(StatusCode::SWITCHING_PROTOCOLS);
    let headers = answer.headers_mut();
    headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
    headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    headers.insert(SEC_WEBSOCKET_ACCEPT, accept);
    answer
}

/// The accept value that answers `key`.
fn accept_for(key: &[u8]) -> String {
    let mut digest = Sha1::new();
    digest.update(key);
    digest.update(ACCEPT_GUID.as_bytes());
    STANDARD.encode(digest.finalize())
}

/// Hears each text message and answers it, until anything else arrives.
async fn talk(upgrade: OnUpgrade, shared: Shared) {
    let Ok(upgraded) = upgrade.await else {
        return;
    };
    let mut line = TokioIo::new(upgraded);
    while let Some(text) = next_text(&mut line).await {
        let answer = format!("heard: {text}");
        shared.heard.keep(text);
        if send_text(&mut line, &answer).await.is_err() {
            return;
        }
    }
}

/// The next text message a client sent, `None` for anything else: a
/// close, a frame that does not read, or the connection ending.
async fn next_text<S: AsyncRead + Unpin>(line: &mut S) -> Option<String> {
    let mut head = [0_u8; 2];
    line.read_exact(&mut head).await.ok()?;
    let [first, second] = head;
    if first & 0x0F != TEXT_OPCODE {
        return None;
    }
    let length = match second & 0x7F {
        TWO_BYTE_LENGTH => usize::from(line.read_u16().await.ok()?),
        short if short <= SHORT_LENGTH => usize::from(short),
        _ => return None,
    };
    let mut mask = [0_u8; 4];
    line.read_exact(&mut mask).await.ok()?;
    let mut payload = vec![0_u8; length];
    line.read_exact(&mut payload).await.ok()?;
    for (byte, key) in payload.iter_mut().zip(mask.iter().cycle()) {
        *byte ^= key;
    }
    String::from_utf8(payload).ok()
}

/// Sends `text` as one short unmasked message, as a server's must be.
async fn send_text<S: AsyncWrite + Unpin>(line: &mut S, text: &str) -> io::Result<()> {
    let length = u8::try_from(text.len())
        .ok()
        .filter(|length| *length <= SHORT_LENGTH)
        .ok_or_else(|| io::Error::other("a message too long for a short frame"))?;
    let mut frame = vec![WHOLE_TEXT, length];
    frame.extend_from_slice(text.as_bytes());
    line.write_all(&frame).await?;
    line.flush().await
}

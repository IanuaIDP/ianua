//! An app that takes bodies and gives them a piece at a time, for showing
//! the gateway moves them without holding them whole: it counts each
//! piece of an upload as it arrives, and sends the first piece of a
//! download only, holding back the rest until a scenario releases it.

use std::convert::Infallible;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::watch;

use super::serving::{Listening, Record};
use crate::net::streams::Pieces;

/// How big each piece of a download is, past the first.
const PIECE_BYTES: usize = 64 * 1024;

/// The pieces of a download waiting to be sent at once.
const PIECES_WAITING: usize = 4;

/// What the path of a download ends in; anything else asked for is
/// answered empty, so a probe waiting on the route is never held back.
const DOWNLOAD_ENDING: &str = "/archive";

/// The bytes a body of `length` carries: a steady pattern, so a scenario
/// knows what must arrive.
#[must_use]
pub fn pattern(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| u8::try_from(index % 251).unwrap_or(0))
        .collect()
}

/// The hex digest of `bytes`, as [`Uploaded`] names a body.
#[must_use]
pub fn digest_of(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// How much of a download comes at once and how much is held back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadSizes {
    /// The bytes sent as soon as the download starts.
    pub first: usize,
    /// The bytes held back until the app is released.
    pub held: usize,
}

/// One upload the app took whole, as it answers it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Uploaded {
    /// How many bytes arrived.
    pub bytes: usize,
    /// The hex digest of those bytes.
    pub digest: String,
}

/// What the app's connections share.
#[derive(Clone)]
struct Shared {
    sizes: DownloadSizes,
    received: Arc<AtomicUsize>,
    uploads: Record<Uploaded>,
    released: watch::Receiver<bool>,
}

/// The body the app answers with.
type Answer = Response<UnsyncBoxBody<Bytes, Infallible>>;

/// The app.
pub struct Pipe {
    listening: Listening,
    received: Arc<AtomicUsize>,
    uploads: Record<Uploaded>,
    release: watch::Sender<bool>,
}

impl std::fmt::Debug for Pipe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pipe")
            .field("address", &self.listening.address())
            .finish_non_exhaustive()
    }
}

impl Pipe {
    /// The app, listening on a port of loopback until dropped, its
    /// downloads as `sizes` says.
    ///
    /// # Errors
    ///
    /// When no port can be listened on.
    pub async fn start(sizes: DownloadSizes) -> io::Result<Self> {
        let (release, released) = watch::channel(false);
        let received = Arc::new(AtomicUsize::new(0));
        let uploads = Record::default();
        let shared = Shared {
            sizes,
            received: Arc::clone(&received),
            uploads: uploads.clone(),
            released,
        };
        let listening = Listening::open(move |stream| serve(stream, shared.clone())).await?;
        Ok(Self {
            listening,
            received,
            uploads,
            release,
        })
    }

    /// The address a service names to reach it.
    #[must_use]
    pub fn url(&self) -> String {
        self.listening.url()
    }

    /// How many bytes of uploads have arrived so far, finished or not.
    #[must_use]
    pub fn received(&self) -> usize {
        self.received.load(Ordering::Relaxed)
    }

    /// Every upload that arrived whole, oldest first.
    #[must_use]
    pub fn uploads(&self) -> Vec<Uploaded> {
        self.uploads.all()
    }

    /// Lets every download, now and later, send what it held back.
    pub fn release(&self) {
        self.release.send_replace(true);
    }
}

/// Serves one connection.
async fn serve(stream: tokio::net::TcpStream, shared: Shared) {
    let service = service_fn(move |request| answered(request, shared.clone()));
    let builder = auto::Builder::new(TokioExecutor::new());
    if let Err(error) = builder
        .serve_connection(TokioIo::new(stream), service)
        .await
    {
        tracing::debug!(%error, "a connection to the pipe app ended early");
    }
}

/// The answer to `request`: an upload is read whole and described, a
/// `GET` of the path [`DOWNLOAD_ENDING`] closes starts a download, and
/// every other request, such as a health check or a probe asking whether
/// the route is served yet, is answered empty at once.
async fn answered(request: Request<Incoming>, shared: Shared) -> Result<Answer, Infallible> {
    if request.method() == Method::POST {
        return Ok(uploaded(request.into_body(), shared).await);
    }
    if request.uri().path().ends_with(DOWNLOAD_ENDING) {
        return Ok(download(shared));
    }
    Ok(plain(StatusCode::OK, Bytes::new()))
}

/// An answer of `body` with `status`.
fn plain(status: StatusCode, body: Bytes) -> Answer {
    let mut answer = Response::new(Full::new(body).boxed_unsync());
    *answer.status_mut() = status;
    answer
}

/// Reads `body` a piece at a time, counting each piece as it arrives,
/// and describes it; one that breaks off is kept as nothing.
async fn uploaded(mut body: Incoming, shared: Shared) -> Answer {
    let mut digest = Sha256::new();
    let mut bytes = 0;
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else {
            return plain(StatusCode::BAD_REQUEST, Bytes::new());
        };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        bytes += data.len();
        shared.received.fetch_add(data.len(), Ordering::Relaxed);
        digest.update(&data);
    }
    let whole = Uploaded {
        bytes,
        digest: format!("{:x}", digest.finalize()),
    };
    shared.uploads.keep(whole.clone());
    let described = serde_json::to_vec(&whole).unwrap_or_default();
    plain(StatusCode::OK, Bytes::from(described))
}

/// A download whose first piece goes out at once, the rest only once the
/// app is released.
fn download(shared: Shared) -> Answer {
    let (pieces, body) = Pieces::channel(PIECES_WAITING);
    tokio::spawn(async move {
        let DownloadSizes { first, held } = shared.sizes;
        let whole = pattern(first + held);
        let (now, later) = whole.split_at(first);
        if pieces.send(Bytes::copy_from_slice(now)).await.is_err() {
            return;
        }
        let mut released = shared.released;
        if released.wait_for(|released| *released).await.is_err() {
            return;
        }
        for piece in later.chunks(PIECE_BYTES) {
            if pieces.send(Bytes::copy_from_slice(piece)).await.is_err() {
                return;
            }
        }
    });
    Response::new(body.boxed_unsync())
}

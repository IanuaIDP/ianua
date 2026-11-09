//! The internal listener's accept loop and its connections.

use std::convert::Infallible;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use ianua_boot::shutdown::Shutdown;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::runtime::answers::Runtime;

/// Connections held at once: a few probes and a scraper on fixed
/// intervals, far below the public listener's, so a misbehaving scraper
/// cannot take what serves requests. Past it a connection is closed at
/// once.
const MAX_CONNECTIONS: usize = 32;

/// The longest a client may take to send its request's head.
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);

/// The longest one connection may stay open, whatever it is doing.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(15);

/// The pause after a failed accept, such as when the process is out of
/// file descriptors, so the loop does not spin.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// Accepts connections on `socket` until `shutdown` stops, serving each
/// through `runtime` under the connection bound.
pub(super) async fn accept_until_stopped(
    socket: TcpListener,
    runtime: Arc<Runtime>,
    shutdown: Shutdown,
) {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut stopping = pin!(shutdown.stopping());
    loop {
        let accepted = tokio::select! {
            () = &mut stopping => return,
            accepted = socket.accept() => accepted,
        };
        let Ok((stream, _)) = accepted else {
            tokio::time::sleep(ACCEPT_BACKOFF).await;
            continue;
        };
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            tracing::debug!("internal listener full; a connection was closed");
            continue;
        };
        let runtime = Arc::clone(&runtime);
        shutdown.spawn_until_stopped(async move {
            serve(stream, runtime).await;
            drop(permit);
        });
    }
}

/// Serves one connection: HTTP/1 only, one request, bounded in time.
async fn serve(stream: TcpStream, runtime: Arc<Runtime>) {
    let service = service_fn(move |request| {
        let runtime = Arc::clone(&runtime);
        async move { Ok::<_, Infallible>(runtime.answer(&request).await) }
    });
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .keep_alive(false);
    let connection = builder.serve_connection(TokioIo::new(stream), service);
    match tokio::time::timeout(CONNECTION_TIMEOUT, connection).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::debug!(%error, "an internal connection ended"),
        Err(_) => tracing::debug!("an internal connection was cut off"),
    }
}

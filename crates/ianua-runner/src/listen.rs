//! The listener the agent talks to: each connection taken while there is
//! room for it, each request's head read within its time, and every
//! request handed to the [`Runner`].

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use ianua_boot::shutdown::Shutdown;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::handler::Runner;

/// How long the loop waits after the listener failed to take a
/// connection, so a lack of file handles does not spin it.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// What one connection may take on.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionLimits {
    /// The most connections held at once; one past it is closed at once.
    pub connections: usize,
    /// How long the agent may take to send a request's head.
    pub header: Duration,
}

/// Takes the agent's connections on `listener` until `shutdown` stops,
/// each served on a task `shutdown` waits for.
pub async fn accept(
    listener: TcpListener,
    runner: Arc<Runner>,
    limits: ConnectionLimits,
    shutdown: Shutdown,
) {
    let room = Arc::new(Semaphore::new(limits.connections));
    loop {
        let accepted = tokio::select! {
            () = shutdown.stopping() => return,
            accepted = listener.accept() => accepted,
        };
        let stream = match accepted {
            Ok((stream, _)) => stream,
            Err(error) => {
                tracing::warn!(%error, "the agent's listener could not take a connection");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        let Ok(held) = Arc::clone(&room).try_acquire_owned() else {
            tracing::warn!("a connection from the agent was closed: the runner holds all it may");
            continue;
        };
        let runner = Arc::clone(&runner);
        shutdown.spawn_until_stopped(async move {
            serve(stream, runner, limits.header).await;
            drop(held);
        });
    }
}

/// Serves the requests of one connection.
async fn serve(stream: TcpStream, runner: Arc<Runner>, header: Duration) {
    let service = service_fn(move |request: hyper::Request<Incoming>| {
        let runner = Arc::clone(&runner);
        async move { Ok::<_, Infallible>(runner.handle(request).await) }
    });
    let served = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(header)
        .serve_connection(TokioIo::new(stream), service)
        .await;
    if let Err(error) = served {
        tracing::debug!(%error, "a connection from the agent ended");
    }
}

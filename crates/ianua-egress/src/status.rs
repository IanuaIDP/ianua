//! The health probes, answered on a listener of their own apart from the
//! services': `/health/live` while the process runs, `/health/ready` while
//! it holds every tenant's database route as last read.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use ianua_boot::shutdown::Shutdown;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// The most probe connections held at once.
const PROBE_CONNECTIONS: usize = 16;

/// How long a probe may take to send its request's head.
const PROBE_HEADER: Duration = Duration::from_secs(5);

/// Whether the egress gateway may take traffic: once it read every
/// tenant's database route, and while the last reading held.
#[derive(Debug, Default)]
pub struct Readiness {
    routes: AtomicBool,
}

impl Readiness {
    /// Every tenant's route was read.
    pub fn routes_read(&self) {
        self.routes.store(true, Ordering::Release);
    }

    /// The tenants' routes could not be read again.
    pub fn routes_unread(&self) {
        self.routes.store(false, Ordering::Release);
    }

    /// Whether it may take traffic.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.routes.load(Ordering::Acquire)
    }
}

/// Answers the probes on `listener` until `shutdown` stops.
pub async fn answer(listener: TcpListener, readiness: Arc<Readiness>, shutdown: Shutdown) {
    let room = Arc::new(Semaphore::new(PROBE_CONNECTIONS));
    loop {
        let accepted = tokio::select! {
            () = shutdown.stopping() => return,
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, _)) = accepted else {
            continue;
        };
        let Ok(held) = Arc::clone(&room).try_acquire_owned() else {
            continue;
        };
        let readiness = Arc::clone(&readiness);
        shutdown.spawn_until_stopped(async move {
            let service = service_fn(move |request: Request<Incoming>| {
                let status = status_for(request.uri().path(), &readiness);
                async move { Ok::<_, Infallible>(empty(status)) }
            });
            let _ = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(PROBE_HEADER)
                .serve_connection(TokioIo::new(stream), service)
                .await;
            drop(held);
        });
    }
}

/// The status a probe of `path` is answered with.
fn status_for(path: &str, readiness: &Readiness) -> StatusCode {
    match path {
        "/health/live" => StatusCode::OK,
        "/health/ready" if readiness.is_ready() => StatusCode::OK,
        "/health/ready" => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::NOT_FOUND,
    }
}

/// An empty answer with `status`.
fn empty(status: StatusCode) -> Response<Empty<Bytes>> {
    let mut response = Response::new(Empty::new());
    *response.status_mut() = status;
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live while running; ready only while the routes were read; nothing
    /// else is answered.
    #[test]
    fn readiness_follows_the_routes() {
        let readiness = Readiness::default();

        let before = status_for("/health/ready", &readiness);
        readiness.routes_read();
        let after = status_for("/health/ready", &readiness);
        readiness.routes_unread();
        let lost = status_for("/health/ready", &readiness);

        assert_eq!(status_for("/health/live", &readiness), StatusCode::OK);
        assert_eq!(before, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(after, StatusCode::OK);
        assert_eq!(lost, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(status_for("/metrics", &readiness), StatusCode::NOT_FOUND);
    }
}

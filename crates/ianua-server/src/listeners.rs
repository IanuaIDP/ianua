//! The listeners: the public API, and the internal one every node opens,
//! whatever its mode, for its probes and its scrape.
//!
//! Each is spawned through the [`Shutdown`]: at the stop it takes no new
//! connection and finishes the requests in flight, and the process waits
//! for it for the grace period. What a listener takes on at once, how
//! large a body may be and how long a request may take are the router's
//! own, as `ianua-api` builds it from the HTTP settings.

use std::net::SocketAddr;

use axum::Router;
use ianua_assembly::runtime::RuntimePorts;
use ianua_boot::shutdown::Shutdown;
use tokio::net::TcpListener;

use crate::config::Config;
use crate::error::ServerError;
use crate::platform::Platform;

/// Selects the public API, internal probes or relay socket to bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listener {
    /// The public API, on `HOST` and `PORT`.
    Public,
    /// The internal listener, on `HOST` and `INTERNAL_PORT`: the probes and
    /// the scrape on every node.
    Internal,
    /// The relay listener, on `HOST` and `RELAY_PORT`: the gateway's app
    /// sign-in relay and approval questions on an API node, over mutual
    /// TLS.
    Relay,
}

impl Listener {
    /// The listener's name, for the logs and a refusal.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Relay => "relay",
        }
    }
}

/// Opens `listener` on `address` and serves `router` on it until the stop,
/// then finishes the requests in flight; returns the address it listens
/// on, which names the port given when `address` asked for any.
///
/// # Errors
///
/// [`ServerError::Listen`] when the address cannot be listened on.
pub async fn serve(
    listener: Listener,
    router: Router,
    address: SocketAddr,
    shutdown: &Shutdown,
) -> Result<SocketAddr, ServerError> {
    let refused = |cause| ServerError::Listen {
        listener: listener.name(),
        address,
        cause,
    };
    let socket = TcpListener::bind(address).await.map_err(refused)?;
    let bound = socket.local_addr().map_err(refused)?;
    let served = axum::serve(
        socket,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown.stopping());
    shutdown.spawn(listener.name(), async move {
        if let Err(error) = served.await {
            tracing::error!(listener = listener.name(), %error, "the listener failed");
        }
    });
    tracing::info!(listener = listener.name(), address = %bound, "listening");
    Ok(bound)
}

/// Opens the internal listener of a node serving no API, such as a
/// worker: the probes and the scrape alone, over the platform's probes and
/// metrics, bounded as `INTERNAL_*` says. An API node opens its own
/// internal listener over its API's state, so call this only where `MODE`
/// runs no API.
///
/// # Errors
///
/// [`ServerError::Listen`] when `HOST` and `INTERNAL_PORT` cannot be
/// listened on.
pub(crate) async fn serve_runtime(
    platform: &Platform,
    config: &Config,
    shutdown: &Shutdown,
) -> Result<SocketAddr, ServerError> {
    let router =
        ianua_api::router::build_runtime(runtime_ports(platform), config.http.internal_limits);
    serve(Listener::Internal, router, config.http.internal, shutdown).await
}

/// What the probes and the scrape read: the platform's probes and its
/// metrics exporter.
#[must_use]
pub fn runtime_ports(platform: &Platform) -> RuntimePorts {
    RuntimePorts {
        database: platform.readiness.database.clone(),
        message_bus: platform.readiness.bus.clone(),
        cache: platform.readiness.cache.clone(),
        exporter: platform.metrics.exporter.clone(),
    }
}

#[cfg(test)]
mod tests;

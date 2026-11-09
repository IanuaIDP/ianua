//! The API: the app's adapters built from the platform, its settings read
//! from the configuration, and the listeners serving them.

mod http;

use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use axum::serve::ListenerExt as _;
use ianua_api::state::Deps;
use ianua_boot::shutdown::Shutdown;
use tokio::net::TcpListener;

use crate::assembly::{Assembly, assembly};
use crate::config::Config;
use crate::config::serving::{RelayConfig, RelayTls};
use crate::error::ServerError;
use crate::listeners::{self, Listener};
use crate::mutual_listener::{self, MutualListener, MutualPem};
use crate::platform::Platform;

/// How long a caller of the relay listener has to finish its TLS
/// handshake.
const RELAY_HANDSHAKE: Duration = Duration::from_secs(5);

/// Everything the API is built from: the assembly's adapters and settings,
/// and the HTTP layer's own settings, from the configuration. Built once a
/// process.
///
/// # Errors
///
/// [`ServerError::Config`] naming a setting the type it is read into
/// refuses, and [`ServerError::Platform`] naming an adapter whose client
/// could not be built.
pub fn deps(platform: &Platform, config: &Config) -> Result<Deps, ServerError> {
    let Assembly { adapters, settings } = assembly(platform, config)?;
    Ok(Deps {
        adapters,
        settings,
        http: http::http(config)?,
        trusted_proxies: config.http.trusted_proxies.clone(),
    })
}

/// Opens the API's listeners over `deps`: the public one on `HOST` and
/// `PORT`, the internal one with the probes and the scrape on
/// `INTERNAL_PORT`, and the relay the gateway asks on `RELAY_PORT`; each
/// spawned through the shutdown so a stop lets its requests in flight
/// finish. Returns once all three listen, with where they listen.
///
/// # Errors
///
/// [`ServerError::Listen`] when a listener cannot be opened, and
/// [`ServerError::RelayTls`] when the relay's certificates do not read.
pub async fn run(
    _platform: &Platform,
    config: &Config,
    shutdown: &Shutdown,
    deps: &Deps,
) -> Result<ApiAddresses, ServerError> {
    let public = ianua_api::router::build(deps);
    let internal = ianua_api::router::build_internal(deps);
    let public = listeners::serve(Listener::Public, public, config.http.public, shutdown).await?;
    let internal =
        listeners::serve(Listener::Internal, internal, config.http.internal, shutdown).await?;
    let relay = match &config.relay {
        Some(relay) => {
            Some(serve_relay(ianua_api::router::build_relay(deps), relay, shutdown).await?)
        }
        None => None,
    };
    Ok(ApiAddresses {
        public,
        internal,
        relay,
    })
}

/// Opens the relay listener as `relay` says: mutual TLS with its files,
/// or plain HTTP outside production. Mutual connections pass through an
/// empty tap, the one way axum hands a listener of its own's peer address
/// to the handlers as it does a plain socket's.
async fn serve_relay(
    router: Router,
    relay: &RelayConfig,
    shutdown: &Shutdown,
) -> Result<SocketAddr, ServerError> {
    let RelayTls::Mutual {
        authority,
        chain,
        key,
    } = &relay.tls
    else {
        return listeners::serve(Listener::Relay, router, relay.address, shutdown).await;
    };
    let config = mutual_listener::server_config(&MutualPem {
        authority,
        chain,
        key: key.expose(),
    })?;
    let refused = |cause| ServerError::Listen {
        listener: Listener::Relay.name(),
        address: relay.address,
        cause,
    };
    let socket = TcpListener::bind(relay.address).await.map_err(refused)?;
    let listener =
        MutualListener::start(socket, config, RELAY_HANDSHAKE, shutdown).map_err(refused)?;
    serve_mutual(router, listener, relay.address, shutdown)
}

/// Starts serving authenticated relay connections and reports the bound address.
fn serve_mutual(
    router: Router,
    listener: MutualListener,
    address: SocketAddr,
    shutdown: &Shutdown,
) -> Result<SocketAddr, ServerError> {
    let bound =
        axum::serve::Listener::local_addr(&listener).map_err(|cause| ServerError::Listen {
            listener: Listener::Relay.name(),
            address,
            cause,
        })?;
    let served = axum::serve(
        listener.tap_io(|_| {}),
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown.stopping());
    shutdown.spawn(Listener::Relay.name(), async move {
        if let Err(error) = served.await {
            tracing::error!(listener = Listener::Relay.name(), %error, "the listener failed");
        }
    });
    tracing::info!(listener = Listener::Relay.name(), address = %bound, tls = "mutual", "listening");
    Ok(bound)
}

/// Where the API's three listeners listen, the ports named even where the
/// settings asked for any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiAddresses {
    /// The public API.
    pub public: SocketAddr,
    /// The internal listener: the probes and the scrape.
    pub internal: SocketAddr,
    /// The relay listener the gateway asks, opened when the configuration
    /// was read for `serve`.
    pub relay: Option<SocketAddr>,
}

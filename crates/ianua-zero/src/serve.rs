//! Running the gateway until a stop.
//!
//! The binary goes through [`on_platform`], which sets up the logs and
//! stops on a signal. The end-to-end scenarios start the same gateway in
//! their own process through [`serving`]: the same configuration, the same
//! adapters, the same listeners, under a stop they hold and with logs they
//! set up themselves.

use std::net::SocketAddr;

use ianua_boot::env::Env;
use ianua_boot::logging;
use ianua_boot::shutdown::{Shutdown, ShutdownError};

use crate::boot::start;
use crate::config::Config;
use crate::error::GatewayError;
use crate::stream::StreamPorts;

/// Where a serving gateway listens, the ports named even where the
/// settings asked for any.
#[derive(Debug, Clone)]
pub struct Serving {
    /// The public listener every request to a tenant's apps reaches.
    pub public: SocketAddr,
    /// The status listener: `/health/live`, `/health/ready`, `/metrics`.
    pub status: SocketAddr,
    /// The plain HTTP listener ACME challenges are fetched from, when set.
    pub acme: Option<SocketAddr>,
    /// The in-cluster listener agent runners send through, when set.
    pub runners: Option<SocketAddr>,
    /// The in-cluster listener Protected apps steps call, when set.
    pub workflows: Option<SocketAddr>,
    /// The stream routes' ports, as they open and close with the routes.
    pub streams: StreamPorts,
    /// The listener connectors link in on, when set.
    pub connectors: Option<SocketAddr>,
}

/// Reads the configuration from `vars`, sets up the logs, builds the
/// gateway and serves until a signal stops it.
///
/// # Errors
///
/// [`GatewayError`] for the first thing that failed, or a stop that did
/// not go cleanly.
pub async fn on_platform(vars: &Env) -> Result<(), GatewayError> {
    let config = Config::read(vars)?;
    logging::init(&config.logging)?;
    announce(vars);
    let shutdown = Shutdown::new(config.listen.shutdown_grace);
    shutdown.stop_on_signals()?;
    started(&config, &shutdown).await?;
    tracing::info!("running");
    shutdown.join().await?;
    tracing::info!("stopped");
    Ok(())
}

/// Builds the gateway `vars` describes and starts it serving under
/// `shutdown`, answering once every listener listens. The caller holds the
/// stop and sets up the logs; nothing here listens for a signal.
///
/// # Errors
///
/// [`GatewayError`] for the first thing that failed; what had started is
/// stopped again.
pub async fn serving(vars: &Env, shutdown: &Shutdown) -> Result<Serving, GatewayError> {
    let config = Config::read(vars)?;
    announce(vars);
    started(&config, shutdown).await
}

/// Starts the gateway; one that cannot start stops what started before.
async fn started(config: &Config, shutdown: &Shutdown) -> Result<Serving, GatewayError> {
    let outcome = start::start(config, shutdown).await;
    if outcome.is_err() {
        shutdown.stop();
        log_unclean(shutdown.join().await);
    }
    outcome
}

/// Logs which settings the gateway starts with, by name alone.
fn announce(vars: &Env) {
    tracing::info!(settings = ?vars.set_names(), "the gateway starts with these settings set");
}

/// Logs a stop that did not go cleanly, when another error is the one to
/// answer with.
fn log_unclean(joined: Result<(), ShutdownError>) {
    if let Err(error) = joined {
        tracing::warn!(%error, "the stop did not go cleanly");
    }
}

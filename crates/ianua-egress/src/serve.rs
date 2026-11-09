//! Starting the egress gateway: from the binary, until a stop; or from a
//! test or a scenario through [`serving`], under a stop the caller holds.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ianua_boot::env::Env;
use ianua_boot::logging;
use ianua_boot::shutdown::Shutdown;
use ianua_domain::shared::errors::causes;
use ianua_infra::postgres::Databases;
use ianua_infra::postgres::tenant::load_tenant_databases;
use tokio::net::TcpListener;

use crate::config::Config;
use crate::error::EgressError;
use crate::listen::{ConnectionLimits, Taking, accept};
use crate::parts::{Built, built};
use crate::status::{Readiness, answer};

/// Where a serving egress gateway listens, the ports named even where the
/// settings asked for any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Serving {
    /// The services' listener.
    pub address: SocketAddr,
    /// The health probes' listener.
    pub status: SocketAddr,
}

/// Reads the configuration from `vars`, sets up the logs, and serves until
/// SIGTERM or Ctrl-C, then waits for the connections in flight.
///
/// # Errors
///
/// [`EgressError`] for the first thing that failed.
pub async fn run(vars: &Env) -> Result<(), EgressError> {
    let config = Config::read(vars)?;
    logging::init(&config.logging)?;
    let shutdown = Shutdown::new(config.limits.shutdown_grace);
    shutdown.stop_on_signals()?;
    started(vars, &config, &shutdown).await?;
    shutdown.join().await?;
    tracing::info!("stopped");
    Ok(())
}

/// Builds the egress gateway `vars` describes and starts it serving under
/// `shutdown`, answering once both listeners listen. The caller holds the
/// stop and sets up the logs; nothing here listens for a signal.
///
/// # Errors
///
/// [`EgressError`] for the first thing that failed.
pub async fn serving(vars: &Env, shutdown: &Shutdown) -> Result<Serving, EgressError> {
    let config = Config::read(vars)?;
    started(vars, &config, shutdown).await
}

/// Builds the egress gateway and starts its listeners and the reading of
/// the tenants' routes.
async fn started(vars: &Env, config: &Config, shutdown: &Shutdown) -> Result<Serving, EgressError> {
    let built = built(config, shutdown).await?;
    let readiness = Arc::new(Readiness::default());
    readiness.routes_read();
    let services = bound(config.listen.address).await?;
    let probes = bound(config.listen.status).await?;
    let serving = Serving {
        address: services.local_addr().map_err(EgressError::Listen)?,
        status: probes.local_addr().map_err(EgressError::Listen)?,
    };
    start_services(services, &built, config, shutdown);
    shutdown.spawn(
        "the health listener",
        answer(probes, Arc::clone(&readiness), shutdown.clone()),
    );
    shutdown.spawn_until_stopped(follow_routes(
        built.databases,
        config.routes_reload,
        readiness,
    ));
    tracing::info!(
        address = %serving.address,
        status = %serving.status,
        settings = ?vars.set_names(),
        "serving egress"
    );
    Ok(serving)
}

/// Runs the TLS service listener with the configured connection and header limits.
fn start_services(services: TcpListener, built: &Built, config: &Config, shutdown: &Shutdown) {
    let limits = ConnectionLimits {
        connections: config.limits.connections,
        handshake: config.limits.handshake,
        header: config.limits.header,
    };
    shutdown.spawn(
        "the egress listener",
        accept(
            services,
            Taking {
                acceptor: built.acceptor.clone(),
                egress: Arc::clone(&built.egress),
                limits,
            },
            shutdown.clone(),
        ),
    );
}

/// A listener on `address`.
async fn bound(address: SocketAddr) -> Result<TcpListener, EgressError> {
    TcpListener::bind(address)
        .await
        .map_err(EgressError::Listen)
}

/// Reads every tenant's database route again each `every`, so a tenant
/// moved to a database of its own is read there; the egress gateway is not
/// ready while a reading fails.
async fn follow_routes(databases: Arc<Databases>, every: Duration, readiness: Arc<Readiness>) {
    let mut ticks = tokio::time::interval(every);
    ticks.tick().await;
    loop {
        ticks.tick().await;
        match load_tenant_databases(&databases).await {
            Ok(()) => readiness.routes_read(),
            Err(error) => {
                tracing::error!(error = %causes(&error), "the tenants' routes could not be read again");
                readiness.routes_unread();
            }
        }
    }
}

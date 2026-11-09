//! The nameservers for the hostnames tenants delegated to us.
//!
//! A tenant delegates one hostname to us with an `NS` record at its own
//! provider, and from then on these answer for it: the records the tenant
//! wrote inside it, and the ones the platform writes for it (the address
//! the gateway listens on and the `TXT` record a certificate authority asks
//! for). They answer only for zones whose delegation was proved, and
//! refuse every other name.
//!
//! Like the gateway, this is a data plane: it reads what the control plane
//! decided and can change none of it. In the cluster it signs in to the
//! database as the nameservers' own role, which reads the zones and
//! nothing more. On a host of its own it holds no database login at all:
//! it follows the control plane's stream over mutual TLS, holding only a
//! client certificate. Either way a nameserver that is taken over gives
//! away public DNS data and no more.
//!
//! The pieces are kept apart:
//!
//! - which zones answer, and with what, is the domain's
//!   (`dns_zone::ZoneCatalog`), loaded through the app's
//!   `LoadCatalogUseCase` from the infra's zone reader, or settled by the
//!   control plane the same way and sent down the stream;
//! - [`wire`] is the only code that knows the DNS packet format;
//! - [`listen`] owns the sockets;
//! - this crate wires them together and starts them under one stop.
//!
//! [`run`] is the binary's entry; [`serving`] starts the same thing under a
//! stop the caller holds, for tests that answer real queries.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(unreachable_pub)]

mod catalog;
pub mod config;
pub mod error;
mod follow;
pub mod listen;
pub mod wire;

use std::net::SocketAddr;
use std::sync::Arc;

use ianua_app::ports::domain::DnsZoneReader;
use ianua_app::use_cases::domain::nameservers::{LoadCatalogPorts, LoadCatalogUseCase};
use ianua_boot::env::Env;
use ianua_boot::foundation::DatabaseConfig;
use ianua_boot::logging;
use ianua_boot::shutdown::Shutdown;
use ianua_infra::postgres::Databases;
use ianua_infra::postgres::domain::PgDnsZoneReader;

use crate::catalog::{CatalogLoader, SharedCatalog, empty_catalog};
use crate::config::{NameserverConfig, ZoneSource};
use crate::error::NameserverError;
use crate::follow::Follower;
use crate::listen::Ports;

/// Where serving nameservers listen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Serving {
    /// The address both UDP and TCP were taken on, the port named even
    /// where `DNS_BIND` asked for any.
    pub address: SocketAddr,
}

/// Reads the settings `vars` holds, sets up the logs, and answers DNS until
/// SIGTERM or Ctrl-C.
///
/// # Errors
///
/// [`NameserverError`] for a setting refused, a port that cannot be taken,
/// or a stop that did not go cleanly.
pub async fn run(vars: &Env) -> Result<(), NameserverError> {
    let config = NameserverConfig::read(vars)?;
    logging::init(&config.logging)?;
    announce(vars);
    let shutdown = Shutdown::new(config.shutdown_grace);
    shutdown.stop_on_signals()?;
    let serving = started(&config, &shutdown).await?;
    tracing::info!(address = %serving.address, "ianua-dns running");
    shutdown.join().await?;
    tracing::info!("stopped");
    Ok(())
}

/// Starts the nameservers `vars` describes under `shutdown`, answering once
/// both ports are taken and, reading the database, the first load was
/// tried; following the control plane, its stream is followed from then
/// on and every query is refused until its first catalog. The caller holds
/// the stop and sets up the logs; nothing here listens for a signal.
///
/// # Errors
///
/// [`NameserverError`] for a setting refused or a port that cannot be
/// taken; nothing was started then.
pub async fn serving(vars: &Env, shutdown: &Shutdown) -> Result<Serving, NameserverError> {
    let config = NameserverConfig::read(vars)?;
    announce(vars);
    started(&config, shutdown).await
}

/// Logs which settings were set, never their values.
fn announce(vars: &Env) {
    tracing::info!(settings = ?vars.set_names(), "starting with these settings set");
}

/// Takes both ports, starts the listeners on an empty catalog, and starts
/// filling it from the source the settings name.
async fn started(
    config: &NameserverConfig,
    shutdown: &Shutdown,
) -> Result<Serving, NameserverError> {
    let ports = Ports::bind(config.bind).await?;
    let catalog = empty_catalog(config.authority());
    shutdown.spawn(
        "dns over udp",
        listen::serve_udp(ports.udp, Arc::clone(&catalog), shutdown.stopping()),
    );
    shutdown.spawn(
        "dns over tcp",
        listen::serve_tcp(ports.tcp, Arc::clone(&catalog), shutdown.stopping()),
    );
    populate(config, catalog, shutdown).await;
    Ok(Serving {
        address: ports.address,
    })
}

/// Starts filling `catalog` from the source `config` names. The database
/// is loaded once before this answers; the control plane's stream is
/// followed from now on, its first catalog arriving when it does.
async fn populate(config: &NameserverConfig, catalog: SharedCatalog, shutdown: &Shutdown) {
    match &config.zones {
        ZoneSource::Database { database, refresh } => {
            let loader = CatalogLoader::new(catalog_load(database, config), catalog, *refresh);
            let first = loader.load().await;
            shutdown.spawn_until_stopped(loader.keep_fresh(first));
        }
        ZoneSource::ControlPlane(link) => {
            let follower = Follower::new(link.clone(), catalog, config.authority());
            shutdown.spawn_until_stopped(follower.follow());
        }
    }
}

/// The load of the catalog, reading the zones as the nameservers' own
/// role.
fn catalog_load(database: &DatabaseConfig, config: &NameserverConfig) -> LoadCatalogUseCase {
    let databases = Arc::new(Databases::nameserver(
        database.login.options.clone(),
        database.pools,
    ));
    let zones: Arc<dyn DnsZoneReader> = Arc::new(PgDnsZoneReader::new(databases));
    LoadCatalogUseCase::new(LoadCatalogPorts { zones }, config.authority())
}

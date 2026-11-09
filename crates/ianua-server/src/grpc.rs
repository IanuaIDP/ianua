//! The link the nameservers outside the cluster follow the zones on: a
//! gRPC listener over mutual TLS, started beside the API when
//! `GRPC_LISTEN` is set, streaming only the zones the domain lets answer,
//! and stopped with everything else.

use std::net::SocketAddr;
use std::sync::Arc;

use ianua_boot::shutdown::Shutdown;
use ianua_domain::shared::errors::causes;
use ianua_grpc::{DnsZonesService, GrpcListener};
use ianua_infra::postgres::domain::PgDnsZoneReader;

use crate::config::Config;
use crate::error::{PlatformError, ServerError};
use crate::platform::Platform;

/// Starts the nameserver link when the configuration names where it
/// listens, and answers where it listens once its port is taken. Does
/// nothing and answers `None` when `GRPC_LISTEN` is unset.
///
/// # Errors
///
/// [`ServerError::Platform`] when the port cannot be taken or the
/// certificate, key or client authority will not load.
pub async fn run(
    platform: &Platform,
    config: &Config,
    shutdown: &Shutdown,
) -> Result<Option<SocketAddr>, ServerError> {
    let Some(settings) = config.domains.grpc.clone() else {
        return Ok(None);
    };
    let zones = DnsZonesService::new(Arc::new(PgDnsZoneReader::new(Arc::clone(
        &platform.databases,
    ))));
    let listener = GrpcListener::open(settings, zones)
        .await
        .map_err(PlatformError::of("the nameserver link"))?;
    let address = listener.address();
    shutdown.spawn("the nameserver link", served(listener, shutdown));
    Ok(Some(address))
}

/// Serves `listener` until the stop, logging a failure: the task ending
/// stops the process, as a link that died must not look alive.
fn served(
    listener: GrpcListener,
    shutdown: &Shutdown,
) -> impl Future<Output = ()> + Send + 'static {
    let stopping = shutdown.stopping();
    async move {
        if let Err(error) = listener.serve(stopping).await {
            tracing::error!(cause = %causes(&error), "the nameserver link failed");
        }
    }
}

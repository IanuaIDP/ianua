//! `ianua sandbox-proxy`: the network filter, the one way a version's code
//! reaches the hosts the version names, until it is stopped.

use std::sync::Arc;

use ianua_boot::env::Env;
use ianua_boot::logging;
use ianua_boot::shutdown::Shutdown;
use ianua_infra::sandbox::SandboxProxy;

use crate::config::serving::ProxyConfig;
use crate::error::ServerError;

/// How long the tunnels still open may go on once a stop is asked for.
const STOP_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Serves the filter `vars` sets up until a stop signal.
///
/// # Errors
///
/// [`ServerError`] when a setting is refused, the logs cannot be set up or
/// the filter's address cannot be listened on.
pub async fn run(vars: &Env) -> Result<(), ServerError> {
    let config = ProxyConfig::read(vars)?;
    logging::init(&config.logging)?;
    let shutdown = Shutdown::new(STOP_GRACE);
    shutdown.stop_on_signals()?;
    let address = config.serving.listen;
    tracing::info!(%address, "the network filter serves");
    let proxy = Arc::new(SandboxProxy::new(config.serving));
    proxy
        .serve(shutdown.stopping())
        .await
        .map_err(|cause| ServerError::Listen {
            listener: "network filter",
            address,
            cause,
        })
}

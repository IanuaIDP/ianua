//! `ianua sandbox-gate`: the one process holding the container engine's
//! socket on a single server, starting locked-down code containers the
//! worker asks for over the gate's own socket, until it is stopped.

use std::sync::Arc;

use ianua_boot::env::Env;
use ianua_boot::logging;
use ianua_boot::shutdown::Shutdown;
use ianua_infra::sandbox::SandboxGate;

use crate::config::serving::GateConfig;
use crate::error::ServerError;

/// Serves the gate `vars` sets up until a stop signal, letting the runs
/// under way end within the start-up grace.
///
/// # Errors
///
/// [`ServerError`] when a setting is refused, the logs cannot be set up or
/// the gate's socket cannot be listened on.
pub async fn run(vars: &Env) -> Result<(), ServerError> {
    let config = GateConfig::read(vars)?;
    logging::init(&config.logging)?;
    let shutdown = Shutdown::new(config.serving.start_grace);
    shutdown.stop_on_signals()?;
    let socket = config.serving.listen.clone();
    tracing::info!(socket = %socket.display(), "the sandbox gate serves");
    let gate = Arc::new(SandboxGate::new(config.serving));
    gate.serve(shutdown.stopping())
        .await
        .map_err(|cause| ServerError::Gate { socket, cause })
}

//! Starting the runner: from the binary, until a stop; or from a test or a
//! scenario through [`serving`], under a stop the caller holds.

use std::net::SocketAddr;
use std::sync::Arc;

use ianua_boot::env::Env;
use ianua_boot::logging;
use ianua_boot::shutdown::Shutdown;
use tokio::net::TcpListener;

use crate::config::Config;
use crate::error::RunnerError;
use crate::listen::{ConnectionLimits, accept};
use crate::parts::runner;

/// Reads the configuration from `vars`, sets up the logs, and serves the
/// agent until SIGTERM or Ctrl-C, then waits for the requests in flight.
///
/// # Errors
///
/// [`RunnerError`] for the first thing that failed.
pub async fn run(vars: &Env) -> Result<(), RunnerError> {
    let config = Config::read(vars)?;
    logging::init(&config.logging)?;
    let shutdown = Shutdown::new(config.limits.shutdown_grace);
    shutdown.stop_on_signals()?;
    started(vars, &config, &shutdown).await?;
    shutdown.join().await?;
    tracing::info!("stopped");
    Ok(())
}

/// Builds the runner `vars` describes and starts it serving under
/// `shutdown`, answering with the address it listens on once it does.
/// The caller holds the stop and sets up the logs; nothing here listens
/// for a signal.
///
/// # Errors
///
/// [`RunnerError`] for the first thing that failed.
pub async fn serving(vars: &Env, shutdown: &Shutdown) -> Result<SocketAddr, RunnerError> {
    let config = Config::read(vars)?;
    started(vars, &config, shutdown).await
}

/// Builds the runner and starts its listener.
async fn started(
    vars: &Env,
    config: &Config,
    shutdown: &Shutdown,
) -> Result<SocketAddr, RunnerError> {
    let runner = Arc::new(runner(config)?);
    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(RunnerError::Listen)?;
    let address = listener.local_addr().map_err(RunnerError::Listen)?;
    let limits = ConnectionLimits {
        connections: config.limits.connections,
        header: config.limits.header,
    };
    shutdown.spawn(
        "the agent's listener",
        accept(listener, runner, limits, shutdown.clone()),
    );
    tracing::info!(
        %address,
        agent = %config.agent.agent,
        settings = ?vars.set_names(),
        "serving the agent"
    );
    Ok(address)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ianua_app::ports::crypto::KeyGenerator as _;
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
    use ianua_infra::crypto::Pkcs8KeyGenerator;
    use tokio::net::TcpStream;

    use super::*;

    /// A runner with a mounted key starts on the address its settings
    /// name, takes the agent's connections, and stops with its holder's
    /// stop.
    #[tokio::test]
    async fn the_runner_serves_until_its_holder_stops_it() {
        let pair = Pkcs8KeyGenerator
            .generate(SigningAlgorithm::EdDsa)
            .await
            .unwrap();
        let vars = Env::of([
            ("APP_ENV", "development"),
            ("RUNNER_LISTEN", "127.0.0.1:0"),
            ("RUNNER_AGENT_ID", "0190a6f0-0000-7000-8000-000000000001"),
            ("RUNNER_API_URL", "http://127.0.0.1:9/agents"),
            ("RUNNER_GATEWAY_URL", "http://127.0.0.1:9"),
            ("RUNNER_UPSTREAM_HOST", "api.acme.test"),
            ("RUNNER_TOKEN_AUDIENCE", "https://ianua.test"),
            ("RUNNER_GRANTED", "{}"),
            ("RUNNER_IDENTITY", "key"),
            ("RUNNER_KEY_ID", "k1"),
            ("RUNNER_KEY", pair.private_key.expose()),
        ]);
        let shutdown = Shutdown::new(Duration::from_secs(1));

        let address = serving(&vars, &shutdown).await.unwrap();
        let connected = TcpStream::connect(address).await;
        shutdown.stop();

        assert!(connected.is_ok());
        assert!(shutdown.join().await.is_ok());
    }

    /// An unreadable mounted key produces a build error before the runner
    /// can start serving requests.
    #[tokio::test]
    async fn a_runner_whose_key_does_not_read_does_not_start() {
        let vars = Env::of([
            ("APP_ENV", "development"),
            ("RUNNER_LISTEN", "127.0.0.1:0"),
            ("RUNNER_AGENT_ID", "0190a6f0-0000-7000-8000-000000000001"),
            ("RUNNER_API_URL", "http://127.0.0.1:9/agents"),
            ("RUNNER_GATEWAY_URL", "http://127.0.0.1:9"),
            ("RUNNER_UPSTREAM_HOST", "api.acme.test"),
            ("RUNNER_TOKEN_AUDIENCE", "https://ianua.test"),
            ("RUNNER_GRANTED", "{}"),
            ("RUNNER_IDENTITY", "key"),
            ("RUNNER_KEY_ID", "k1"),
            ("RUNNER_KEY", "not a key"),
        ]);
        let shutdown = Shutdown::new(Duration::from_secs(1));

        let started = serving(&vars, &shutdown).await;

        assert!(matches!(started, Err(RunnerError::Build { .. })));
    }
}

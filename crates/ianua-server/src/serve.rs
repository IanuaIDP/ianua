//! Running a command on the platform: serving until a stop, or one task
//! and out.
//!
//! The binary goes through [`on_platform`], which sets up the logs and
//! stops on a signal. The end-to-end scenarios start the same platform in
//! their own process through [`serving`] and [`perform`]: the same
//! configuration, the same adapters, the same listeners, under a stop they
//! hold and with logs they set up themselves.

use std::net::SocketAddr;

use ianua_boot::env::Env;
use ianua_boot::logging;
use ianua_boot::shutdown::{Shutdown, ShutdownError};

use crate::api::ApiAddresses;
use crate::command::Command;
use crate::config::Config;
use crate::error::ServerError;
use crate::platform::Platform;
use crate::{api, demo, grpc, install, ldap, worker};

/// What a command does once the platform is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Run {
    /// Serve until a stop.
    Serve,
    /// Make the installation's organization, then exit.
    Install,
    /// Make the platform's first operator, then exit.
    CreateOperator,
    /// Seed the demonstration organization, then exit.
    Demo,
}

impl Run {
    /// What `command` runs on the platform, or `None` for migrating, for
    /// issuing the nameserver link's certificates, the connector authority
    /// or the internal links' certificates, and for serving the sandbox
    /// gate, which build no platform.
    #[must_use]
    pub fn of(command: &Command) -> Option<Self> {
        match command {
            Command::Migrate
            | Command::LinkPki(_)
            | Command::ConnectorPki(_)
            | Command::InternalPki(_)
            | Command::SandboxGate
            | Command::SandboxProxy => None,
            Command::Serve => Some(Self::Serve),
            Command::Install => Some(Self::Install),
            Command::CreateOperator { .. } => Some(Self::CreateOperator),
            Command::Demo => Some(Self::Demo),
        }
    }
}

/// Where a serving platform listens, the ports named even where the
/// settings asked for any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Serving {
    /// The API's listeners, when `MODE` runs the API.
    pub api: Option<ApiAddresses>,
    /// The LDAP directory, when `LDAP_BIND_ADDR` is set.
    pub directory: Option<SocketAddr>,
    /// The link the nameservers outside the cluster follow the zones on,
    /// when `GRPC_LISTEN` is set.
    pub nameserver_link: Option<SocketAddr>,
}

/// Reads the configuration for `command` from `vars`, sets up the logs,
/// builds the platform and does what `run` says on it, stopping on a
/// signal.
///
/// # Errors
///
/// [`ServerError`] for the first thing that failed.
pub async fn on_platform(run: Run, command: &Command, vars: &Env) -> Result<(), ServerError> {
    let config = Config::read(vars, command)?;
    logging::init(&config.logging)?;
    announce(vars, &config, run);
    let shutdown = Shutdown::new(config.http.shutdown_grace);
    shutdown.stop_on_signals()?;
    on_built(run, &config, &shutdown).await
}

/// Builds the platform `vars` describes and starts it serving under
/// `shutdown`, answering once every listener listens. The caller holds the
/// stop and sets up the logs; nothing here listens for a signal.
///
/// # Errors
///
/// [`ServerError`] for the first thing that failed; what had started is
/// stopped again.
pub async fn serving(vars: &Env, shutdown: &Shutdown) -> Result<Serving, ServerError> {
    let config = Config::read(vars, &Command::Serve)?;
    announce(vars, &config, Run::Serve);
    let platform = Platform::build(&config, shutdown).await?;
    started(&platform, &config, shutdown).await
}

/// Does what the one-off `command` does on the platform `vars` describes,
/// then stops: making the first operator, the installation's organization
/// or the demonstration. The caller sets up the logs.
///
/// # Errors
///
/// [`ServerError::NotOneOff`] for `serve`, which never ends on its own,
/// and for `migrate`; otherwise the first thing that failed.
pub async fn perform(command: &Command, vars: &Env) -> Result<(), ServerError> {
    let Some(run) = Run::of(command).filter(|run| *run != Run::Serve) else {
        return Err(ServerError::NotOneOff);
    };
    let config = Config::read(vars, command)?;
    announce(vars, &config, run);
    let shutdown = Shutdown::new(config.http.shutdown_grace);
    on_built(run, &config, &shutdown).await
}

/// Builds the platform and does what `run` says on it.
async fn on_built(run: Run, config: &Config, shutdown: &Shutdown) -> Result<(), ServerError> {
    let platform = Platform::build(config, shutdown).await?;
    match run {
        Run::Serve => serve(&platform, config, shutdown).await,
        Run::Install => once(install::run(&platform, config).await, shutdown).await,
        Run::CreateOperator => {
            once(install::operator::run(&platform, config).await, shutdown).await
        }
        Run::Demo => once(demo::run(&platform, config).await, shutdown).await,
    }
}

/// Logs what starts and with which settings, and lets the API show its
/// development detail outside production.
fn announce(vars: &Env, config: &Config, run: Run) {
    if !config.environment().is_production() {
        ianua_api::error::enable_dev_mode();
    }
    tracing::info!(
        mode = ?config.mode(),
        command = ?run,
        settings = ?vars.set_names(),
        "starting with these settings set"
    );
}

/// Starts the platform serving, then waits for the stop and for every task
/// to end.
async fn serve(
    platform: &Platform,
    config: &Config,
    shutdown: &Shutdown,
) -> Result<(), ServerError> {
    started(platform, config, shutdown).await?;
    tracing::info!(mode = ?config.mode(), "running");
    shutdown.join().await?;
    tracing::info!("stopped");
    Ok(())
}

/// Starts what every node runs and the halves `MODE` names. A half that
/// cannot start stops what started before it.
async fn started(
    platform: &Platform,
    config: &Config,
    shutdown: &Shutdown,
) -> Result<Serving, ServerError> {
    platform.follow(config, shutdown);
    let outcome = start(platform, config, shutdown).await;
    if outcome.is_err() {
        shutdown.stop();
        log_unclean(shutdown.join().await);
    }
    outcome
}

/// Starts the API with the LDAP directory and the nameserver link beside
/// it, and the worker, as `MODE` names them.
async fn start(
    platform: &Platform,
    config: &Config,
    shutdown: &Shutdown,
) -> Result<Serving, ServerError> {
    let mut serving = Serving {
        api: None,
        directory: None,
        nameserver_link: None,
    };
    if config.mode().runs_api() {
        let deps = api::deps(platform, config)?;
        serving.api = Some(api::run(platform, config, shutdown, &deps).await?);
        serving.directory = ldap::run(platform, config, shutdown, &deps).await?;
        serving.nameserver_link = grpc::run(platform, config, shutdown).await?;
    }
    if config.mode().runs_worker() {
        worker::run(platform, config, shutdown).await?;
    }
    Ok(serving)
}

/// Ends a one-off command: the stop asked for, every task waited for, and
/// the command's own outcome answered.
async fn once(outcome: Result<(), ServerError>, shutdown: &Shutdown) -> Result<(), ServerError> {
    shutdown.stop();
    log_unclean(shutdown.join().await);
    outcome
}

/// Logs a stop that did not go cleanly, when another error is the one to
/// answer with.
fn log_unclean(joined: Result<(), ShutdownError>) {
    if let Err(error) = joined {
        tracing::warn!(%error, "the stop did not go cleanly");
    }
}

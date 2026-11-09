//! The composition root: reads the configuration, builds the shared core
//! once, and runs the API, the worker or both in one binary, or one of the
//! one-off commands.
//!
//! Nothing here decides anything a use case or an adapter should: the
//! server builds adapters, hands them over and starts loops. A library as
//! well as a binary, so the end-to-end tests can start the real thing.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(unreachable_pub)]

pub mod api;
pub mod assembly;
pub mod command;
pub mod config;
pub mod connector_pki;
pub mod demo;
pub mod error;
pub mod grpc;
pub mod install;
pub mod internal_pki;
pub mod ldap;
pub mod link_pki;
pub mod listeners;
pub mod migrate;
pub mod mutual_listener;
pub mod pki_files;
pub mod platform;
pub mod sandbox_gate;
pub mod sandbox_proxy;
pub mod serve;
pub mod worker;

use ianua_boot::env::Env;
use ianua_boot::logging;

use crate::command::Command;
use crate::config::MigrationConfig;
use crate::error::ServerError;
use crate::serve::Run;

/// Runs `command` with the settings `vars` holds.
///
/// # Errors
///
/// [`ServerError`] for the first thing that failed: a setting refused, a
/// part of the platform not built, or a stop that did not go cleanly.
pub async fn run(command: Command, vars: &Env) -> Result<(), ServerError> {
    if let Command::LinkPki(request) = &command {
        return link_pki::run(request);
    }
    if let Command::ConnectorPki(request) = &command {
        return connector_pki::run(request);
    }
    if let Command::InternalPki(request) = &command {
        return internal_pki::run(request);
    }
    if command == Command::SandboxGate {
        return sandbox_gate::run(vars).await;
    }
    if command == Command::SandboxProxy {
        return sandbox_proxy::run(vars).await;
    }
    let Some(run) = Run::of(&command) else {
        return run_migrate(vars).await;
    };
    serve::on_platform(run, &command, vars).await
}

/// Brings the schema up to date with nothing but the database settings,
/// then exits.
async fn run_migrate(vars: &Env) -> Result<(), ServerError> {
    let config = MigrationConfig::read(vars)?;
    logging::init(&config.logging)?;
    tracing::info!(settings = ?vars.set_names(), "migrating with these settings set");
    migrate::migrate(&config.database, &config.logins).await?;
    Ok(())
}

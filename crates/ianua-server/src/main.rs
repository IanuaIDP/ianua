//! The `ianua` binary: `ianua [serve | migrate | install | demo |
//! sandbox-gate | sandbox-proxy | operator create --email <address>]`,
//! serving by default, as `MODE` (`api`, `worker` or `all`) says.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

use std::process::ExitCode;

use ianua_boot::env::Env;
use ianua_server::command::Command;
use ianua_server::error::described;

#[tokio::main]
async fn main() -> ExitCode {
    install_crypto_provider();
    let outcome = match Command::parse(std::env::args().skip(1)) {
        Ok(command) => ianua_server::run(command, &Env::from_process()).await,
        Err(error) => Err(error.into()),
    };
    let Err(error) = outcome else {
        return ExitCode::SUCCESS;
    };
    eprintln!("{}", described(&error));
    ExitCode::FAILURE
}

/// Selects the rustls crypto provider before anything opens a TLS
/// connection.
///
/// More than one provider is reachable across the dependency graph and
/// rustls refuses to guess: without this it panics on a worker thread at
/// the first handshake. `ring` matches every other place in the workspace
/// that installs one. A second install answers an error, which only says
/// one is in place already.
fn install_crypto_provider() {
    if tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("a TLS crypto provider was installed already");
    }
}

//! The `ianua-connector` binary: links a private network to the ianua
//! gateway as its settings say, until SIGTERM or Ctrl-C.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

use std::process::ExitCode;

use ianua_boot::env::Env;
use ianua_connector::error::described;

#[tokio::main]
async fn main() -> ExitCode {
    install_crypto_provider();
    let Err(error) = ianua_connector::run(&Env::from_process()).await else {
        return ExitCode::SUCCESS;
    };
    eprintln!("{}", described(&error));
    ExitCode::FAILURE
}

/// Selects the rustls crypto provider before anything opens a TLS
/// connection.
///
/// More than one provider is reachable across the dependency graph and
/// rustls refuses to guess. `ring` matches every other place in the
/// workspace that installs one. A second install answers an error, which
/// only says one is in place already.
fn install_crypto_provider() {
    if tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("a TLS crypto provider was installed already");
    }
}

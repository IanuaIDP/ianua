//! The `ianua-dns` binary: the nameservers for the hostnames tenants
//! delegated to us, answering until a stop.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

use std::process::ExitCode;

use ianua_boot::env::Env;
use ianua_domain::shared::errors::causes;

#[tokio::main]
async fn main() -> ExitCode {
    install_crypto_provider();
    let Err(error) = ianua_dns::run(&Env::from_process()).await else {
        return ExitCode::SUCCESS;
    };
    eprintln!("{}", causes(&error));
    ExitCode::FAILURE
}

/// Selects the rustls crypto provider before the database connection opens
/// one over TLS.
///
/// More than one provider is reachable across the dependency graph and
/// rustls refuses to guess: without this it panics at the first handshake.
/// `ring` matches every other place in the workspace that installs one. A
/// second install answers an error, which only says one is in place
/// already.
fn install_crypto_provider() {
    if tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("a TLS crypto provider was installed already");
    }
}

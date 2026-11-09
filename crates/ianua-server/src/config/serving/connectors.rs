//! Private network connectors: the authority their certificates are signed
//! by.
//!
//! The API signs a connector's certificate when its agent enrolls and each
//! day after, so the API nodes hold the authority's key. Without it every
//! enrollment and renewal is refused, and services behind a connector stay
//! unreachable.

use ianua_boot::env::{Env, Read};
use ianua_boot::network::PemFiles;

/// The connector authority.
#[derive(Debug, Clone)]
pub struct ConnectorsConfig {
    /// `CONNECTOR_CA_CERT_FILE` and `CONNECTOR_CA_KEY_FILE`: the authority
    /// `ianua connector-pki` issued; none refuses every enrollment.
    pub authority: Option<PemFiles>,
}

impl ConnectorsConfig {
    /// The connector settings `vars` holds.
    ///
    /// # Errors
    ///
    /// Half of the certificate and key.
    pub fn read(vars: &Env) -> Read<Self> {
        Ok(Self {
            authority: vars.pem_files("CONNECTOR_CA_CERT_FILE", "CONNECTOR_CA_KEY_FILE")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without the files, no authority is set up.
    #[test]
    fn no_files_set_up_no_authority() {
        let config = ConnectorsConfig::read(&Env::of([])).unwrap();

        assert!(config.authority.is_none());
    }

    /// A connector authority certificate without its key is refused when
    /// reading configuration.
    #[test]
    fn half_of_the_authority_is_refused() {
        let read = ConnectorsConfig::read(&Env::of([(
            "CONNECTOR_CA_CERT_FILE",
            "/run/connectors/ca-cert.pem",
        )]));

        assert!(read.is_err());
    }
}

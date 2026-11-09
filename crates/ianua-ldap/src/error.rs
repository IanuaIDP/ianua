//! Why the LDAP server could not start.

use std::net::SocketAddr;
use std::path::PathBuf;

/// Why the LDAP server could not start.
#[derive(Debug, thiserror::Error)]
pub enum LdapError {
    /// The listen address could not be taken.
    #[error("the LDAP server could not listen on {address}")]
    Listen {
        /// Local socket the directory attempted to bind.
        address: SocketAddr,
        /// What failed.
        #[source]
        cause: std::io::Error,
    },
    /// A TLS file could not be read.
    #[error("the LDAP server's {what} could not be read from {path}")]
    Read {
        /// Which file: the certificate, the key or the client authority.
        what: &'static str,
        /// Where it was looked for.
        path: PathBuf,
        /// What failed.
        #[source]
        cause: std::io::Error,
    },
    /// A TLS file was read but holds nothing usable.
    #[error("the LDAP server's {what} at {path} is not usable")]
    Unusable {
        /// Which file: the certificate, the key or the client authority.
        what: &'static str,
        /// Where it was read from.
        path: PathBuf,
        /// What was wrong with it.
        #[source]
        cause: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The certificate and key, or the client authority, make no TLS
    /// configuration.
    #[error("the LDAP server's TLS could not be set up")]
    Tls(#[source] Box<dyn std::error::Error + Send + Sync>),
}

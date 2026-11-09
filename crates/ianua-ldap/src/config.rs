//! What the LDAP server runs with: where it listens, its TLS, and how much
//! it takes on.
//!
//! The server reads and checks every setting; this crate reads none and
//! only takes the result.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// The LDAP server's settings.
#[derive(Debug, Clone)]
pub struct LdapConfig {
    /// Where it listens.
    pub listen: SocketAddr,
    /// TLS on every connection from its first byte (LDAPS). `None` takes
    /// plain connections, for TLS ended in front of it: no client
    /// certificate reaches the server then, so no person can bind and
    /// service account secrets cross the wire as the client sent them.
    pub tls: Option<LdapTls>,
    /// How much it takes on.
    pub limits: LdapLimits,
}

/// The certificate the server presents, and the authority its clients'
/// certificates are checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapTls {
    /// The PEM file of the server's certificate chain.
    pub certificate: PathBuf,
    /// The PEM file of the server's private key.
    pub key: PathBuf,
    /// The PEM file of the authority client certificates are issued from.
    /// A client is asked for a certificate signed by it, never made to
    /// present one; `None` asks for none, so no person can bind.
    pub client_ca: Option<PathBuf>,
}

/// How much the server takes on, and for how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LdapLimits {
    /// Connections served at once; one more is closed, not queued.
    pub max_connections: usize,
    /// How long a connection may sit idle before it is closed.
    pub idle_timeout: Duration,
    /// How long a TLS handshake may take. Short, because it bounds a client
    /// that proved nothing holding a connection.
    pub handshake_timeout: Duration,
    /// Binds one source address may try a minute, counted before a bind
    /// names any tenant.
    pub binds_per_ip_per_minute: u32,
}

//! Every setting the egress gateway reads, read once from the environment
//! and checked together before anything starts.
//!
//! The egress gateway is part of the data plane: it signs in to the
//! database as the data plane's role (`GATEWAY_DATABASE_URL`) and holds
//! the shared root and the sealing keys, never the control plane's root.
//! Every setting is read through [`Env`], each reader naming the variable
//! it reads.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_boot::environment::Environment;
use ianua_boot::foundation::{DatabaseConfig, DatabaseRole, SharedKeys};
use ianua_boot::logging::LoggingConfig;
use ianua_boot::network::PemFiles;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;

/// The settings only the control plane holds. The egress gateway takes
/// traffic from services agents reach, so holding any of them would hand
/// whoever takes it what the data plane is kept apart from.
const CONTROL_PLANE_ONLY: [(&str, &str); 4] = [
    (
        "EVENT_SIGNING_SECRET",
        "is the control plane's root, which would let the egress gateway seal any event",
    ),
    (
        "DATABASE_URL",
        "is the app's login; the egress gateway signs in as GATEWAY_DATABASE_URL",
    ),
    (
        "MIGRATION_DATABASE_URL",
        "is the database owner's login, past every grant",
    ),
    (
        "AUDIT_PURGE_DATABASE_URL",
        "is the login that may remove audit records",
    ),
];

/// Where the egress gateway listens and the certificates it serves and
/// takes.
#[derive(Debug, Clone)]
pub struct ListenConfig {
    /// `EGRESS_LISTEN` (`0.0.0.0:3128`): where services connect.
    pub address: SocketAddr,
    /// `EGRESS_STATUS_LISTEN` (`0.0.0.0:9902`): where the health probes
    /// are answered, apart from the services' listener.
    pub status: SocketAddr,
    /// `EGRESS_TLS_CERT_FILE` and `EGRESS_TLS_KEY_FILE`: the certificate
    /// the egress gateway serves.
    pub certificate: PemFiles,
    /// `EGRESS_CLIENT_CA_FILE`: the authorities a service's client
    /// certificate must chain to, such as the SPIRE trust bundle. A
    /// service without one is refused at the handshake.
    pub client_ca: PathBuf,
}

/// What one connection and the egress gateway as a whole may take on.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// `EGRESS_MAX_CONNECTIONS` (1024): the most service connections held at
    /// once; one past it is closed.
    pub connections: usize,
    /// `EGRESS_MAX_TUNNELS` (1024): the most tunnels open at once; one past
    /// it is answered busy.
    pub tunnels: usize,
    /// `EGRESS_HANDSHAKE_TIMEOUT_SECONDS` (10): how long a service may take
    /// to finish the TLS handshake.
    pub handshake: Duration,
    /// `EGRESS_HEADER_TIMEOUT_SECONDS` (10): how long a service may take to
    /// send a request's head.
    pub header: Duration,
    /// `EGRESS_DECISION_TIMEOUT_SECONDS` (5): the longest the decision on
    /// one connection may take; past it the connection is refused.
    pub decision: Duration,
    /// `EGRESS_CONNECT_TIMEOUT_SECONDS` (10): the longest resolving and
    /// connecting to a destination may take.
    pub connect: Duration,
    /// `EGRESS_REQUEST_TIMEOUT_SECONDS` (60): the longest a plain HTTP
    /// exchange may take, its answer streamed to the end included.
    pub request: Duration,
    /// `EGRESS_IDLE_TIMEOUT_SECONDS` (300): how long a tunnel may carry
    /// nothing before it is closed.
    pub idle: Duration,
    /// `EGRESS_SHUTDOWN_GRACE_SECONDS` (10): how long a stop waits for
    /// the connections in flight.
    pub shutdown_grace: Duration,
}

/// Every setting the egress gateway runs with.
#[derive(Debug, Clone)]
pub struct Config {
    /// `APP_ENV`.
    pub environment: Environment,
    /// What is logged and how.
    pub logging: LoggingConfig,
    /// The database, reached as the data plane's role.
    pub database: DatabaseConfig,
    /// `TENANT_DB_RELOAD_SECONDS` (300): how often every tenant's database
    /// route is read again.
    pub routes_reload: Duration,
    /// The shared root, which seals the denials it records, and the
    /// sealing keys.
    pub keys: SharedKeys,
    /// Where it listens.
    pub listen: ListenConfig,
    /// `EGRESS_PRIVATE_NETWORKS`: the internal networks a destination may
    /// resolve to, as CIDR blocks; public addresses only when unset.
    pub networks: UpstreamNetworks,
    /// What it may take on.
    pub limits: Limits,
}

impl Config {
    /// Every setting `vars` holds, checked together.
    ///
    /// # Errors
    ///
    /// The first setting refused: a secret only the control plane holds,
    /// or a setting missing or not of its kind.
    pub fn read(vars: &Env) -> Read<Self> {
        ensure_no_control_plane_secret(vars)?;
        let environment = Environment::read(vars)?;
        Ok(Self {
            logging: LoggingConfig::read(vars, environment)?,
            database: DatabaseConfig::read(vars, DatabaseRole::Gateway)?,
            routes_reload: vars.seconds("TENANT_DB_RELOAD_SECONDS", Duration::from_secs(300))?,
            keys: SharedKeys::read(vars)?,
            listen: listen(vars)?,
            networks: vars.networks("EGRESS_PRIVATE_NETWORKS")?,
            limits: limits(vars)?,
            environment,
        })
    }
}

/// Where the egress gateway listens and what it serves.
fn listen(vars: &Env) -> Read<ListenConfig> {
    let certificate = vars
        .pem_files("EGRESS_TLS_CERT_FILE", "EGRESS_TLS_KEY_FILE")?
        .ok_or_else(|| ConfigError::missing("EGRESS_TLS_CERT_FILE and EGRESS_TLS_KEY_FILE"))?;
    Ok(ListenConfig {
        address: address(vars, "EGRESS_LISTEN", ([0, 0, 0, 0], 3128))?,
        status: address(vars, "EGRESS_STATUS_LISTEN", ([0, 0, 0, 0], 9902))?,
        certificate,
        client_ca: vars
            .path("EGRESS_CLIENT_CA_FILE")?
            .ok_or_else(|| ConfigError::missing("EGRESS_CLIENT_CA_FILE"))?,
    })
}

/// The socket address `name` holds, or `default` when it is unset.
fn address(vars: &Env, name: &str, default: ([u8; 4], u16)) -> Read<SocketAddr> {
    Ok(vars
        .parsed(name, |text| text.parse::<SocketAddr>())?
        .unwrap_or_else(|| SocketAddr::from(default)))
}

/// What one connection and the egress gateway may take on.
fn limits(vars: &Env) -> Read<Limits> {
    Ok(Limits {
        connections: vars.number_in("EGRESS_MAX_CONNECTIONS", 1024, 1..=100_000)?,
        tunnels: vars.number_in("EGRESS_MAX_TUNNELS", 1024, 1..=100_000)?,
        handshake: vars.seconds("EGRESS_HANDSHAKE_TIMEOUT_SECONDS", Duration::from_secs(10))?,
        header: vars.seconds("EGRESS_HEADER_TIMEOUT_SECONDS", Duration::from_secs(10))?,
        decision: vars.seconds("EGRESS_DECISION_TIMEOUT_SECONDS", Duration::from_secs(5))?,
        connect: vars.seconds("EGRESS_CONNECT_TIMEOUT_SECONDS", Duration::from_secs(10))?,
        request: vars.seconds("EGRESS_REQUEST_TIMEOUT_SECONDS", Duration::from_secs(60))?,
        idle: vars.seconds("EGRESS_IDLE_TIMEOUT_SECONDS", Duration::from_secs(300))?,
        shutdown_grace: vars.seconds("EGRESS_SHUTDOWN_GRACE_SECONDS", Duration::from_secs(10))?,
    })
}

/// Refuses any secret or login only the control plane holds, given in its
/// variable or as a file.
fn ensure_no_control_plane_secret(vars: &Env) -> Read<()> {
    for (name, why) in CONTROL_PLANE_ONLY {
        let file = format!("{name}_FILE");
        let held = vars.optional(name)?.is_some() || vars.optional(&file)?.is_some();
        if held {
            return Err(ConfigError::contradicts(
                name,
                format!("is set on the egress gateway, which must never hold it: it {why}"),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// A complete environment, with `overrides` laid over it.
    fn vars(overrides: &[(&'static str, &'static str)]) -> Env {
        let mut pairs: Vec<(&str, &str)> = vec![
            (
                "GATEWAY_DATABASE_URL",
                "postgres://ianua_gateway:a%20secret@db.internal/ianua",
            ),
            ("HMAC_SECRET", ROOT),
            ("ENCRYPTION_KEY", ROOT),
            ("EGRESS_TLS_CERT_FILE", "/run/egress/tls.crt"),
            ("EGRESS_TLS_KEY_FILE", "/run/egress/tls.key"),
            ("EGRESS_CLIENT_CA_FILE", "/run/spire/bundle.pem"),
        ];
        for &(name, value) in overrides {
            pairs.retain(|(kept, _)| *kept != name);
            pairs.push((name, value));
        }
        Env::of(pairs)
    }

    /// A complete environment reads with safe defaults: public
    /// destinations only, and bounded connections and tunnels.
    #[test]
    fn a_complete_environment_reads_with_safe_defaults() {
        let config = Config::read(&vars(&[])).unwrap();

        assert_eq!(config.listen.address.port(), 3128);
        assert_eq!(config.networks, UpstreamNetworks::public_only());
        assert_eq!(config.limits.connections, 1024);
        assert_eq!(config.limits.idle, Duration::from_secs(300));
    }

    /// Egress configuration refuses the control plane's root and the
    /// application's database login, naming each forbidden setting.
    #[test]
    fn a_control_plane_secret_is_refused() {
        for name in ["EVENT_SIGNING_SECRET", "DATABASE_URL"] {
            let read = Config::read(&vars(&[(name, "anything")]));

            assert!(
                matches!(read, Err(ConfigError::Contradicts { name: refused, .. }) if refused == name),
                "{name}"
            );
        }
    }

    /// Omitting the client authority refuses egress configuration and
    /// identifies the missing authority setting.
    #[test]
    fn no_client_authority_is_refused() {
        let read = Config::read(&vars(&[("EGRESS_CLIENT_CA_FILE", "")]));

        assert!(
            read.unwrap_err()
                .to_string()
                .contains("EGRESS_CLIENT_CA_FILE")
        );
    }
}

//! The LDAP directory: where it listens, the certificate it serves, the
//! authority its clients' certificates come from, and what it takes on.
//!
//! A directory takes passwords, so it never takes plain connections by
//! accident: in production it needs its certificate, or the explicit word
//! that TLS is ended in front of it.

use std::net::SocketAddr;
use std::time::Duration;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_boot::environment::Environment;
use ianua_boot::network::PemFiles;

/// The setting that says TLS is ended in front of the directory.
const TERMINATED_UPSTREAM: &str = "LDAP_TLS_TERMINATED_UPSTREAM";

/// Where the directory listens, and how its connections are protected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectoryListener {
    /// `LDAP_BIND_ADDR`.
    pub address: SocketAddr,
    /// How what crosses the wire is protected.
    pub transport: DirectoryTransport,
}

/// How the directory's connections are protected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectoryTransport {
    /// LDAPS with `LDAP_TLS_CERT_PATH` and `LDAP_TLS_KEY_PATH`.
    Tls(PemFiles),
    /// Plain connections, because `LDAP_TLS_TERMINATED_UPSTREAM` says TLS
    /// is ended in front of the directory.
    EndedUpstream,
    /// Plain connections outside production, with neither set.
    PlainInDevelopment,
}

/// The LDAP directory.
#[derive(Debug, Clone)]
pub(crate) struct DirectoryConfig {
    /// Where the directory listens and how; `None` when `LDAP_BIND_ADDR` is
    /// unset, which starts no directory.
    pub listener: Option<DirectoryListener>,
    /// `LDAP_CLIENT_CA_CERT_PATH` and `LDAP_CLIENT_CA_KEY_PATH`: the
    /// authority client certificates are issued from and checked against;
    /// none refuses every write.
    pub client_ca: Option<PemFiles>,
    /// `LDAP_MAX_CONNECTIONS` (256).
    pub max_connections: usize,
    /// `LDAP_IDLE_TIMEOUT_SECONDS` (300).
    pub idle_timeout: Duration,
    /// `LDAP_HANDSHAKE_TIMEOUT_SECONDS` (10).
    pub handshake_timeout: Duration,
    /// `LDAP_BINDS_PER_IP_PER_MINUTE` (30): binds one address may try.
    pub binds_per_ip_per_minute: u32,
    /// `LDAP_MAX_BIND_ATTEMPTS_PER_MINUTE` (30): binds one tenant may
    /// receive.
    pub binds_per_tenant_per_minute: u32,
    /// `LDAP_CLIENT_CERT_VALIDITY_DAYS` (90): how long an issued client
    /// certificate is valid.
    pub client_cert_validity: Duration,
}

impl DirectoryConfig {
    /// The directory settings `vars` holds, in `environment`.
    ///
    /// # Errors
    ///
    /// A setting that does not read, half of a certificate and key, a
    /// certificate or `LDAP_TLS_TERMINATED_UPSTREAM` for a directory that
    /// does not listen, both a certificate and
    /// `LDAP_TLS_TERMINATED_UPSTREAM`, or a production directory with
    /// neither.
    pub(crate) fn read(vars: &Env, environment: Environment) -> Read<Self> {
        Ok(Self {
            listener: listener(vars, environment)?,
            client_ca: vars.pem_files("LDAP_CLIENT_CA_CERT_PATH", "LDAP_CLIENT_CA_KEY_PATH")?,
            max_connections: vars.number_in("LDAP_MAX_CONNECTIONS", 256, 1..=100_000)?,
            idle_timeout: vars.seconds("LDAP_IDLE_TIMEOUT_SECONDS", Duration::from_secs(300))?,
            handshake_timeout: vars
                .seconds("LDAP_HANDSHAKE_TIMEOUT_SECONDS", Duration::from_secs(10))?,
            binds_per_ip_per_minute: vars.number_in(
                "LDAP_BINDS_PER_IP_PER_MINUTE",
                30,
                1..=100_000,
            )?,
            binds_per_tenant_per_minute: vars.number_in(
                "LDAP_MAX_BIND_ATTEMPTS_PER_MINUTE",
                30,
                1..=100_000,
            )?,
            client_cert_validity: vars.days(
                "LDAP_CLIENT_CERT_VALIDITY_DAYS",
                Duration::from_secs(90 * 86_400),
            )?,
        })
    }
}

/// Where the directory listens and how its connections are protected, when
/// `LDAP_BIND_ADDR` is set.
fn listener(vars: &Env, environment: Environment) -> Read<Option<DirectoryListener>> {
    let address = vars.parsed("LDAP_BIND_ADDR", |address| address.parse::<SocketAddr>())?;
    let tls = vars.pem_files("LDAP_TLS_CERT_PATH", "LDAP_TLS_KEY_PATH")?;
    let ended_upstream = vars.flag(TERMINATED_UPSTREAM, false)?;
    let Some(address) = address else {
        return ensure_nothing_for_no_listener(tls.as_ref(), ended_upstream).map(|()| None);
    };
    let transport = transport(tls, ended_upstream, environment)?;
    Ok(Some(DirectoryListener { address, transport }))
}

/// Refuses a certificate, or the word that TLS ends upstream, for a
/// directory that does not listen.
fn ensure_nothing_for_no_listener(tls: Option<&PemFiles>, ended_upstream: bool) -> Read<()> {
    if tls.is_some() {
        return Err(ConfigError::contradicts(
            "LDAP_TLS_CERT_PATH",
            "is set without LDAP_BIND_ADDR",
        ));
    }
    if ended_upstream {
        return Err(ConfigError::contradicts(
            TERMINATED_UPSTREAM,
            "is set without LDAP_BIND_ADDR",
        ));
    }
    Ok(())
}

/// How a listening directory's connections are protected. Plain takes the
/// explicit word in production.
fn transport(
    tls: Option<PemFiles>,
    ended_upstream: bool,
    environment: Environment,
) -> Read<DirectoryTransport> {
    match (tls, ended_upstream) {
        (Some(_), true) => Err(ConfigError::contradicts(
            TERMINATED_UPSTREAM,
            "is set with LDAP_TLS_CERT_PATH; the directory either ends TLS itself or leaves it to what is in front",
        )),
        (Some(files), false) => Ok(DirectoryTransport::Tls(files)),
        (None, true) => Ok(DirectoryTransport::EndedUpstream),
        (None, false) if environment.is_production() => Err(ConfigError::missing(
            "LDAP_TLS_CERT_PATH and LDAP_TLS_KEY_PATH, or LDAP_TLS_TERMINATED_UPSTREAM=true when TLS is ended in front of the directory,",
        )),
        (None, false) => Ok(DirectoryTransport::PlainInDevelopment),
    }
}

#[cfg(test)]
mod tests {
    use Environment::{Development, Production};

    use super::*;

    /// The directory's own certificate and key.
    fn certificate() -> [(&'static str, &'static str); 2] {
        [
            ("LDAP_TLS_CERT_PATH", "/run/pki/ldap.crt"),
            ("LDAP_TLS_KEY_PATH", "/run/pki/ldap.key"),
        ]
    }

    /// The listener `pairs` set up, read in `environment`.
    fn listening(
        environment: Environment,
        pairs: &[(&'static str, &'static str)],
    ) -> Read<Option<DirectoryListener>> {
        let mut all = vec![("LDAP_BIND_ADDR", "0.0.0.0:636")];
        all.extend_from_slice(pairs);
        DirectoryConfig::read(&Env::of(all), environment).map(|config| config.listener)
    }

    /// With nothing set, no directory listens, in production too.
    #[test]
    fn with_nothing_set_no_directory_listens() {
        let config = DirectoryConfig::read(&Env::of([]), Production).unwrap();

        assert!(config.listener.is_none());
        assert_eq!(config.max_connections, 256);
    }

    /// A production directory with its certificate serves LDAPS.
    #[test]
    fn a_production_directory_with_its_certificate_serves_tls() {
        let listener = listening(Production, &certificate()).unwrap().unwrap();

        assert!(matches!(listener.transport, DirectoryTransport::Tls(_)));
    }

    /// A production LDAP listener without TLS configuration is refused,
    /// naming the missing certificate settings.
    #[test]
    fn a_production_directory_without_tls_is_refused() {
        let read = listening(Production, &[]);

        assert!(
            matches!(read, Err(ConfigError::Missing { name }) if name.starts_with("LDAP_TLS_CERT_PATH"))
        );
    }

    /// A production directory behind something that ends TLS takes plain
    /// connections once the setting says so.
    #[test]
    fn a_production_directory_takes_plain_once_tls_is_said_to_end_upstream() {
        let listener = listening(Production, &[(TERMINATED_UPSTREAM, "true")])
            .unwrap()
            .unwrap();

        assert_eq!(listener.transport, DirectoryTransport::EndedUpstream);
    }

    /// A development directory may take plain connections with nothing set.
    #[test]
    fn a_development_directory_may_take_plain_connections() {
        let listener = listening(Development, &[]).unwrap().unwrap();

        assert_eq!(listener.transport, DirectoryTransport::PlainInDevelopment);
    }

    /// A listener certificate conflicts with a setting that TLS ends
    /// upstream, and configuration names that conflicting setting.
    #[test]
    fn a_certificate_and_tls_ended_upstream_together_are_refused() {
        let mut pairs = certificate().to_vec();
        pairs.push((TERMINATED_UPSTREAM, "true"));

        let read = listening(Production, &pairs);

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == TERMINATED_UPSTREAM)
        );
    }

    /// TLS said to end upstream for a directory that does not listen is
    /// refused.
    #[test]
    fn tls_ended_upstream_for_no_listener_is_refused() {
        let vars = Env::of([(TERMINATED_UPSTREAM, "true")]);

        assert!(DirectoryConfig::read(&vars, Development).is_err());
    }

    /// An LDAP certificate without its key is refused even in development.
    #[test]
    fn half_a_certificate_pair_is_refused() {
        let read = listening(Development, &[("LDAP_TLS_CERT_PATH", "/run/pki/ldap.crt")]);

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "LDAP_TLS_CERT_PATH")
        );
    }

    /// A certificate for a directory that does not listen is refused.
    #[test]
    fn a_certificate_for_no_listener_is_refused() {
        assert!(DirectoryConfig::read(&Env::of(certificate()), Development).is_err());
    }

    /// A listen address that is no address is refused.
    #[test]
    fn a_listen_address_that_is_no_address_is_refused() {
        let vars = Env::of([("LDAP_BIND_ADDR", "ldap.example.com")]);

        assert!(DirectoryConfig::read(&vars, Development).is_err());
    }
}

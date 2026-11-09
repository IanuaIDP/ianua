//! Where the gateway listens and how its connections are taken on: the
//! main listener and its TLS, the peers whose PROXY header and
//! `X-Forwarded-For` are believed, the side listeners, and how long a
//! connection may take over each step.
//!
//! The main listener ends TLS itself, with the certificate stored for each
//! name it serves, so in production it never takes plain connections.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_boot::environment::Environment;
use ianua_boot::network::PemFiles;
use ianua_domain::domains::proxy::request::forwarded::TrustedProxies;

use crate::config::internal::{Clients, InternalListen, InternalSettings, internal_listen};

/// The setting that asks for plain HTTP on the main listener.
const PLAIN_HTTP: &str = "GATEWAY_PLAIN_HTTP";

/// The settings of the workflow listener.
const WORKFLOW_LISTENER: InternalSettings = InternalSettings {
    listen: "GATEWAY_WORKFLOW_LISTEN",
    clients: Clients::Certified {
        authority: "GATEWAY_WORKFLOW_CA_FILE",
    },
    certificate: "GATEWAY_WORKFLOW_TLS_CERT_FILE",
    key: "GATEWAY_WORKFLOW_TLS_KEY_FILE",
};

/// The settings of the runner listener. A runner holds no certificate of
/// the internal authority; every request it sends carries its agent's
/// proof.
const RUNNER_LISTENER: InternalSettings = InternalSettings {
    listen: "GATEWAY_RUNNER_LISTEN",
    clients: Clients::Uncertified,
    certificate: "GATEWAY_RUNNER_TLS_CERT_FILE",
    key: "GATEWAY_RUNNER_TLS_KEY_FILE",
};

/// How the main listener protects its connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MainTransport {
    /// TLS, with the certificate stored for the name each client asks for.
    Tls {
        /// `GATEWAY_TLS_CERT` and `GATEWAY_TLS_KEY`: the platform's own
        /// certificate, served for the base domain and every name one label
        /// under it (`*.<PROXY_BASE_DOMAIN>`), where tenants' platform
        /// subdomains live. None serves those names only where a stored
        /// certificate covers them. It is never served for any other name:
        /// a name no certificate covers is refused at the handshake.
        platform: Option<PemFiles>,
    },
    /// Plain HTTP, because `GATEWAY_PLAIN_HTTP` asks for it outside
    /// production.
    PlainInDevelopment,
}

/// Whether connections begin with a PROXY protocol v2 header naming the
/// real client.
#[derive(Debug, Clone)]
pub(crate) enum ProxyProtocol {
    /// No header is expected: the socket peer is the client.
    Off,
    /// `GATEWAY_PROXY_PROTOCOL_PEERS`: every connection from these peers
    /// begins with the header. The header is unauthenticated, so a
    /// connection from any other peer is refused rather than believed.
    From(TrustedProxies),
}

/// How long a connection may take over each step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConnectionTimeouts {
    /// `GATEWAY_HANDSHAKE_TIMEOUT_SECONDS` (10): the TLS handshake.
    pub handshake: Duration,
    /// `GATEWAY_HEADER_TIMEOUT_SECONDS` (10): the PROXY header and the
    /// request's head.
    pub header: Duration,
    /// `GATEWAY_IDLE_TIMEOUT_SECONDS` (30): a connection reading and
    /// writing nothing.
    pub idle: Duration,
}

/// Where the gateway listens and how.
#[derive(Debug, Clone)]
pub(crate) struct ListenConfig {
    /// `GATEWAY_LISTEN` (`0.0.0.0:8080`): the main listener.
    pub main: SocketAddr,
    /// How the main listener protects its connections.
    pub transport: MainTransport,
    /// Whether the main listener's connections begin with a PROXY header.
    pub proxy_protocol: ProxyProtocol,
    /// `TRUSTED_PROXIES`: the proxies whose `X-Forwarded-For` is believed;
    /// empty trusts nobody. The server reads the same setting.
    pub trusted_proxies: TrustedProxies,
    /// `GATEWAY_ACME_LISTEN`: the plain HTTP listener a certificate
    /// authority fetches its challenges from, usually port 80. None leaves
    /// tenants' own domains uncertifiable over HTTP.
    pub acme: Option<SocketAddr>,
    /// `GATEWAY_RUNNER_LISTEN`: the in-cluster listener agent runners send
    /// through, serving TLS with `GATEWAY_RUNNER_TLS_CERT_FILE` and
    /// `GATEWAY_RUNNER_TLS_KEY_FILE` and asking no client certificate. It
    /// never takes a PROXY header: a runner shares its pod with its agent,
    /// which could otherwise name its own address.
    pub runners: Option<InternalListen>,
    /// `GATEWAY_WORKFLOW_LISTEN`: the in-cluster listener Protected apps
    /// steps call from the worker, serving mutual TLS with
    /// `GATEWAY_WORKFLOW_CA_FILE`, `GATEWAY_WORKFLOW_TLS_CERT_FILE` and
    /// `GATEWAY_WORKFLOW_TLS_KEY_FILE`. A request there reaches only the
    /// route its run pass names, and never takes a PROXY header. None
    /// leaves Protected apps unreachable.
    pub workflows: Option<InternalListen>,
    /// `GATEWAY_STATUS_LISTEN` (`0.0.0.0:9090`): `/health/live`,
    /// `/health/ready` and `/metrics`, apart from the main listener since
    /// the metrics describe the deployment.
    pub status: SocketAddr,
    /// How long a connection may take over each step.
    pub timeouts: ConnectionTimeouts,
    /// `SHUTDOWN_GRACE_SECONDS` (30): how long a stop waits for the
    /// requests and streams in flight before the process ends them. The
    /// server reads the same setting.
    pub shutdown_grace: Duration,
}

impl ListenConfig {
    /// The listener settings `vars` holds, in `environment`.
    ///
    /// # Errors
    ///
    /// An address or peer that does not read, half of a certificate and
    /// key, plain HTTP beside a certificate or in production, two listeners
    /// on one port, or a timeout out of its range.
    pub(crate) fn read(vars: &Env, environment: Environment) -> Read<Self> {
        let config = Self {
            main: address(vars, "GATEWAY_LISTEN", "0.0.0.0:8080")?,
            transport: transport(vars, environment)?,
            proxy_protocol: proxy_protocol(vars)?,
            trusted_proxies: vars.peers("TRUSTED_PROXIES")?,
            acme: optional_address(vars, "GATEWAY_ACME_LISTEN")?,
            runners: internal_listen(vars, environment, &RUNNER_LISTENER)?,
            workflows: internal_listen(vars, environment, &WORKFLOW_LISTENER)?,
            status: address(vars, "GATEWAY_STATUS_LISTEN", "0.0.0.0:9090")?,
            timeouts: timeouts(vars)?,
            shutdown_grace: vars.seconds_in(
                "SHUTDOWN_GRACE_SECONDS",
                Duration::from_secs(30),
                1..=3600,
            )?,
        };
        config.ensure_ports_apart()?;
        config.ensure_workflows_private()?;
        Ok(config)
    }

    /// Refuses a workflow listener on a public address: a run pass is only
    /// ever sent inside the deployment's own network, and a listener the
    /// internet reaches would take one lifted off it. Every address of the
    /// host (`0.0.0.0`), loopback, private and link-local addresses are
    /// taken; a pod's network policy keeps the rest out.
    fn ensure_workflows_private(&self) -> Read<()> {
        let Some(workflows) = &self.workflows else {
            return Ok(());
        };
        if is_inside(workflows.address.ip()) {
            return Ok(());
        }
        Err(ConfigError::contradicts(
            "GATEWAY_WORKFLOW_LISTEN",
            "names a public address; the workflow listener only serves the deployment's own network",
        ))
    }

    /// Refuses two listeners on one port: whichever binds second fails, or
    /// on some systems both take a share of the other's connections.
    fn ensure_ports_apart(&self) -> Read<()> {
        let listeners = [
            ("GATEWAY_LISTEN", Some(self.main)),
            ("GATEWAY_ACME_LISTEN", self.acme),
            (
                "GATEWAY_RUNNER_LISTEN",
                self.runners.as_ref().map(|listen| listen.address),
            ),
            (
                "GATEWAY_WORKFLOW_LISTEN",
                self.workflows.as_ref().map(|listen| listen.address),
            ),
            ("GATEWAY_STATUS_LISTEN", Some(self.status)),
        ];
        let bound: Vec<(&str, u16)> = listeners
            .into_iter()
            .filter_map(|(name, address)| Some((name, address?.port())))
            .filter(|(_, port)| *port != 0)
            .collect();
        for (index, (name, port)) in bound.iter().enumerate() {
            let Some((first, _)) = bound[..index].iter().find(|(_, other)| other == port) else {
                continue;
            };
            return Err(ConfigError::contradicts(
                name,
                format!("listens on the same port as {first}"),
            ));
        }
        Ok(())
    }
}

/// Whether `ip` is an address of the deployment's own network: every
/// address of the host, loopback, private or link-local.
fn is_inside(ip: IpAddr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

/// The address `name` holds, or `default`.
fn address(vars: &Env, name: &str, default: &str) -> Read<SocketAddr> {
    let value = vars.text(name, default)?;
    value.parse().map_err(|_| {
        ConfigError::invalid(
            name,
            format!("must be an address and port such as 0.0.0.0:8080, got {value:?}"),
        )
    })
}

/// The address `name` holds, or `None` when it is unset.
fn optional_address(vars: &Env, name: &str) -> Read<Option<SocketAddr>> {
    vars.parsed(name, |value| value.parse::<SocketAddr>())
}

/// How the main listener protects its connections. Plain HTTP takes the
/// explicit word, and never in production.
fn transport(vars: &Env, environment: Environment) -> Read<MainTransport> {
    let platform = vars.pem_files("GATEWAY_TLS_CERT", "GATEWAY_TLS_KEY")?;
    let plain = vars.flag(PLAIN_HTTP, false)?;
    match (plain, platform) {
        (false, platform) => Ok(MainTransport::Tls { platform }),
        (true, Some(_)) => Err(ConfigError::contradicts(
            PLAIN_HTTP,
            "is set with GATEWAY_TLS_CERT; the main listener either ends TLS or serves plain HTTP",
        )),
        (true, None) if environment.is_production() => Err(ConfigError::contradicts(
            PLAIN_HTTP,
            "is set in production, where the gateway ends TLS for every name it serves",
        )),
        (true, None) => Ok(MainTransport::PlainInDevelopment),
    }
}

/// Whether connections begin with a PROXY header, and from whom.
fn proxy_protocol(vars: &Env) -> Read<ProxyProtocol> {
    let peers = vars.peers("GATEWAY_PROXY_PROTOCOL_PEERS")?;
    if peers.is_empty() {
        return Ok(ProxyProtocol::Off);
    }
    Ok(ProxyProtocol::From(peers))
}

/// How long a connection may take over each step.
fn timeouts(vars: &Env) -> Read<ConnectionTimeouts> {
    Ok(ConnectionTimeouts {
        handshake: vars.seconds_in(
            "GATEWAY_HANDSHAKE_TIMEOUT_SECONDS",
            Duration::from_secs(10),
            1..=120,
        )?,
        header: vars.seconds_in(
            "GATEWAY_HEADER_TIMEOUT_SECONDS",
            Duration::from_secs(10),
            1..=120,
        )?,
        idle: vars.seconds_in(
            "GATEWAY_IDLE_TIMEOUT_SECONDS",
            Duration::from_secs(30),
            1..=3600,
        )?,
    })
}

#[cfg(test)]
mod tests {
    use Environment::{Development, Production};

    use super::*;

    /// With nothing set, the main listener ends TLS on port 8080 with no
    /// platform certificate, believes no PROXY header and no forwarded
    /// address, and opens only the status listener beside it.
    #[test]
    fn with_nothing_set_the_documented_defaults_hold() {
        let config = ListenConfig::read(&Env::of([]), Production).unwrap();

        assert_eq!(config.main.to_string(), "0.0.0.0:8080");
        assert_eq!(config.transport, MainTransport::Tls { platform: None });
        assert!(matches!(config.proxy_protocol, ProxyProtocol::Off));
        assert!(config.trusted_proxies.is_empty());
        assert!(config.acme.is_none() && config.runners.is_none() && config.workflows.is_none());
        assert_eq!(config.status.to_string(), "0.0.0.0:9090");
        assert_eq!(config.timeouts.handshake, Duration::from_secs(10));
        assert_eq!(config.timeouts.header, Duration::from_secs(10));
        assert_eq!(config.timeouts.idle, Duration::from_secs(30));
        assert_eq!(config.shutdown_grace, Duration::from_secs(30));
    }

    /// The platform's certificate is read with its key.
    #[test]
    fn the_platform_certificate_is_read_with_its_key() {
        let vars = Env::of([
            ("GATEWAY_TLS_CERT", "/etc/ianua/tls/tls.crt"),
            ("GATEWAY_TLS_KEY", "/etc/ianua/tls/tls.key"),
        ]);

        let config = ListenConfig::read(&vars, Production).unwrap();

        assert!(matches!(
            config.transport,
            MainTransport::Tls { platform: Some(_) }
        ));
    }

    /// A platform certificate without its private key is rejected as contradictory configuration.
    #[test]
    fn a_certificate_without_its_key_is_refused() {
        let read = ListenConfig::read(
            &Env::of([("GATEWAY_TLS_CERT", "/etc/ianua/tls/tls.crt")]),
            Production,
        );

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "GATEWAY_TLS_CERT")
        );
    }

    /// Explicitly enabling plain HTTP in production is rejected with the transport setting named.
    #[test]
    fn plain_http_in_production_is_refused() {
        let read = ListenConfig::read(&Env::of([(PLAIN_HTTP, "true")]), Production);

        assert!(matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == PLAIN_HTTP));
    }

    /// Plain HTTP is had in development by asking for it.
    #[test]
    fn plain_http_in_development_is_had_by_asking() {
        let config = ListenConfig::read(&Env::of([(PLAIN_HTTP, "true")]), Development).unwrap();

        assert_eq!(config.transport, MainTransport::PlainInDevelopment);
    }

    /// Plain HTTP beside a certificate is refused: nobody can tell which
    /// was meant.
    #[test]
    fn plain_http_beside_a_certificate_is_refused() {
        let vars = Env::of([
            (PLAIN_HTTP, "true"),
            ("GATEWAY_TLS_CERT", "/etc/ianua/tls/tls.crt"),
            ("GATEWAY_TLS_KEY", "/etc/ianua/tls/tls.key"),
        ]);

        let read = ListenConfig::read(&vars, Development);

        assert!(matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == PLAIN_HTTP));
    }

    /// PROXY headers are believed from the peers listed, and from no one
    /// else.
    #[test]
    fn proxy_headers_are_believed_from_the_listed_peers_alone() {
        let vars = Env::of([("GATEWAY_PROXY_PROTOCOL_PEERS", "10.42.0.0/16")]);

        let config = ListenConfig::read(&vars, Production).unwrap();

        let ProxyProtocol::From(peers) = config.proxy_protocol else {
            panic!("expected PROXY headers from the listed peers");
        };
        assert!(peers.contains("10.42.3.4".parse().unwrap()));
        assert!(!peers.contains("203.0.113.9".parse().unwrap()));
    }

    /// A malformed CIDR among valid PROXY peers rejects the peer configuration.
    #[test]
    fn a_peer_that_is_no_address_is_refused() {
        let read = ListenConfig::read(
            &Env::of([("GATEWAY_PROXY_PROTOCOL_PEERS", "10.42.0.0/16, 10.42.0/16")]),
            Production,
        );

        assert!(
            matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "GATEWAY_PROXY_PROTOCOL_PEERS")
        );
    }

    /// A trusted proxy that is no address is refused.
    #[test]
    fn a_trusted_proxy_that_is_no_address_is_refused() {
        let read = ListenConfig::read(&Env::of([("TRUSTED_PROXIES", "ingress")]), Production);

        assert!(
            matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "TRUSTED_PROXIES")
        );
    }

    /// Binding the status listener to the main listener's port is rejected as contradictory.
    #[test]
    fn two_listeners_on_one_port_are_refused() {
        let read = ListenConfig::read(
            &Env::of([("GATEWAY_STATUS_LISTEN", "0.0.0.0:8080")]),
            Production,
        );

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "GATEWAY_STATUS_LISTEN")
        );
    }

    /// A public workflow listener address is rejected; private IPv4, private
    /// IPv6 and all-interface bindings remain accepted in development.
    #[test]
    fn the_workflow_listener_is_refused_on_a_public_address() {
        let on = |address: &str| {
            ListenConfig::read(
                &Env::of([("GATEWAY_WORKFLOW_LISTEN", address)]),
                Development,
            )
        };

        let public = on("203.0.113.7:8082");

        assert!(
            matches!(public, Err(ConfigError::Contradicts { name, .. }) if name == "GATEWAY_WORKFLOW_LISTEN")
        );
        assert!(on("10.0.4.2:8082").is_ok());
        assert!(on("0.0.0.0:8082").is_ok());
        assert!(on("[fd00::7]:8082").is_ok());
    }

    /// Giving the workflow and runner listeners the same port rejects the workflow setting.
    #[test]
    fn the_workflow_listener_shares_no_port() {
        let read = ListenConfig::read(
            &Env::of([
                ("GATEWAY_RUNNER_LISTEN", "0.0.0.0:8081"),
                ("GATEWAY_WORKFLOW_LISTEN", "0.0.0.0:8081"),
            ]),
            Development,
        );

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "GATEWAY_WORKFLOW_LISTEN")
        );
    }

    /// An address that does not read is refused, naming the setting.
    #[test]
    fn an_address_that_does_not_read_is_refused() {
        let read = ListenConfig::read(&Env::of([("GATEWAY_LISTEN", "8080")]), Production);

        assert!(matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "GATEWAY_LISTEN"));
    }

    /// A zero handshake timeout and a one-day idle timeout are both rejected.
    #[test]
    fn a_timeout_out_of_its_range_is_refused() {
        let zero = ListenConfig::read(
            &Env::of([("GATEWAY_HANDSHAKE_TIMEOUT_SECONDS", "0")]),
            Production,
        );
        let long = ListenConfig::read(
            &Env::of([("GATEWAY_IDLE_TIMEOUT_SECONDS", "86400")]),
            Production,
        );

        assert!(zero.is_err());
        assert!(long.is_err());
    }
}

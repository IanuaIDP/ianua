//! What an operator tells the nameservers: where to listen, whom the zones
//! name as their contact, and where the zones come from. In the cluster
//! that is the database, signed in to as the nameservers' own role; on a
//! host of its own, which cannot reach the database, it is the control
//! plane's stream over mutual TLS.

use std::net::SocketAddr;
use std::time::Duration;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_boot::environment::Environment;
use ianua_boot::foundation::{DatabaseConfig, DatabaseRole};
use ianua_boot::logging::LoggingConfig;
use ianua_domain::domains::tenant::custom_domains::dns_zone::{Authority, RecordName};
use ianua_domain::shared::security::secret::Secret;

use crate::follow::ControlPlaneLink;

/// The setting that makes a nameserver follow the control plane.
const ENDPOINT: &str = "CONTROL_PLANE_ENDPOINT";

/// The setting that makes a nameserver read the database.
const DATABASE_LOGIN: &str = "NAMESERVER_DATABASE_URL";

/// Where the zones come from.
#[derive(Debug, Clone)]
pub(crate) enum ZoneSource {
    /// In the cluster: the database, as the nameservers' own role.
    Database {
        /// `NAMESERVER_DATABASE_URL` and the pool settings. Boxed: the
        /// pool settings are many times the size of a link.
        database: Box<DatabaseConfig>,
        /// `DNS_REFRESH_SECONDS` (15): how often the zones are loaded
        /// again. A tenant's change answers within this, plus the record's
        /// own TTL.
        refresh: Duration,
    },
    /// On a host of its own: the control plane's stream, set by
    /// `CONTROL_PLANE_ENDPOINT` and its certificates.
    ControlPlane(ControlPlaneLink),
}

/// Everything the nameservers need to start.
#[derive(Debug, Clone)]
pub(crate) struct NameserverConfig {
    /// `LOG_LEVEL` and `LOG_FORMAT`.
    pub logging: LoggingConfig,
    /// Where the zones come from: `NAMESERVER_DATABASE_URL` or
    /// `CONTROL_PLANE_ENDPOINT`, never both.
    pub zones: ZoneSource,
    /// `DNS_BIND` (`0.0.0.0:53`): where to listen, on UDP and TCP alike.
    pub bind: SocketAddr,
    /// `DNS_HOSTMASTER`: the contact every zone's `SOA` names, written
    /// with a dot where an address has an `@`, such as
    /// `hostmaster.example.com`.
    pub hostmaster: RecordName,
    /// `SHUTDOWN_GRACE_SECONDS` (10): how long a stop waits for the
    /// queries in flight.
    pub shutdown_grace: Duration,
}

impl NameserverConfig {
    /// The settings `vars` holds.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] naming the first setting missing or refused.
    pub(crate) fn read(vars: &Env) -> Read<Self> {
        let environment = Environment::read(vars)?;
        Ok(Self {
            logging: LoggingConfig::read(vars, environment)?,
            zones: zone_source(vars)?,
            bind: vars
                .parsed("DNS_BIND", |address| address.parse::<SocketAddr>())?
                .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 53))),
            hostmaster: vars.required_parsed("DNS_HOSTMASTER", RecordName::new)?,
            shutdown_grace: vars.seconds("SHUTDOWN_GRACE_SECONDS", Duration::from_secs(10))?,
        })
    }

    /// Who every zone says answers for it.
    #[must_use]
    pub(crate) fn authority(&self) -> Authority {
        Authority::new(self.hostmaster.clone())
    }
}

/// The source the settings name: the control plane when its endpoint is
/// set, the database when its login is, and refused with neither or both.
fn zone_source(vars: &Env) -> Read<ZoneSource> {
    let endpoint = vars.url(ENDPOINT)?;
    let login_set = vars.secret(DATABASE_LOGIN)?.is_some();
    match (endpoint, login_set) {
        (Some(_), true) => Err(ConfigError::contradicts(
            DATABASE_LOGIN,
            "is set beside CONTROL_PLANE_ENDPOINT; a nameserver reads its zones from one of them",
        )),
        (Some(endpoint), false) => control_plane(vars, &endpoint).map(ZoneSource::ControlPlane),
        (None, true) => Ok(ZoneSource::Database {
            database: Box::new(DatabaseConfig::read(vars, DatabaseRole::Nameserver)?),
            refresh: vars.seconds_in("DNS_REFRESH_SECONDS", Duration::from_secs(15), 1..=3_600)?,
        }),
        (None, false) => Err(ConfigError::missing(
            "NAMESERVER_DATABASE_URL in the cluster, or CONTROL_PLANE_ENDPOINT on a host of its own,",
        )),
    }
}

/// The link to the control plane at `endpoint`, with this host's
/// certificate and key and the authority the control plane is checked
/// against.
fn control_plane(vars: &Env, endpoint: &url::Url) -> Read<ControlPlaneLink> {
    if endpoint.scheme() != "https" {
        return Err(ConfigError::invalid(
            ENDPOINT,
            "must be an https URL: the link is mutual TLS",
        ));
    }
    let host = endpoint
        .host_str()
        .unwrap_or_default()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let file = |name: &str| {
        vars.file_text(name)?
            .ok_or_else(|| ConfigError::missing(name))
    };
    Ok(ControlPlaneLink {
        endpoint: endpoint.as_str().to_owned(),
        server_name: vars.text("CONTROL_PLANE_SERVER_NAME", host)?,
        certificate_pem: file("CONTROL_PLANE_CLIENT_CERT")?,
        private_key_pem: Secret::new(file("CONTROL_PLANE_CLIENT_KEY")?),
        authority_pem: file("CONTROL_PLANE_CA_CERT")?,
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    const LOGIN: &str = "postgres://ianua_nameserver:ns-pw@db.internal:5432/ianua";

    /// Whether `error` refuses `DNS_HOSTMASTER`, as unset or as no name.
    fn is_hostmaster_refusal(error: &ConfigError) -> bool {
        match error {
            ConfigError::Rejected { name, .. } | ConfigError::Missing { name } => {
                name == "DNS_HOSTMASTER"
            }
            _ => false,
        }
    }

    fn settings(extra: &[(&'static str, &'static str)]) -> Env {
        let base = [
            ("NAMESERVER_DATABASE_URL", LOGIN),
            ("DNS_HOSTMASTER", "hostmaster.example.com"),
        ];
        Env::of(base.into_iter().chain(extra.iter().copied()))
    }

    /// A folder holding a certificate, a key and an authority file.
    fn pem_files() -> tempfile::TempDir {
        let folder = tempfile::tempdir().unwrap();
        for name in ["ns1-cert.pem", "ns1-key.pem", "ca-cert.pem"] {
            std::fs::write(folder.path().join(name), "-----BEGIN PEM-----").unwrap();
        }
        folder
    }

    fn path(folder: &Path, name: &str) -> String {
        folder.join(name).to_string_lossy().into_owned()
    }

    /// The settings of a host following the control plane at `endpoint`,
    /// its files in `folder`.
    fn following(folder: &Path, endpoint: &str) -> Vec<(String, String)> {
        vec![
            ("CONTROL_PLANE_ENDPOINT".to_owned(), endpoint.to_owned()),
            (
                "CONTROL_PLANE_CLIENT_CERT".to_owned(),
                path(folder, "ns1-cert.pem"),
            ),
            (
                "CONTROL_PLANE_CLIENT_KEY".to_owned(),
                path(folder, "ns1-key.pem"),
            ),
            (
                "CONTROL_PLANE_CA_CERT".to_owned(),
                path(folder, "ca-cert.pem"),
            ),
            (
                "DNS_HOSTMASTER".to_owned(),
                "hostmaster.example.com".to_owned(),
            ),
        ]
    }

    fn env_of(pairs: &[(String, String)]) -> Env {
        Env::of(
            pairs
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        )
    }

    /// Unset, the nameservers listen on port 53 everywhere, load the zones
    /// every fifteen seconds and sign in as their own role.
    #[test]
    fn the_defaults_listen_on_53_and_reload_every_fifteen_seconds() {
        let config = NameserverConfig::read(&settings(&[])).unwrap();

        assert_eq!(config.bind, SocketAddr::from(([0, 0, 0, 0], 53)));
        let ZoneSource::Database { database, refresh } = config.zones else {
            panic!("a nameserver with a database login reads the database");
        };
        assert_eq!(refresh, Duration::from_secs(15));
        assert_eq!(database.login.role, "ianua_nameserver");
    }

    /// Supplying only the application's database login leaves the
    /// nameserver's own zone-source setting missing.
    #[test]
    fn the_apps_login_alone_does_not_start_a_nameserver() {
        let vars = Env::of([
            ("DATABASE_URL", "postgres://ianua_app:pw@db.internal/ianua"),
            ("DNS_HOSTMASTER", "hostmaster.example.com"),
        ]);

        let read = NameserverConfig::read(&vars);

        assert!(
            matches!(read, Err(ConfigError::Missing { name }) if name.starts_with("NAMESERVER_DATABASE_URL"))
        );
    }

    /// A host given the control plane's endpoint and its files follows
    /// the control plane, checking its certificate against the endpoint's
    /// host.
    #[test]
    fn an_endpoint_makes_the_nameserver_follow_the_control_plane() {
        let folder = pem_files();
        let vars = env_of(&following(folder.path(), "https://grpc.ianua.io:50051"));

        let config = NameserverConfig::read(&vars).unwrap();

        let ZoneSource::ControlPlane(link) = config.zones else {
            panic!("a host given the endpoint follows the control plane");
        };
        assert_eq!(link.server_name, "grpc.ianua.io");
        assert_eq!(link.authority_pem, "-----BEGIN PEM-----");
    }

    /// Configuring both a zone stream and a nameserver database login is
    /// refused as contradictory.
    #[test]
    fn an_endpoint_beside_a_database_login_is_refused() {
        let folder = pem_files();
        let mut pairs = following(folder.path(), "https://grpc.ianua.io:50051");
        pairs.push(("NAMESERVER_DATABASE_URL".to_owned(), LOGIN.to_owned()));

        let read = NameserverConfig::read(&env_of(&pairs));

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "NAMESERVER_DATABASE_URL")
        );
    }

    /// A plain HTTP control-plane endpoint is refused by setting name.
    #[test]
    fn a_plain_endpoint_is_refused() {
        let folder = pem_files();

        let read = NameserverConfig::read(&env_of(&following(
            folder.path(),
            "http://grpc.ianua.io:50051",
        )));

        assert!(
            matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "CONTROL_PLANE_ENDPOINT")
        );
    }

    /// Omitting the client certificate refuses stream configuration and
    /// names the missing certificate setting.
    #[test]
    fn a_missing_client_certificate_is_refused() {
        let folder = pem_files();
        let pairs: Vec<(String, String)> = following(folder.path(), "https://grpc.ianua.io")
            .into_iter()
            .filter(|(name, _)| name != "CONTROL_PLANE_CLIENT_CERT")
            .collect();

        let read = NameserverConfig::read(&env_of(&pairs));

        assert!(
            matches!(read, Err(ConfigError::Missing { name }) if name == "CONTROL_PLANE_CLIENT_CERT")
        );
    }

    /// A nameserver database login without a zone contact is refused for
    /// the missing hostmaster setting.
    #[test]
    fn a_missing_contact_is_refused() {
        let vars = Env::of([("NAMESERVER_DATABASE_URL", LOGIN)]);

        let read = NameserverConfig::read(&vars);

        assert!(read.is_err_and(|error| is_hostmaster_refusal(&error)));
    }

    /// A contact that is no name is refused, naming the setting.
    #[test]
    fn a_contact_that_is_no_name_is_refused() {
        let vars = settings(&[("DNS_HOSTMASTER", "not a name")]);

        let read = NameserverConfig::read(&vars);

        assert!(read.is_err_and(|error| is_hostmaster_refusal(&error)));
    }

    /// An address that does not read is refused rather than replaced by
    /// the default.
    #[test]
    fn an_address_that_does_not_read_is_refused() {
        let read = NameserverConfig::read(&settings(&[("DNS_BIND", "port 53")]));

        assert!(read.is_err());
    }
}

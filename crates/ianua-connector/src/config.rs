//! Every setting the connector reads, read once from the environment and
//! checked together before anything starts.
//!
//! The connector runs in a tenant's own network, outside the platform. It
//! holds no platform secret and no login: any of them given to it is
//! refused at start, so a copied compose file cannot leave the platform's
//! root on a machine the platform does not run.

use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_boot::environment::Environment;
use ianua_boot::logging::LoggingConfig;
use ianua_domain::shared::security::secret::Secret;
use url::{Host, Url};

use crate::targets::AllowList;

/// The settings only the platform holds, and why the connector must not.
const PLATFORM_ONLY: [(&str, &str); 10] = [
    ("HMAC_SECRET", "is the platform's shared root"),
    ("ENCRYPTION_KEY", "seals the platform's stored secrets"),
    ("EVENT_SIGNING_SECRET", "is the control plane's root"),
    ("DATABASE_URL", "is the app's database login"),
    ("GATEWAY_DATABASE_URL", "is the data plane's database login"),
    ("MIGRATION_DATABASE_URL", "is the database owner's login"),
    ("AUDIT_PURGE_DATABASE_URL", "may remove audit records"),
    ("CONNECTOR_CA_KEY", "signs every connector's certificate"),
    ("BUS_URL", "reaches the platform's message bus"),
    ("CACHE_URL", "reaches the platform's shared state"),
];

/// The default folder the connector keeps its key and certificate in.
const DEFAULT_STATE_DIR: &str = "/var/lib/ianua-connector";

/// Why a host and port was not read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("must be host:port, an IPv6 address in brackets")]
pub(crate) struct AddressError;

/// The gateway's connector listener: the name or address the connector
/// dials, which is also the name its certificate is checked against, and
/// the port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GatewayAddress {
    host: String,
    port: u16,
}

impl GatewayAddress {
    /// The host, unbracketed.
    #[must_use]
    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    /// Socket number of the gateway listener accepting connector links.
    #[must_use]
    pub(crate) fn port(&self) -> u16 {
        self.port
    }
}

impl FromStr for GatewayAddress {
    type Err = AddressError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (host, port) = match text.strip_prefix('[') {
            Some(rest) => rest.split_once("]:").ok_or(AddressError)?,
            None => text.rsplit_once(':').ok_or(AddressError)?,
        };
        let unbracketed_v6 = !text.starts_with('[') && host.contains(':');
        if host.is_empty() || unbracketed_v6 {
            return Err(AddressError);
        }
        let port = port
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or(AddressError)?;
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }
}

/// Why a tenant path was not read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("must be organization-slug/tenant-slug")]
pub(crate) struct TenantPathError;

/// The organization and tenant the connector belongs to, by slug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TenantPath {
    organization: String,
    tenant: String,
}

impl TenantPath {
    /// The organization's slug.
    #[must_use]
    pub(crate) fn organization(&self) -> &str {
        &self.organization
    }

    /// The tenant's slug.
    #[must_use]
    pub(crate) fn tenant(&self) -> &str {
        &self.tenant
    }
}

impl FromStr for TenantPath {
    type Err = TenantPathError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (organization, tenant) = text.split_once('/').ok_or(TenantPathError)?;
        if !is_slug(organization) || !is_slug(tenant) {
            return Err(TenantPathError);
        }
        Ok(Self {
            organization: organization.to_owned(),
            tenant: tenant.to_owned(),
        })
    }
}

/// Where the API is and whom the connector enrolls with.
#[derive(Debug, Clone)]
pub(crate) struct ApiConfig {
    /// `CONNECTOR_API_URL`: the ianua API, over HTTPS unless it is on this
    /// machine.
    pub url: Url,
    /// `CONNECTOR_TENANT`: `organization-slug/tenant-slug`.
    pub tenant: TenantPath,
    /// `CONNECTOR_ENROLLMENT_CODE` or `CONNECTOR_ENROLLMENT_CODE_FILE`:
    /// the one-time code, needed only until the connector has enrolled.
    pub enrollment_code: Option<Secret>,
}

/// What the connector and each of its steps may take on.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// `CONNECTOR_MAX_LINKS` (8): the most gateway addresses linked at
    /// once.
    pub links: usize,
    /// `CONNECTOR_MAX_STREAMS` (256): the most connections relayed at once
    /// on one link.
    pub streams: u32,
    /// `CONNECTOR_DIAL_TIMEOUT_SECONDS` (10): the longest resolving and
    /// connecting to a target may take.
    pub dial: Duration,
    /// `CONNECTOR_IDLE_TIMEOUT_SECONDS` (300): how long a relayed
    /// connection may carry nothing before it is closed.
    pub idle: Duration,
    /// `CONNECTOR_HANDSHAKE_TIMEOUT_SECONDS` (10): the longest connecting
    /// to the gateway and its TLS handshake may take.
    pub handshake: Duration,
    /// `CONNECTOR_REQUEST_TIMEOUT_SECONDS` (30): the longest one call to the
    /// API may take.
    pub request: Duration,
    /// `CONNECTOR_RESOLVE_SECONDS` (30): how often the gateway's name is
    /// resolved again.
    pub resolve: Duration,
    /// `CONNECTOR_BACKOFF_MAX_SECONDS` (60): the longest wait before trying
    /// again.
    pub backoff_max: Duration,
    /// `CONNECTOR_SHUTDOWN_GRACE_SECONDS` (10): how long a stop waits for
    /// the connections in flight.
    pub shutdown_grace: Duration,
}

/// Every setting the connector runs with.
#[derive(Debug, Clone)]
pub(crate) struct Config {
    /// What is logged and how.
    pub logging: LoggingConfig,
    /// The API it enrolls and renews with.
    pub api: ApiConfig,
    /// `CONNECTOR_GATEWAY_ADDRESS`: the gateway's connector listener.
    pub gateway: GatewayAddress,
    /// `CONNECTOR_STATE_DIR` (`/var/lib/ianua-connector`): where its key,
    /// certificate and enrollment are kept.
    pub state_dir: PathBuf,
    /// `CONNECTOR_ALLOWED_TARGETS`: the only local targets it dials.
    pub targets: AllowList,
    /// What it may take on.
    pub limits: Limits,
}

impl Config {
    /// Every setting `vars` holds, checked together.
    ///
    /// # Errors
    ///
    /// The first setting refused: a platform secret, or a setting missing
    /// or not of its kind.
    pub(crate) fn read(vars: &Env) -> Read<Self> {
        ensure_no_platform_secret(vars)?;
        let environment = Environment::read(vars)?;
        Ok(Self {
            logging: LoggingConfig::read(vars, environment)?,
            api: api(vars)?,
            gateway: vars.required_parsed("CONNECTOR_GATEWAY_ADDRESS", |text| text.parse())?,
            state_dir: vars
                .path("CONNECTOR_STATE_DIR")?
                .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR)),
            targets: targets(vars)?,
            limits: limits(vars)?,
        })
    }
}

/// The API the connector enrolls and renews with.
fn api(vars: &Env) -> Read<ApiConfig> {
    let url = vars
        .url("CONNECTOR_API_URL")?
        .ok_or_else(|| ConfigError::missing("CONNECTOR_API_URL"))?;
    if url.scheme() != "https" && !is_loopback(&url) {
        return Err(ConfigError::invalid(
            "CONNECTOR_API_URL",
            "must be an https URL; plain http is taken only on this machine",
        ));
    }
    Ok(ApiConfig {
        url,
        tenant: vars.required_parsed("CONNECTOR_TENANT", |text| text.parse())?,
        enrollment_code: vars.secret("CONNECTOR_ENROLLMENT_CODE")?,
    })
}

/// The allow list, which must name something.
fn targets(vars: &Env) -> Read<AllowList> {
    let entries = vars.list("CONNECTOR_ALLOWED_TARGETS")?;
    if entries.is_empty() {
        return Err(ConfigError::missing("CONNECTOR_ALLOWED_TARGETS"));
    }
    AllowList::parse(entries.iter().map(String::as_str))
        .map_err(|cause| ConfigError::rejected("CONNECTOR_ALLOWED_TARGETS", cause))
}

/// What the connector and its steps may take on.
fn limits(vars: &Env) -> Read<Limits> {
    let seconds_in = |name: &str, default: u64, most: u64| {
        vars.seconds_in(name, Duration::from_secs(default), 1..=most)
    };
    Ok(Limits {
        links: vars.number_in("CONNECTOR_MAX_LINKS", 8, 1..=64)?,
        streams: vars.number_in("CONNECTOR_MAX_STREAMS", 256, 1..=10_000)?,
        dial: seconds_in("CONNECTOR_DIAL_TIMEOUT_SECONDS", 10, 300)?,
        idle: seconds_in("CONNECTOR_IDLE_TIMEOUT_SECONDS", 300, 86_400)?,
        handshake: seconds_in("CONNECTOR_HANDSHAKE_TIMEOUT_SECONDS", 10, 300)?,
        request: seconds_in("CONNECTOR_REQUEST_TIMEOUT_SECONDS", 30, 600)?,
        resolve: seconds_in("CONNECTOR_RESOLVE_SECONDS", 30, 3_600)?,
        backoff_max: seconds_in("CONNECTOR_BACKOFF_MAX_SECONDS", 60, 3_600)?,
        shutdown_grace: vars
            .seconds("CONNECTOR_SHUTDOWN_GRACE_SECONDS", Duration::from_secs(10))?,
    })
}

/// Refuses any platform secret or login, given in its variable or as a
/// file.
fn ensure_no_platform_secret(vars: &Env) -> Read<()> {
    for (name, why) in PLATFORM_ONLY {
        let file = format!("{name}_FILE");
        let held = vars.optional(name)?.is_some() || vars.optional(&file)?.is_some();
        if held {
            return Err(ConfigError::contradicts(
                name,
                format!("is set on the connector, which must never hold it: it {why}"),
            ));
        }
    }
    Ok(())
}

/// Whether `url` points at this machine.
fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => IpAddr::V4(address).is_loopback(),
        Some(Host::Ipv6(address)) => IpAddr::V6(address).is_loopback(),
        None => false,
    }
}

/// Whether `text` is a slug: lower-case letters, digits and inner hyphens.
fn is_slug(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 63
        && !text.starts_with('-')
        && !text.ends_with('-')
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A complete environment, with `overrides` laid over it.
    fn vars(overrides: &[(&'static str, &'static str)]) -> Env {
        let mut pairs: Vec<(&str, &str)> = vec![
            ("CONNECTOR_API_URL", "https://api.ianua.example"),
            ("CONNECTOR_TENANT", "acme/main"),
            ("CONNECTOR_GATEWAY_ADDRESS", "connect.ianua.example:8444"),
            (
                "CONNECTOR_ENROLLMENT_CODE",
                "enroll code from the dashboard",
            ),
            ("CONNECTOR_ALLOWED_TARGETS", "wiki.corp.internal:443"),
        ];
        for &(name, value) in overrides {
            pairs.retain(|(kept, _)| *kept != name);
            pairs.push((name, value));
        }
        Env::of(pairs)
    }

    /// A complete environment reads with bounded defaults.
    #[test]
    fn a_complete_environment_reads_with_safe_defaults() {
        let config = Config::read(&vars(&[])).unwrap();

        assert_eq!(config.gateway.host(), "connect.ianua.example");
        assert_eq!(config.gateway.port(), 8444);
        assert_eq!(config.api.tenant.organization(), "acme");
        assert_eq!(config.state_dir, PathBuf::from(DEFAULT_STATE_DIR));
        assert_eq!(config.limits.links, 8);
        assert_eq!(config.limits.streams, 256);
        assert_eq!(config.limits.idle, Duration::from_secs(300));
    }

    /// Platform roots, database logins and a connector-authority key file
    /// are refused in connector configuration.
    #[test]
    fn a_platform_secret_is_refused() {
        for name in [
            "HMAC_SECRET",
            "DATABASE_URL",
            "GATEWAY_DATABASE_URL",
            "CONNECTOR_CA_KEY_FILE",
        ] {
            let read = Config::read(&vars(&[(name, "anything")]));

            assert!(
                matches!(read, Err(ConfigError::Contradicts { .. })),
                "{name}"
            );
        }
    }

    /// An empty target allow list refuses configuration and names the
    /// missing setting.
    #[test]
    fn no_allow_list_is_refused() {
        let read = Config::read(&vars(&[("CONNECTOR_ALLOWED_TARGETS", "")]));

        assert!(
            read.unwrap_err()
                .to_string()
                .contains("CONNECTOR_ALLOWED_TARGETS")
        );
    }

    /// A remote API using plain HTTP is refused, while a loopback HTTP
    /// endpoint remains usable.
    #[test]
    fn plain_http_is_taken_only_on_this_machine() {
        let remote = Config::read(&vars(&[("CONNECTOR_API_URL", "http://api.ianua.example")]));
        let local = Config::read(&vars(&[("CONNECTOR_API_URL", "http://127.0.0.1:3000")]));

        assert!(remote.is_err());
        assert!(local.is_ok());
    }

    /// A gateway address with no port, or a tenant without its
    /// organization, is refused.
    #[test]
    fn a_malformed_address_or_tenant_is_refused() {
        assert!(
            Config::read(&vars(&[(
                "CONNECTOR_GATEWAY_ADDRESS",
                "connect.ianua.example"
            )]))
            .is_err()
        );
        assert!(Config::read(&vars(&[("CONNECTOR_TENANT", "main")])).is_err());
        assert!("[fd00::1]:8444".parse::<GatewayAddress>().is_ok());
    }
}

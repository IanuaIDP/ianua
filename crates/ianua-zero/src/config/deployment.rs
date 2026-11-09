//! Where the gateway runs and what it serves: the environment, the domain
//! tenants' platform subdomains sit under, the dashboard's address tenants'
//! tokens are issued under, the fleet it shares threat verdicts with, and
//! the country database the geo fence reads.

use std::fmt;
use std::path::PathBuf;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_boot::environment::Environment;
use ianua_boot::hosts;
use ianua_domain::domains::tenant::hosts::PlatformAddressing;
use ianua_domain::types::{DomainName, HttpsUrl};

/// The longest fleet name taken.
const LONGEST_FLEET: usize = 64;

/// The fleet a gateway belongs to: the gateways that share threat verdicts.
///
/// It is part of the bus subject the verdicts travel on, so it holds only
/// lowercase letters, digits, `-` and `_`: a dot would split the subject and
/// a `*` or `>` would match other fleets' verdicts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct FleetName(String);

impl FleetName {
    /// The fleet `name` names.
    ///
    /// # Errors
    ///
    /// [`FleetNameError`] when `name` is empty, longer than 64 characters,
    /// or holds anything but lowercase letters, digits, `-` and `_`.
    pub(crate) fn new(name: impl Into<String>) -> Result<Self, FleetNameError> {
        let name = name.into();
        let fits = (1..=LONGEST_FLEET).contains(&name.len())
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
        if !fits {
            return Err(FleetNameError);
        }
        Ok(Self(name))
    }

    /// The name, as it appears in the bus subject.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FleetName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a fleet name was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "a fleet name takes 1 to 64 lowercase letters, digits, '-' and '_', so it fits a bus subject"
)]
pub(crate) struct FleetNameError;

/// Where the gateway runs and what it serves.
#[derive(Debug, Clone)]
pub(crate) struct DeploymentConfig {
    /// The shared platform address shape, or custom domains only.
    pub platform_addressing: PlatformAddressing,
    /// `APP_ENV`, `production` unless `development` is asked for by name.
    pub environment: Environment,
    /// `PROXY_BASE_DOMAIN`: the domain tenants' platform subdomains sit
    /// under. The server reads the same setting, with the same value.
    pub base_domain: DomainName,
    /// `APP_BASE_URL`: the dashboard's public address, which a tenant's
    /// tokens name as their issuer unless the tenant set its own. The
    /// server reads the same setting, with the same value, or no token it
    /// issues is taken here.
    pub app_base_url: HttpsUrl,
    /// `GATEWAY_FLEET_ID` (`default`): the gateways this one shares blocked
    /// addresses and reputation flags with.
    pub fleet: FleetName,
    /// `GEOIP_DB_PATH`: the MaxMind City database client countries are
    /// looked up in. Without it no country is known, so a geo fence with an
    /// allow list refuses every caller. The server reads the same setting.
    pub geoip_database: Option<PathBuf>,
}

impl DeploymentConfig {
    /// The deployment settings `vars` holds.
    ///
    /// # Errors
    ///
    /// `APP_ENV` that names no environment, `PROXY_BASE_DOMAIN` missing or
    /// no domain, `APP_BASE_URL` missing or no `https` address, or a fleet
    /// name that does not fit a bus subject.
    pub(crate) fn read(vars: &Env) -> Read<Self> {
        Ok(Self {
            platform_addressing: hosts::addressing(vars)?,
            environment: Environment::read(vars)?,
            base_domain: vars.required_parsed("PROXY_BASE_DOMAIN", DomainName::new)?,
            app_base_url: vars.required_parsed("APP_BASE_URL", HttpsUrl::new)?,
            fleet: fleet(vars)?,
            geoip_database: vars.path("GEOIP_DB_PATH")?,
        })
    }
}

/// `GATEWAY_FLEET_ID`, or the `default` fleet.
fn fleet(vars: &Env) -> Read<FleetName> {
    let name = "GATEWAY_FLEET_ID";
    FleetName::new(vars.text(name, "default")?).map_err(|cause| ConfigError::rejected(name, cause))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAINS: [(&str, &str); 2] = [
        ("PROXY_BASE_DOMAIN", "apps.example.com"),
        ("APP_BASE_URL", "https://app.example.com"),
    ];

    /// With only the two addresses set, the gateway runs in production in
    /// the `default` fleet, with no country database.
    #[test]
    fn with_only_the_addresses_the_defaults_hold() {
        let config = DeploymentConfig::read(&Env::of(DOMAINS)).unwrap();

        assert_eq!(config.environment, Environment::Production);
        assert_eq!(config.base_domain.as_str(), "apps.example.com");
        assert_eq!(config.app_base_url.as_str(), "https://app.example.com");
        assert_eq!(config.fleet.as_str(), "default");
        assert!(config.geoip_database.is_none());
    }

    /// Setting the proxy domain without the dashboard address reports the missing issuer setting.
    #[test]
    fn the_dashboard_address_must_be_set() {
        let read = DeploymentConfig::read(&Env::of([("PROXY_BASE_DOMAIN", "apps.example.com")]));

        assert!(matches!(read, Err(ConfigError::Missing { name }) if name == "APP_BASE_URL"));
    }

    /// Empty deployment settings report the missing domain needed for tenant application hosts.
    #[test]
    fn the_base_domain_must_be_set() {
        let read = DeploymentConfig::read(&Env::of([]));

        assert!(matches!(read, Err(ConfigError::Missing { name }) if name == "PROXY_BASE_DOMAIN"));
    }

    /// A base domain that is no domain is refused.
    #[test]
    fn a_base_domain_that_is_no_domain_is_refused() {
        let read = DeploymentConfig::read(&Env::of([("PROXY_BASE_DOMAIN", "not a domain")]));

        assert!(
            matches!(read, Err(ConfigError::Rejected { name, .. }) if name == "PROXY_BASE_DOMAIN")
        );
    }

    /// A fleet name containing a bus wildcard is rejected with the fleet setting named.
    #[test]
    fn a_fleet_name_that_breaks_the_subject_is_refused() {
        let read = DeploymentConfig::read(&Env::of([
            DOMAINS[0],
            DOMAINS[1],
            ("GATEWAY_FLEET_ID", "prod.*"),
        ]));

        assert!(
            matches!(read, Err(ConfigError::Rejected { name, .. }) if name == "GATEWAY_FLEET_ID")
        );
    }

    /// A fleet name of letters, digits, dashes and underscores is taken.
    #[test]
    fn a_plain_fleet_name_is_taken() {
        assert_eq!(FleetName::new("eu-west_1").unwrap().as_str(), "eu-west_1");
        assert!(FleetName::new("x".repeat(65)).is_err());
        assert!(FleetName::new("Prod").is_err());
    }
}

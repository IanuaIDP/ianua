//! Every setting the gateway reads, read once from the environment and
//! checked together before anything starts.
//!
//! Each area reads its own settings through [`Env`], every reader naming
//! the variable it reads, and refuses what it cannot use with that name.
//! The readers both composition roots share (the environment, the logs,
//! the database, the keys, the bus, the cache and the namespace their
//! names sit under) live in `ianua-boot`, and
//! are read here by the gateway's role: it signs in as its own database
//! role and holds the shared root and the sealing keys, never the control
//! plane's root. [`Config::read`] then checks the areas against each other:
//! a production gateway needs the bus and the cache every node shares, and
//! no gateway may hold a secret only the control plane holds. No setting
//! is read anywhere else.

pub mod agents;
pub mod app_sign_in;
pub mod connectors;
pub mod credentials;
pub mod deployment;
pub mod forward;
pub mod internal;
pub mod limits;
pub mod listen;
pub mod observability;
pub mod reload;
pub mod secrets;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_boot::environment::Environment;
use ianua_boot::foundation::{BusConfig, CacheConfig, DatabaseConfig, DatabaseRole, SharedKeys};
use ianua_boot::logging::LoggingConfig;
use ianua_infra::namespace::Namespace;

use crate::config::agents::AgentsConfig;
use crate::config::app_sign_in::AppSignInConfig;
use crate::config::connectors::ConnectorsConfig;
use crate::config::credentials::CredentialsConfig;
use crate::config::deployment::DeploymentConfig;
use crate::config::forward::ForwardConfig;
use crate::config::limits::LimitsConfig;
use crate::config::listen::ListenConfig;
use crate::config::observability::ObservabilityConfig;
use crate::config::reload::ReloadConfig;

/// The settings only the control plane holds. A gateway faces the internet,
/// so holding any of them would hand whoever takes it what the gateway's
/// own role and keys are kept apart from.
const CONTROL_PLANE_ONLY: [(&str, &str); 5] = [
    (
        "EVENT_SIGNING_SECRET",
        "is the control plane's root, which would let a gateway seal any event",
    ),
    (
        "DATABASE_URL",
        "is the app's login; the gateway signs in as GATEWAY_DATABASE_URL",
    ),
    (
        "MIGRATION_DATABASE_URL",
        "is the database owner's login, past every grant",
    ),
    (
        "AUDIT_PURGE_DATABASE_URL",
        "is the login that may remove audit records",
    ),
    (
        "CONNECTOR_CA_KEY_FILE",
        "signs every connector's certificate, which would let a gateway mint a link for any tenant",
    ),
];

/// Every setting the gateway runs with.
#[derive(Debug, Clone)]
pub(crate) struct Config {
    /// Where the gateway runs and what it serves.
    pub deployment: DeploymentConfig,
    /// What is logged and how.
    pub logging: LoggingConfig,
    /// The database, reached as the gateway's role.
    pub database: DatabaseConfig,
    /// The shared root and the sealing keys.
    pub keys: SharedKeys,
    /// The message bus.
    pub bus: BusConfig,
    /// The shared state and the store caches.
    pub cache: CacheConfig,
    /// `NAMESPACE` (`ianua`): what every subject and stream on the bus
    /// server and every key on the cache server sits under. It must be the
    /// control plane's, or the gateway hears none of its changes.
    pub namespace: Namespace,
    /// Where the gateway listens and how.
    pub listen: ListenConfig,
    /// What one request and the gateway as a whole may take on.
    pub limits: LimitsConfig,
    /// Where the gateway may forward to.
    pub forward: ForwardConfig,
    /// Access recheck cadence and deadlines for open connections.
    pub agents: AgentsConfig,
    /// How presented credentials are checked.
    pub credentials: CredentialsConfig,
    /// Request records, spans and log shipping.
    pub observability: ObservabilityConfig,
    /// App sign-in and the API's internal channel.
    pub app_sign_in: AppSignInConfig,
    /// How often the configuration is read again.
    pub reload: ReloadConfig,
    /// Where connectors link in, and what their links are held to.
    pub connectors: ConnectorsConfig,
}

impl Config {
    /// Every setting `vars` holds, checked together.
    ///
    /// # Errors
    ///
    /// The first setting refused: a secret only the control plane holds,
    /// a setting its area refuses, or one the checks between areas refuse.
    pub(crate) fn read(vars: &Env) -> Read<Self> {
        ensure_no_control_plane_secret(vars)?;
        let deployment = DeploymentConfig::read(vars)?;
        let environment = deployment.environment;
        let config = Self {
            logging: LoggingConfig::read(vars, environment)?,
            database: DatabaseConfig::read(vars, DatabaseRole::Gateway)?,
            keys: SharedKeys::read(vars)?,
            bus: BusConfig::read(vars)?,
            cache: CacheConfig::read(vars)?,
            namespace: vars.namespace("NAMESPACE")?,
            listen: ListenConfig::read(vars, environment)?,
            limits: LimitsConfig::read(vars)?,
            forward: ForwardConfig::read(vars)?,
            agents: AgentsConfig::read(vars)?,
            credentials: CredentialsConfig::read(vars, environment)?,
            observability: ObservabilityConfig::read(vars)?,
            app_sign_in: {
                secrets::validate(vars, environment)?;
                AppSignInConfig::read(vars, environment)?
            },
            reload: ReloadConfig::read(vars)?,
            connectors: ConnectorsConfig::read(vars)?,
            deployment,
        };
        config.check_sharing()?;
        config.check_session_check()?;
        Ok(config)
    }

    /// The deployment classification used to enforce production-only requirements.
    #[must_use]
    pub(crate) fn environment(&self) -> Environment {
        self.deployment.environment
    }

    /// Requires the bus and the cache outside the process in production,
    /// and the cache wherever the bus is shared. A gateway on its own bus
    /// hears no configuration change and shares no verdict; one counting
    /// on its own lets a rate limit, a budget or a DPoP proof through once
    /// per gateway.
    fn check_sharing(&self) -> Read<()> {
        let production = self.environment().is_production();
        if production && self.bus.in_process() {
            return Err(ConfigError::missing(
                "BUS_URL, which a production gateway needs to hear configuration changes and share threat verdicts,",
            ));
        }
        if production && self.cache.in_process() {
            return Err(ConfigError::missing(
                "CACHE_URL, which a production gateway needs to share rate limits, budgets and replay checks,",
            ));
        }
        if !self.bus.in_process() && self.cache.in_process() {
            return Err(ConfigError::contradicts(
                "BUS_URL",
                "is set without CACHE_URL: gateways sharing a bus share their counts too",
            ));
        }
        Ok(())
    }

    /// Refuses an app session check allowed as long as the whole set of
    /// checks it runs inside: the request would be ended by the checks'
    /// timeout before the session's own.
    fn check_session_check(&self) -> Read<()> {
        if self.app_sign_in.session_check_timeout < self.limits.pipeline_timeout {
            return Ok(());
        }
        Err(ConfigError::contradicts(
            "GATEWAY_APP_SESSION_CHECK_TIMEOUT_MS",
            "is not shorter than GATEWAY_PIPELINE_TIMEOUT_MS",
        ))
    }
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
                format!("is set on the gateway, which must never hold it: it {why}"),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX_1: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const HEX_2: &str = "0000000000000000000000000000000000000000000000000000000000000002";
    const HEX_3: &str = "0000000000000000000000000000000000000000000000000000000000000003";

    /// The least a production gateway needs.
    fn production() -> Vec<(&'static str, &'static str)> {
        vec![
            ("PROXY_BASE_DOMAIN", "apps.example.com"),
            ("APP_BASE_URL", "https://app.example.com"),
            (
                "GATEWAY_DATABASE_URL",
                "postgres://ianua_gateway:gateway-pw@db/ianua",
            ),
            ("HMAC_SECRET", HEX_1),
            ("ENCRYPTION_KEY", HEX_3),
            ("BUS_URL", "nats://bus.internal:4222"),
            ("BUS_TOKEN", "bus-t0ken"),
            ("CACHE_URL", "redis://:cache-pw@cache.internal:6379"),
        ]
    }

    /// `production` with `dropped` left out and `extra` added.
    fn with(dropped: &[&str], extra: &[(&'static str, &'static str)]) -> Env {
        let mut pairs: Vec<_> = production()
            .into_iter()
            .filter(|(name, _)| !dropped.contains(name))
            .collect();
        pairs.extend_from_slice(extra);
        Env::of(pairs)
    }

    /// A production gateway starts with the least it needs, signed in as
    /// its own role.
    #[test]
    fn a_production_gateway_starts_with_the_least_it_needs() {
        let config = Config::read(&with(&[], &[])).unwrap();

        assert_eq!(config.environment(), Environment::Production);
        assert_eq!(config.database.login.role, "ianua_gateway");
        assert!(!config.bus.in_process());
        assert!(!config.cache.in_process());
        assert_eq!(config.namespace.as_str(), "ianua");
    }

    /// A gateway reads the namespace the control plane runs under, and
    /// refuses one that would break a subject or a key.
    #[test]
    fn a_namespace_is_read_and_one_breaking_a_name_refused() {
        let staging = Config::read(&with(&[], &[("NAMESPACE", "staging")]));
        let broken = Config::read(&with(&[], &[("NAMESPACE", "staging:eu")]));

        assert_eq!(staging.unwrap().namespace.as_str(), "staging");
        assert!(matches!(broken, Err(ConfigError::Rejected { name, .. }) if name == "NAMESPACE"));
    }

    /// The gateway's login must be set.
    #[test]
    fn the_gateways_login_must_be_set() {
        let read = Config::read(&with(&["GATEWAY_DATABASE_URL"], &[]));

        assert!(
            matches!(read, Err(ConfigError::Missing { name }) if name.starts_with("GATEWAY_DATABASE_URL"))
        );
    }

    /// Production settings without the shared cache are rejected with its missing URL named.
    #[test]
    fn production_without_the_cache_is_refused() {
        let read = Config::read(&with(&["CACHE_URL"], &[]));

        assert!(
            matches!(read, Err(ConfigError::Missing { name }) if name.starts_with("CACHE_URL"))
        );
    }

    /// Production settings without the shared bus are rejected with its missing URL named.
    #[test]
    fn production_without_the_bus_is_refused() {
        let read = Config::read(&with(&["BUS_URL", "BUS_TOKEN"], &[]));

        assert!(matches!(read, Err(ConfigError::Missing { name }) if name.starts_with("BUS_URL")));
    }

    /// A development gateway may keep the bus and the cache to itself.
    #[test]
    fn development_may_keep_the_bus_and_cache_to_itself() {
        let vars = with(
            &["BUS_URL", "BUS_TOKEN", "CACHE_URL"],
            &[("APP_ENV", "development")],
        );

        let config = Config::read(&vars).unwrap();

        assert!(config.bus.in_process());
        assert!(config.cache.in_process());
    }

    /// Gateways sharing a bus but counting on their own are refused, in
    /// development too.
    #[test]
    fn a_shared_bus_without_a_shared_cache_is_refused() {
        let vars = with(&["CACHE_URL"], &[("APP_ENV", "development")]);

        let read = Config::read(&vars);

        assert!(matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "BUS_URL"));
    }

    /// The control plane's event-signing secret is rejected on a gateway,
    /// whether supplied directly or through a file setting.
    #[test]
    fn the_control_plane_root_on_a_gateway_is_refused() {
        let given = Config::read(&with(&[], &[("EVENT_SIGNING_SECRET", HEX_2)]));
        let as_file = Config::read(&with(
            &[],
            &[("EVENT_SIGNING_SECRET_FILE", "/run/secrets/event-signing")],
        ));

        for read in [given, as_file] {
            assert!(
                matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "EVENT_SIGNING_SECRET")
            );
        }
    }

    /// The application's database login is rejected on a gateway without
    /// exposing its password in the error.
    #[test]
    fn the_apps_login_on_a_gateway_is_refused() {
        let read = Config::read(&with(
            &[],
            &[("DATABASE_URL", "postgres://ianua_app:app-pw@db/ianua")],
        ));

        let error = read.unwrap_err();
        assert!(matches!(&error, ConfigError::Contradicts { name, .. } if name == "DATABASE_URL"));
        assert!(!error.to_string().contains("app-pw"));
    }

    /// The owner's and the audit purge's logins are refused too.
    #[test]
    fn the_privileged_logins_on_a_gateway_are_refused() {
        for login in ["MIGRATION_DATABASE_URL", "AUDIT_PURGE_DATABASE_URL"] {
            let read = Config::read(&with(&[], &[(login, "postgres://postgres:pw@db/ianua")]));

            assert!(matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == login));
        }
    }

    /// A short HMAC passphrase is rejected without exposing its text in the error.
    #[test]
    fn a_short_shared_root_is_refused() {
        let read = Config::read(&with(
            &["HMAC_SECRET"],
            &[("HMAC_SECRET", "correct-horse-battery")],
        ));

        let error = read.unwrap_err();
        assert!(matches!(&error, ConfigError::Rejected { name, .. } if name == "HMAC_SECRET"));
        assert!(!error.to_string().contains("correct-horse"));
    }

    /// An app session check as long as all the checks is refused.
    #[test]
    fn a_session_check_as_long_as_the_pipeline_is_refused() {
        let read = Config::read(&with(
            &[],
            &[
                ("GATEWAY_PIPELINE_TIMEOUT_MS", "2000"),
                ("GATEWAY_APP_SESSION_CHECK_TIMEOUT_MS", "2000"),
            ],
        ));

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "GATEWAY_APP_SESSION_CHECK_TIMEOUT_MS")
        );
    }

    /// Debug output omits configured database, cache, bus, Vault and collector
    /// credentials as well as the HMAC and encryption keys.
    #[test]
    fn the_configuration_prints_no_secret() {
        let config = Config::read(&with(
            &[],
            &[
                ("VAULT_ADDR", "https://vault.internal:8200"),
                ("VAULT_TOKEN", "made up vault token"),
                ("LOG_SINK_URL", "https://logs.example.com/push"),
                ("LOG_SINK_AUTH", "X-Api-Key: sink-k3y"),
            ],
        ))
        .unwrap();

        let shown = format!("{config:?}");
        for secret in [
            "gateway-pw",
            "cache-pw",
            "bus-t0ken",
            "made up vault token",
            "sink-k3y",
            HEX_1,
            HEX_3,
        ] {
            assert!(!shown.contains(secret), "printed {secret}");
        }
    }
}

//! Every setting the server reads, read once from the environment and
//! checked together before anything starts.
//!
//! Each area reads its own settings through [`Env`], every reader naming
//! the variable it reads, and refuses what it cannot use with that name.
//! The readers every process shares (the environment, the logs, the
//! database, the keys, the bus, the cache and the files) live in
//! `ianua-boot`; the server's own areas live here. [`Config::read`] then
//! checks the areas against each other and against the command being run:
//! a split deployment needs a bus and a cache every node shares, the
//! worker needs the owner's and the audit purge's logins, and an API node
//! holds neither, nor the gateway's. No setting is read anywhere else.

pub mod deployment;
pub mod installation;
pub mod operator;
pub mod serving;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_boot::environment::Environment;
use ianua_boot::foundation::{
    AppDatabaseSettings, BusConfig, CacheConfig, ControlPlaneLogins, CryptoConfig, DatabaseConfig,
    DatabaseRole, FilesConfig,
};
use ianua_boot::internal_link::InternalCaller;
use ianua_boot::logging::LoggingConfig;
use ianua_infra::namespace::Namespace;

use crate::command::Command;
use crate::config::deployment::{DeploymentConfig, Mode};
use crate::config::installation::Installation;
use crate::config::operator::FirstOperatorConfig;
use crate::config::serving::{
    AgentsConfig, BillingConfig, CloudConfig, ConnectorsConfig, DirectoryConfig, DomainsConfig,
    HttpConfig, IntegrationsConfig, LimitsConfig, MailConfig, MemoryConfig, RelayConfig,
    SandboxesConfig, SignInConfig, SmsConfig, WORKFLOW_LINK, WorkerConfig,
};

/// Every setting the platform runs with.
#[derive(Debug, Clone)]
pub struct Config {
    /// Who the deployment serves and where it is reached.
    pub deployment: DeploymentConfig,
    /// What is logged and how.
    pub logging: LoggingConfig,
    /// The database, reached as the app's role.
    pub database: DatabaseConfig,
    /// Whether the app's role must be kept from the audit records, and how
    /// often the tenants' database routes are read again.
    pub app_database: AppDatabaseSettings,
    /// The owner's, the audit purge's and the gateway's logins, where set.
    pub logins: ControlPlaneLogins,
    /// The keys and the work of hashing.
    pub crypto: CryptoConfig,
    /// The message bus.
    pub bus: BusConfig,
    /// The shared state and the store caches.
    pub cache: CacheConfig,
    /// `NAMESPACE` (`ianua`): what every subject and stream on the bus
    /// server and every key on the cache server sits under, so deployments
    /// can share both servers.
    pub namespace: Namespace,
    /// Where files are kept.
    pub files: FilesConfig,
    /// The platform's own mail.
    pub(crate) mail: MailConfig,
    /// The text message provider.
    pub(crate) sms: SmsConfig,
    /// Lifetimes, execution limits and trusted attestation sources for machine identities.
    pub(crate) agents: AgentsConfig,
    /// The listeners and the calls out.
    pub http: HttpConfig,
    /// The outside services workflow steps call, such as GitHub and Slack.
    pub(crate) integrations: IntegrationsConfig,
    /// The gateway's workflow listener, which Protected apps steps call;
    /// none leaves Protected apps out.
    pub gateway_link: Option<InternalCaller>,
    /// The relay listener the gateway asks on, read only where `serve`
    /// runs an API, which alone opens it.
    pub(crate) relay: Option<RelayConfig>,
    /// Where sandbox versions' packages are fetched from.
    pub(crate) sandboxes: SandboxesConfig,
    /// The platform's embedding server and where memories' vectors are
    /// kept.
    pub(crate) memory: MemoryConfig,
    /// The rate limits and caps.
    pub limits: LimitsConfig,
    /// Queue concurrency, event delivery and recurring maintenance settings.
    pub(crate) worker: WorkerConfig,
    /// Sign-in, sessions, tokens and second factors.
    pub(crate) sign_in: SignInConfig,
    /// Tenants' own domains.
    pub(crate) domains: DomainsConfig,
    /// The LDAP directory.
    pub(crate) directory: DirectoryConfig,
    /// The authority connectors' certificates are signed by.
    pub connectors: ConnectorsConfig,
    /// Customers' own cloud accounts.
    pub(crate) cloud: CloudConfig,
    /// The payment provider organizations are billed through.
    pub(crate) billing: BillingConfig,
    /// The platform's first operator, for `ianua operator create` alone.
    pub first_operator: Option<FirstOperatorConfig>,
    /// The organization `ianua install` makes, for that command alone.
    pub installation: Option<Installation>,
}

impl Config {
    /// Every setting `vars` holds, checked for `command`.
    ///
    /// # Errors
    ///
    /// The first setting refused, by its area or by the checks between
    /// areas.
    pub fn read(vars: &Env, command: &Command) -> Read<Self> {
        let config = ConfigReader::new(vars, command)?.read()?;
        config.check(command)?;
        Ok(config)
    }

    /// The checks between areas, for `command`.
    fn check(&self, command: &Command) -> Read<()> {
        self.check_command(command)?;
        self.check_logins(command)?;
        self.check_sharing()?;
        self.check_certificate_orders()?;
        self.check_nameserver_link()
    }

    /// Refuses the nameserver link on a node that runs no API, which never
    /// opens it: whoever set it would believe the nameservers outside the
    /// cluster were fed.
    fn check_nameserver_link(&self) -> Read<()> {
        if self.deployment.mode.runs_api() || self.domains.grpc.is_none() {
            return Ok(());
        }
        Err(ConfigError::contradicts(
            "GRPC_LISTEN",
            "is set on a worker node, which never opens it; the nameserver link listens on API nodes",
        ))
    }

    /// Refuses a certificate order's job timeout no longer than the wait
    /// for its DNS proof to be seen, on a node that runs jobs: every order
    /// over DNS would be stopped while it still waits, and retried for
    /// ever.
    fn check_certificate_orders(&self) -> Read<()> {
        if !self.deployment.mode.runs_worker() {
            return Ok(());
        }
        if self.worker.jobs.tls_timeout > self.domains.proof_wait {
            return Ok(());
        }
        Err(ConfigError::contradicts(
            "JOB_TLS_TIMEOUT_SECONDS",
            "is not longer than ACME_DNS_PROPAGATION_TIMEOUT_SECONDS, so a certificate order would be stopped while it still waits for its DNS proof",
        ))
    }

    /// Refuses a command this deployment must not run.
    fn check_command(&self, command: &Command) -> Read<()> {
        match command {
            Command::Demo if self.deployment.environment.is_production() => {
                Err(ConfigError::contradicts(
                    "APP_ENV",
                    "is production, and the demo command seeds made-up people, keys and settings; it runs in development only",
                ))
            }
            Command::Install if !self.deployment.deployment.is_self_hosted() => {
                Err(ConfigError::contradicts(
                    "DEPLOYMENT",
                    "is not self_hosted, and the install command makes a self-hosted installation's organization",
                ))
            }
            Command::Serve
            | Command::Demo
            | Command::Install
            | Command::Migrate
            | Command::LinkPki(_)
            | Command::ConnectorPki(_)
            | Command::InternalPki(_)
            | Command::SandboxGate
            | Command::SandboxProxy
            | Command::CreateOperator { .. } => Ok(()),
        }
    }

    /// Requires the owner's and the audit purge's logins where they are
    /// used, and refuses them on an API node, which never uses them. The
    /// one-off commands that make the first records bring the schema up to
    /// date first, as the owner. The gateway's and the nameservers'
    /// logins, which only the migrations use to make their roles, are never
    /// required and refused on an API node too.
    fn check_logins(&self, command: &Command) -> Read<()> {
        let needs_them = matches!(
            command,
            Command::Install | Command::Migrate | Command::CreateOperator { .. }
        ) || self.deployment.mode.runs_worker();
        if !needs_them {
            self.ensure_no_migration_roles()?;
        }
        let logins = [
            ("MIGRATION_DATABASE_URL", self.logins.owner.is_some()),
            (
                "AUDIT_PURGE_DATABASE_URL",
                self.logins.audit_purge.is_some(),
            ),
        ];
        for (name, held) in logins {
            match (needs_them, held) {
                (true, false) => {
                    return Err(ConfigError::missing(&format!("{name} or {name}_FILE")));
                }
                (false, true) => {
                    return Err(ConfigError::contradicts(
                        name,
                        "is set on an API node, which never uses it; keep it to the worker",
                    ));
                }
                (true, true) | (false, false) => {}
            }
        }
        Ok(())
    }

    /// Refuses migration-only role logins before checking an API node's other credentials.
    fn ensure_no_migration_roles(&self) -> Read<()> {
        let role_logins = [
            ("GATEWAY_DATABASE_URL", self.logins.gateway.is_some()),
            ("NAMESERVER_DATABASE_URL", self.logins.nameserver.is_some()),
        ];
        let Some((name, _)) = role_logins.iter().find(|(_, held)| *held) else {
            return Ok(());
        };
        Err(ConfigError::contradicts(
            name,
            "is set on an API node, which never uses it; keep it to the worker",
        ))
    }

    /// Requires the bus and the cache to live outside the process when
    /// more than one process shares the work.
    fn check_sharing(&self) -> Read<()> {
        if self.deployment.mode.is_split() && self.bus.in_process() {
            return Err(ConfigError::missing(
                "BUS_URL, which a split MODE needs to reach the other processes,",
            ));
        }
        if self.deployment.mode.is_split() && self.cache.in_process() {
            return Err(ConfigError::missing(
                "CACHE_URL, which a split MODE needs to share counts with the other processes,",
            ));
        }
        if !self.bus.in_process() && self.cache.in_process() {
            return Err(ConfigError::contradicts(
                "BUS_URL",
                "is set without CACHE_URL: nodes sharing a bus share their counts and cache versions too",
            ));
        }
        Ok(())
    }

    /// The run mode.
    #[must_use]
    pub fn mode(&self) -> Mode {
        self.deployment.mode
    }

    /// The deployment classification used to enforce production-only requirements.
    #[must_use]
    pub fn environment(&self) -> Environment {
        self.deployment.environment
    }
}

/// The deployment and database settings later area readers depend on.
struct ConfigReader<'a> {
    vars: &'a Env,
    command: &'a Command,
    deployment: DeploymentConfig,
    logging: LoggingConfig,
    database: DatabaseConfig,
}

impl<'a> ConfigReader<'a> {
    /// Reads the shared prerequisites in their startup validation order.
    fn new(vars: &'a Env, command: &'a Command) -> Read<Self> {
        let deployment = DeploymentConfig::read(vars)?;
        let logging = LoggingConfig::read(vars, deployment.environment)?;
        let database = DatabaseConfig::read(vars, DatabaseRole::App)?;
        Ok(Self {
            vars,
            command,
            deployment,
            logging,
            database,
        })
    }

    /// Reads every area in order into the server's public configuration shape.
    /// The exhaustive field initializer keeps that shape and validation order visible together.
    #[allow(clippy::too_many_lines)]
    fn read(self) -> Read<Config> {
        Ok(Config {
            logging: self.logging,
            logins: ControlPlaneLogins::read(self.vars, &self.database.login)?,
            database: self.database,
            app_database: AppDatabaseSettings::read(self.vars, self.deployment.environment)?,
            crypto: CryptoConfig::read(self.vars)?,
            bus: BusConfig::read(self.vars)?,
            cache: CacheConfig::read(self.vars)?,
            namespace: self.vars.namespace("NAMESPACE")?,
            files: FilesConfig::read(self.vars)?,
            mail: MailConfig::read(self.vars, self.deployment.environment)?,
            sms: SmsConfig::read(self.vars, self.deployment.environment)?,
            agents: AgentsConfig::read(self.vars, &self.deployment.app_base_url)?,
            http: HttpConfig::read(self.vars)?,
            integrations: IntegrationsConfig::read(self.vars, self.deployment.environment)?,
            gateway_link: self
                .vars
                .internal_caller(&WORKFLOW_LINK, self.deployment.environment)?,
            relay: read_relay(self.vars, self.command, &self.deployment)?,
            sandboxes: SandboxesConfig::read(self.vars, self.deployment.environment)?,
            memory: MemoryConfig::read(self.vars)?,
            limits: LimitsConfig::read(self.vars)?,
            worker: WorkerConfig::read(self.vars)?,
            sign_in: SignInConfig::read(self.vars, self.deployment.environment)?,
            domains: DomainsConfig::read(self.vars, self.deployment.environment)?,
            directory: DirectoryConfig::read(self.vars, self.deployment.environment)?,
            connectors: ConnectorsConfig::read(self.vars)?,
            cloud: CloudConfig::read(self.vars)?,
            billing: BillingConfig::read(self.vars, &self.deployment.app_base_url)?,
            first_operator: FirstOperatorConfig::read(self.vars, self.command)?,
            installation: Installation::read(self.vars, self.command)?,
            deployment: self.deployment,
        })
    }
}

/// Reads relay settings only for a command and mode that open the API listener.
fn read_relay(
    vars: &Env,
    command: &Command,
    deployment: &DeploymentConfig,
) -> Read<Option<RelayConfig>> {
    match (command, deployment.mode.runs_api()) {
        (Command::Serve, true) => Ok(Some(RelayConfig::read(vars, deployment.environment)?)),
        _ => Ok(None),
    }
}

/// What the migrate command runs with: the database and the logs, and
/// nothing a migration does not use.
#[derive(Debug, Clone)]
pub(crate) struct MigrationConfig {
    /// What is logged and how.
    pub logging: LoggingConfig,
    /// The database, reached as the app's role.
    pub database: DatabaseConfig,
    /// The owner's and the audit purge's logins, and the gateway's where
    /// set.
    pub logins: ControlPlaneLogins,
}

impl MigrationConfig {
    /// The settings a migration reads from `vars`.
    ///
    /// # Errors
    ///
    /// A database setting refused, or the owner's or the audit purge's
    /// login missing.
    pub(crate) fn read(vars: &Env) -> Read<Self> {
        let environment = Environment::read(vars)?;
        let database = DatabaseConfig::read(vars, DatabaseRole::App)?;
        let logins = ControlPlaneLogins::read(vars, &database.login)?;
        if logins.owner.is_none() {
            return Err(ConfigError::missing(
                "MIGRATION_DATABASE_URL or MIGRATION_DATABASE_URL_FILE",
            ));
        }
        if logins.audit_purge.is_none() {
            return Err(ConfigError::missing(
                "AUDIT_PURGE_DATABASE_URL or AUDIT_PURGE_DATABASE_URL_FILE",
            ));
        }
        Ok(Self {
            logging: LoggingConfig::read(vars, environment)?,
            database,
            logins,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX_1: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const HEX_2: &str = "0000000000000000000000000000000000000000000000000000000000000002";
    const HEX_3: &str = "0000000000000000000000000000000000000000000000000000000000000003";

    /// The relay listener's three files, written once for every test: a
    /// production API node refuses to start without them.
    static RELAY_FILES: std::sync::LazyLock<[(&str, &str); 3]> = std::sync::LazyLock::new(|| {
        let folder = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        ["RELAY_CA_FILE", "RELAY_TLS_CERT_FILE", "RELAY_TLS_KEY_FILE"].map(|name| {
            let path = folder.path().join(name);
            std::fs::write(&path, "pem text").unwrap();
            let path: &'static str = Box::leak(path.display().to_string().into_boxed_str());
            (name, path)
        })
    });

    /// The least a single node running everything needs.
    fn single_node() -> Vec<(&'static str, &'static str)> {
        let mut pairs = vec![
            ("APP_BASE_URL", "https://app.example.com"),
            ("PROXY_BASE_DOMAIN", "apps.example.com"),
            ("DATABASE_URL", "postgres://ianua_app:app-pw@db/ianua"),
            (
                "MIGRATION_DATABASE_URL",
                "postgres://postgres:owner-pw@db/ianua",
            ),
            (
                "AUDIT_PURGE_DATABASE_URL",
                "postgres://ianua_audit_purge:purge-pw@db/ianua",
            ),
            ("HMAC_SECRET", HEX_1),
            ("EVENT_SIGNING_SECRET", HEX_2),
            ("ENCRYPTION_KEY", HEX_3),
            ("EMAIL_FROM", "noreply@example.com"),
            ("SMTP_HOST", "smtp.example.com"),
            ("WEBAUTHN_RP_ID", "example.com"),
            ("WEBAUTHN_RP_ORIGIN", "https://app.example.com"),
            (
                "ACME_DIRECTORY_URL",
                "https://acme-v02.api.letsencrypt.org/directory",
            ),
        ];
        pairs.extend(*RELAY_FILES);
        pairs
    }

    /// `single_node` with `name` dropped and `extra` added.
    fn with(dropped: &[&str], extra: &[(&'static str, &'static str)]) -> Env {
        let mut pairs: Vec<_> = single_node()
            .into_iter()
            .filter(|(name, _)| !dropped.contains(name))
            .collect();
        pairs.extend_from_slice(extra);
        Env::of(pairs)
    }

    /// A single node running everything starts with the least it needs.
    #[test]
    fn a_single_node_starts_with_the_least_it_needs() {
        let config = Config::read(&with(&[], &[]), &Command::Serve).unwrap();

        assert_eq!(config.mode(), Mode::All);
        assert!(config.bus.in_process());
        assert_eq!(config.namespace.as_str(), "ianua");
    }

    /// A relay port clash refuses API serving, while migration and
    /// worker-only configuration ignore the relay listener.
    #[test]
    fn the_relay_is_read_only_where_an_api_is_served() {
        let clash = [("PORT", "3000"), ("RELAY_PORT", "3000")];
        let worker = [
            ("MODE", "worker"),
            ("BUS_URL", "nats://bus.internal:4222"),
            ("CACHE_URL", "redis://cache.internal:6379"),
        ];

        let served = Config::read(&with(&[], &clash), &Command::Serve);
        let migrated = Config::read(&with(&[], &clash), &Command::Migrate).unwrap();
        let on_a_worker = Config::read(
            &with(&[], &[clash.as_slice(), &worker].concat()),
            &Command::Serve,
        )
        .unwrap();

        assert!(
            matches!(served, Err(ConfigError::Contradicts { name, .. }) if name == "RELAY_PORT")
        );
        assert!(migrated.relay.is_none());
        assert!(on_a_worker.relay.is_none());
    }

    /// Two deployments sharing a bus and a cache server each name their
    /// own namespace; one that would break a subject or a key is refused.
    #[test]
    fn a_namespace_is_read_and_one_breaking_a_name_refused() {
        let staging = Config::read(&with(&[], &[("NAMESPACE", "staging")]), &Command::Serve);
        let broken = Config::read(&with(&[], &[("NAMESPACE", "ianua.prod")]), &Command::Serve);

        assert_eq!(staging.unwrap().namespace.as_str(), "staging");
        assert!(matches!(broken, Err(ConfigError::Rejected { name, .. }) if name == "NAMESPACE"));
    }

    /// A TLS job timeout equal to the DNS proof wait is refused as a
    /// contradictory job timeout setting.
    #[test]
    fn a_tls_timeout_within_the_proofs_wait_is_refused() {
        let vars = with(
            &[],
            &[
                ("JOB_TLS_TIMEOUT_SECONDS", "120"),
                ("ACME_DNS_PROPAGATION_TIMEOUT_SECONDS", "120"),
            ],
        );

        let read = Config::read(&vars, &Command::Serve);

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "JOB_TLS_TIMEOUT_SECONDS")
        );
    }

    /// Worker configuration requires the audit purge database login.
    #[test]
    fn a_worker_without_the_purge_login_is_refused() {
        let read = Config::read(&with(&["AUDIT_PURGE_DATABASE_URL"], &[]), &Command::Serve);

        assert!(
            matches!(read, Err(ConfigError::Missing { name }) if name.starts_with("AUDIT_PURGE_DATABASE_URL"))
        );
    }

    /// API-only configuration refuses the database owner's login.
    #[test]
    fn an_api_node_holding_the_owner_login_is_refused() {
        let vars = with(
            &["AUDIT_PURGE_DATABASE_URL"],
            &[
                ("MODE", "api"),
                ("BUS_URL", "nats://bus.internal:4222"),
                ("CACHE_URL", "redis://cache.internal:6379"),
            ],
        );

        let read = Config::read(&vars, &Command::Serve);

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "MIGRATION_DATABASE_URL")
        );
    }

    /// An API node without the owner's and the purge's logins starts.
    #[test]
    fn an_api_node_without_the_privileged_logins_starts() {
        let vars = with(
            &["AUDIT_PURGE_DATABASE_URL", "MIGRATION_DATABASE_URL"],
            &[
                ("MODE", "api"),
                ("BUS_URL", "nats://bus.internal:4222"),
                ("CACHE_URL", "redis://cache.internal:6379"),
            ],
        );

        assert!(Config::read(&vars, &Command::Serve).is_ok());
    }

    /// A worker holding the gateway's login reads it, for the migrations
    /// to make the gateway's role with.
    #[test]
    fn a_worker_reads_the_gateway_login() {
        let vars = with(
            &[],
            &[(
                "GATEWAY_DATABASE_URL",
                "postgres://ianua_gateway:gateway-pw@db/ianua",
            )],
        );

        let config = Config::read(&vars, &Command::Serve).unwrap();

        assert!(config.logins.gateway.is_some());
    }

    /// API-only configuration refuses the gateway database login.
    #[test]
    fn an_api_node_holding_the_gateway_login_is_refused() {
        let vars = with(
            &["AUDIT_PURGE_DATABASE_URL", "MIGRATION_DATABASE_URL"],
            &[
                ("MODE", "api"),
                ("BUS_URL", "nats://bus.internal:4222"),
                ("CACHE_URL", "redis://cache.internal:6379"),
                (
                    "GATEWAY_DATABASE_URL",
                    "postgres://ianua_gateway:gateway-pw@db/ianua",
                ),
            ],
        );

        let read = Config::read(&vars, &Command::Serve);

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "GATEWAY_DATABASE_URL")
        );
    }

    /// A worker holding the nameservers' login reads it, for the
    /// migrations to make the nameservers' role with.
    #[test]
    fn a_worker_reads_the_nameserver_login() {
        let vars = with(
            &[],
            &[(
                "NAMESERVER_DATABASE_URL",
                "postgres://ianua_nameserver:ns-pw@db/ianua",
            )],
        );

        let config = Config::read(&vars, &Command::Serve).unwrap();

        assert!(config.logins.nameserver.is_some());
    }

    /// API-only configuration refuses the nameserver database login.
    #[test]
    fn an_api_node_holding_the_nameserver_login_is_refused() {
        let vars = with(
            &["AUDIT_PURGE_DATABASE_URL", "MIGRATION_DATABASE_URL"],
            &[
                ("MODE", "api"),
                ("BUS_URL", "nats://bus.internal:4222"),
                ("CACHE_URL", "redis://cache.internal:6379"),
                (
                    "NAMESERVER_DATABASE_URL",
                    "postgres://ianua_nameserver:ns-pw@db/ianua",
                ),
            ],
        );

        let read = Config::read(&vars, &Command::Serve);

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "NAMESERVER_DATABASE_URL")
        );
    }

    /// Worker-only configuration requires a shared bus URL.
    #[test]
    fn a_split_mode_on_an_in_process_bus_is_refused() {
        let read = Config::read(&with(&[], &[("MODE", "worker")]), &Command::Serve);

        assert!(matches!(read, Err(ConfigError::Missing { name }) if name.starts_with("BUS_URL")));
    }

    /// A shared bus without a shared cache is refused as contradictory
    /// configuration.
    #[test]
    fn a_shared_bus_without_a_shared_cache_is_refused() {
        let read = Config::read(
            &with(&[], &[("BUS_URL", "nats://bus.internal:4222")]),
            &Command::Serve,
        );

        assert!(matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "BUS_URL"));
    }

    /// The demo command refuses production configuration.
    #[test]
    fn the_demo_in_production_is_refused() {
        let read = Config::read(&with(&[], &[]), &Command::Demo);

        assert!(matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "APP_ENV"));
    }

    /// The install command on the hosted service is refused.
    #[test]
    fn the_install_command_on_the_hosted_service_is_refused() {
        let installing = [
            ("INSTALL_ORGANIZATION_NAME", "Acme"),
            ("INSTALL_OWNER_EMAIL", "owner@acme.com"),
            ("INSTALL_OWNER_PASSWORD", "a long first password"),
        ];
        let read = Config::read(&with(&[], &installing), &Command::Install);

        assert!(matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "DEPLOYMENT"));
    }

    /// The operator command reads its password, in production too: every
    /// deployment needs its first operator.
    #[test]
    fn the_operator_command_reads_its_password() {
        let command = Command::CreateOperator {
            email: ianua_domain::types::Email::new("root@example.com").unwrap(),
        };
        let vars = with(&[], &[("OPERATOR_PASSWORD", "a long operator password")]);

        let config = Config::read(&vars, &command).unwrap();

        assert!(config.first_operator.is_some());
    }

    /// Creating an operator requires the database owner's login even in
    /// API mode.
    #[test]
    fn the_operator_command_without_the_owner_login_is_refused() {
        let command = Command::CreateOperator {
            email: ianua_domain::types::Email::new("root@example.com").unwrap(),
        };
        let vars = with(
            &["MIGRATION_DATABASE_URL"],
            &[
                ("OPERATOR_PASSWORD", "a long operator password"),
                ("MODE", "api"),
                ("BUS_URL", "nats://bus.internal:4222"),
                ("CACHE_URL", "redis://cache.internal:6379"),
            ],
        );

        let read = Config::read(&vars, &command);

        assert!(
            matches!(read, Err(ConfigError::Missing { name }) if name.starts_with("MIGRATION_DATABASE_URL"))
        );
    }

    /// A migration reads only the database and the logs, and needs the
    /// owner's and the purge's logins.
    #[test]
    fn a_migration_reads_the_database_alone() {
        let vars = Env::of([
            ("DATABASE_URL", "postgres://ianua_app:app-pw@db/ianua"),
            (
                "MIGRATION_DATABASE_URL",
                "postgres://postgres:owner-pw@db/ianua",
            ),
            (
                "AUDIT_PURGE_DATABASE_URL",
                "postgres://ianua_audit_purge:purge-pw@db/ianua",
            ),
        ]);
        let without_owner = Env::of([
            ("DATABASE_URL", "postgres://ianua_app:app-pw@db/ianua"),
            (
                "AUDIT_PURGE_DATABASE_URL",
                "postgres://ianua_audit_purge:purge-pw@db/ianua",
            ),
        ]);

        assert!(MigrationConfig::read(&vars).is_ok());
        assert!(MigrationConfig::read(&without_owner).is_err());
    }

    /// Configuration debug output omits database passwords and root and
    /// sealing keys.
    #[test]
    fn the_configuration_prints_no_secret() {
        let config = Config::read(&with(&[], &[]), &Command::Serve).unwrap();

        let shown = format!("{config:?}");
        for secret in ["app-pw", "owner-pw", "purge-pw", HEX_1, HEX_2, HEX_3] {
            assert!(!shown.contains(secret), "printed {secret}");
        }
    }
}

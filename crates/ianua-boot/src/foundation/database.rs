//! Where the database is and whom each process signs in to it as.
//!
//! Every process names the role it expects, [`DatabaseRole`], and reads
//! that role's login alone, with the pools it opens: the server signs in
//! as the app's role, the gateway and the nameservers each as their own.
//! A process signing in as the app's role also reads
//! [`AppDatabaseSettings`]. The control plane also holds
//! [`ControlPlaneLogins`]: the database owner's, for migrations and
//! tenants' schemas, the audit purge's own role, and the gateway's and the
//! nameservers', whose roles the migrations make where each is deployed.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use ianua_domain::shared::security::secret::Secret;
use ianua_infra::postgres::PoolLimits;
use percent_encoding::percent_decode_str;
use sqlx::postgres::PgConnectOptions;

use crate::env::{ConfigError, Env, Read};
use crate::environment::Environment;

/// One role's way into the database: how it connects, its name and its
/// password. `Debug` names the role and where it connects, never the
/// password.
#[derive(Clone)]
pub struct DatabaseLogin {
    /// How the role connects.
    pub options: PgConnectOptions,
    /// The role's name.
    pub role: String,
    /// The role's password.
    pub password: Secret,
}

impl fmt::Debug for DatabaseLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseLogin")
            .field("role", &self.role)
            .field("host", &self.options.get_host())
            .field("database", &self.options.get_database())
            .finish_non_exhaustive()
    }
}

impl DatabaseLogin {
    /// The login the `postgres://` URL in `name` holds, or `None` when it
    /// is unset. The URL holds a password, so it is read as a secret and
    /// no refusal repeats it.
    fn read(vars: &Env, name: &str) -> Read<Option<Self>> {
        let Some(url) = vars.secret(name)? else {
            return Ok(None);
        };
        Self::parse(name, &url).map(Some)
    }

    /// The login `url` holds, read for `name`.
    fn parse(name: &str, url: &Secret) -> Read<Self> {
        let refused = || ConfigError::invalid(name, "must be a postgres:// URL naming a role");
        let parsed = url::Url::parse(url.expose()).map_err(|_| refused())?;
        if !matches!(parsed.scheme(), "postgres" | "postgresql") || parsed.username().is_empty() {
            return Err(refused());
        }
        let role = decoded(parsed.username()).ok_or_else(refused)?;
        let password = parsed
            .password()
            .and_then(decoded)
            .map(Secret::new)
            .ok_or_else(|| ConfigError::invalid(name, "must hold the role's password"))?;
        let options = PgConnectOptions::from_str(url.expose()).map_err(|_| refused())?;
        Ok(Self {
            options,
            role,
            password,
        })
    }

    /// Refuses this login for `name` unless its role is one the platform
    /// makes and grants to: lowercase letters, digits and underscores.
    fn ensure_made_here(&self, name: &str) -> Read<()> {
        let made_here = self
            .role
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if !made_here {
            return Err(ConfigError::invalid(
                name,
                "must sign in as a role named in lowercase letters, digits and underscores",
            ));
        }
        Ok(())
    }
}

/// `part` of a URL with its percent escapes undone, or `None` when it is
/// not UTF-8 once undone.
fn decoded(part: &str) -> Option<String> {
    percent_decode_str(part)
        .decode_utf8()
        .ok()
        .map(Cow::into_owned)
}

/// The role a process signs in to the database as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseRole {
    /// The app's role, which owns nothing and cannot get past row-level
    /// security: the API's and the worker's.
    App,
    /// The gateway's role, which reads the configuration it serves and
    /// writes only its request records and its inbox.
    Gateway,
    /// The nameservers' role, which reads the zones tenants delegated to
    /// us and nothing more.
    Nameserver,
}

impl DatabaseRole {
    /// The setting this role's login is read from: `DATABASE_URL` for the
    /// app, `GATEWAY_DATABASE_URL` for the gateway and
    /// `NAMESERVER_DATABASE_URL` for the nameservers.
    #[must_use]
    pub fn setting(self) -> &'static str {
        match self {
            Self::App => "DATABASE_URL",
            Self::Gateway => "GATEWAY_DATABASE_URL",
            Self::Nameserver => "NAMESERVER_DATABASE_URL",
        }
    }
}

/// Where the database is and how one process reaches it, whichever role it
/// signs in as.
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// The login of the role the process named: `DATABASE_URL` for the
    /// app, `GATEWAY_DATABASE_URL` for the gateway,
    /// `NAMESERVER_DATABASE_URL` for the nameservers.
    pub login: DatabaseLogin,
    /// `DATABASE_MAX_CONNECTIONS` (10), `TENANT_DB_MAX_CONNECTIONS` (5) and
    /// `DATABASE_ACQUIRE_TIMEOUT_SECONDS` (5).
    pub pools: PoolLimits,
    /// `DATABASE_READY_POLL_SECONDS` (3): how often a starting process asks
    /// again whether the database is migrated.
    pub ready_poll: Duration,
}

impl DatabaseConfig {
    /// The database settings `vars` holds for a process signing in as
    /// `role`.
    ///
    /// # Errors
    ///
    /// The role's login missing, or any setting that does not read.
    pub fn read(vars: &Env, role: DatabaseRole) -> Read<Self> {
        let name = role.setting();
        let login = DatabaseLogin::read(vars, name)?
            .ok_or_else(|| ConfigError::missing(&format!("{name} or {name}_FILE")))?;
        login.ensure_made_here(name)?;
        Ok(Self {
            login,
            pools: PoolLimits {
                platform_connections: vars.number_in("DATABASE_MAX_CONNECTIONS", 10, 1..=1000)?,
                dedicated_connections: vars.number_in("TENANT_DB_MAX_CONNECTIONS", 5, 1..=1000)?,
                acquire_timeout: vars
                    .seconds("DATABASE_ACQUIRE_TIMEOUT_SECONDS", Duration::from_secs(5))?,
            },
            ready_poll: vars.seconds("DATABASE_READY_POLL_SECONDS", Duration::from_secs(3))?,
        })
    }
}

/// What only a process signing in as the app's role reads: whether its
/// role must be kept from the audit records, and how often it reads the
/// tenants' database routes again. The gateway writes no audit record and
/// reloads its configuration on a timer of its own, so it reads neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppDatabaseSettings {
    /// `AUDIT_REQUIRE_SEALED`: refuse to start unless the app's role can
    /// neither change nor remove an audit record; on in production.
    pub require_sealed: bool,
    /// `TENANT_DB_RELOAD_SECONDS` (300): how often each node reads every
    /// tenant's database route again, for a route change it never heard
    /// of.
    pub routes_reload: Duration,
}

impl AppDatabaseSettings {
    /// The app's database settings `vars` holds, in `environment`.
    ///
    /// # Errors
    ///
    /// A setting that does not read.
    pub fn read(vars: &Env, environment: Environment) -> Read<Self> {
        Ok(Self {
            require_sealed: vars.flag("AUDIT_REQUIRE_SEALED", environment.is_production())?,
            routes_reload: vars.seconds("TENANT_DB_RELOAD_SECONDS", Duration::from_secs(300))?,
        })
    }
}

/// The logins the control plane holds beside the app's: each read where it
/// is set, and none the same role as another.
#[derive(Debug, Clone)]
pub struct ControlPlaneLogins {
    /// `MIGRATION_DATABASE_URL`: the database owner, which migrates, makes
    /// the roles and makes tenants' schemas. Only the worker and the
    /// migrate, install and operator commands hold it.
    pub owner: Option<DatabaseLogin>,
    /// `AUDIT_PURGE_DATABASE_URL`: the audit retention purge's own role,
    /// the only one that may remove audit records. Only the worker and the
    /// migrate, install and operator commands hold it.
    pub audit_purge: Option<DatabaseLogin>,
    /// `AUDIT_PURGE_MAX_CONNECTIONS` (2): the purge's pool, small since
    /// only the retention sweep uses it.
    pub audit_purge_connections: u32,
    /// `GATEWAY_DATABASE_URL`: the gateway's role, made with its grants by
    /// the migrations where it is set, so a gateway can sign in as it. The
    /// control plane never connects as it.
    pub gateway: Option<DatabaseLogin>,
    /// `NAMESERVER_DATABASE_URL`: the nameservers' role, made with its
    /// grants by the migrations where it is set, so a nameserver can sign
    /// in as it. The control plane never connects as it.
    pub nameserver: Option<DatabaseLogin>,
}

impl ControlPlaneLogins {
    /// The control plane's other logins `vars` holds, checked against
    /// `app`, the app's own.
    ///
    /// # Errors
    ///
    /// A login that does not read, or two of the roles being one.
    pub fn read(vars: &Env, app: &DatabaseLogin) -> Read<Self> {
        let logins = Self {
            owner: DatabaseLogin::read(vars, "MIGRATION_DATABASE_URL")?,
            audit_purge: DatabaseLogin::read(vars, "AUDIT_PURGE_DATABASE_URL")?,
            audit_purge_connections: vars.number_in("AUDIT_PURGE_MAX_CONNECTIONS", 2, 1..=100)?,
            gateway: DatabaseLogin::read(vars, "GATEWAY_DATABASE_URL")?,
            nameserver: DatabaseLogin::read(vars, "NAMESERVER_DATABASE_URL")?,
        };
        logins.ensure_purge_apart(app)?;
        logins.ensure_owner_apart(app)?;
        logins.ensure_gateway_apart(app)?;
        logins.ensure_nameserver_apart(app)?;
        Ok(logins)
    }

    /// Refuses the audit purge as the app's role, which could then remove
    /// audit records.
    fn ensure_purge_apart(&self, app: &DatabaseLogin) -> Read<()> {
        let Some(purge) = &self.audit_purge else {
            return Ok(());
        };
        purge.ensure_made_here("AUDIT_PURGE_DATABASE_URL")?;
        if purge.role == app.role {
            return Err(ConfigError::contradicts(
                "AUDIT_PURGE_DATABASE_URL",
                "signs in as the app's own role; the purge must have a role of its own",
            ));
        }
        Ok(())
    }

    /// Refuses the owner as the app's or the purge's role: the app as the
    /// owner would get past row-level security.
    fn ensure_owner_apart(&self, app: &DatabaseLogin) -> Read<()> {
        let Some(owner) = &self.owner else {
            return Ok(());
        };
        let shared = owner.role == app.role || self.is_purge(&owner.role);
        if shared {
            return Err(ConfigError::contradicts(
                "MIGRATION_DATABASE_URL",
                "signs in as the app's or the audit purge's role; the owner must be another",
            ));
        }
        Ok(())
    }

    /// Refuses the gateway as any other role: the gateway faces the
    /// internet, and as another role it would hold that role's grants.
    fn ensure_gateway_apart(&self, app: &DatabaseLogin) -> Read<()> {
        let Some(gateway) = &self.gateway else {
            return Ok(());
        };
        gateway.ensure_made_here("GATEWAY_DATABASE_URL")?;
        let is_owner = self
            .owner
            .as_ref()
            .is_some_and(|owner| owner.role == gateway.role);
        if gateway.role == app.role || self.is_purge(&gateway.role) || is_owner {
            return Err(ConfigError::contradicts(
                "GATEWAY_DATABASE_URL",
                "signs in as the app's, the audit purge's or the owner's role; the gateway must have a role of its own",
            ));
        }
        Ok(())
    }

    /// Refuses the nameservers as any other role: they answer anyone over
    /// UDP, and as another role they would hold that role's grants.
    fn ensure_nameserver_apart(&self, app: &DatabaseLogin) -> Read<()> {
        let Some(nameserver) = &self.nameserver else {
            return Ok(());
        };
        nameserver.ensure_made_here("NAMESERVER_DATABASE_URL")?;
        let taken = [self.owner.as_ref(), self.gateway.as_ref(), Some(app)]
            .into_iter()
            .flatten()
            .any(|other| other.role == nameserver.role);
        if taken || self.is_purge(&nameserver.role) {
            return Err(ConfigError::contradicts(
                "NAMESERVER_DATABASE_URL",
                "signs in as the app's, the audit purge's, the owner's or the gateway's role; the nameservers must have a role of their own",
            ));
        }
        Ok(())
    }

    /// Whether `role` is the audit purge's.
    fn is_purge(&self, role: &str) -> bool {
        self.audit_purge
            .as_ref()
            .is_some_and(|purge| purge.role == role)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = "postgres://ianua_app:app%40pw@db.internal:5432/ianua";
    const PURGE: &str = "postgres://ianua_audit_purge:purge-pw@db.internal:5432/ianua";
    const OWNER: &str = "postgres://postgres:owner-pw@db.internal:5432/ianua";
    const GATEWAY: &str = "postgres://ianua_gateway:gateway-pw@db.internal:5432/ianua";
    const NAMESERVER: &str = "postgres://ianua_nameserver:ns-pw@db.internal:5432/ianua";

    /// The app's database settings and the control plane's other logins
    /// `vars` holds, in production.
    fn control_plane(vars: &Env) -> Read<(DatabaseConfig, ControlPlaneLogins)> {
        let config = DatabaseConfig::read(vars, DatabaseRole::App)?;
        let logins = ControlPlaneLogins::read(vars, &config.login)?;
        Ok((config, logins))
    }

    /// The app's login reads its role and its password, escapes undone.
    #[test]
    fn the_app_login_reads_its_role_and_password() {
        let (config, logins) = control_plane(&Env::of([("DATABASE_URL", APP)])).unwrap();

        assert_eq!(config.login.role, "ianua_app");
        assert_eq!(config.login.password.expose(), "app@pw");
        assert!(logins.owner.is_none());
    }

    /// The gateway signs in with its own login and reads no other, nor the
    /// app's own settings.
    #[test]
    fn the_gateway_signs_in_with_its_own_login() {
        let vars = Env::of([
            ("DATABASE_URL", APP),
            ("GATEWAY_DATABASE_URL", GATEWAY),
            ("AUDIT_REQUIRE_SEALED", "false"),
            ("TENANT_DB_RELOAD_SECONDS", "60"),
        ]);

        let config = DatabaseConfig::read(&vars, DatabaseRole::Gateway).unwrap();

        assert_eq!(config.login.role, "ianua_gateway");
        assert_eq!(vars.set_names(), ["GATEWAY_DATABASE_URL"]);
    }

    /// A process whose role's login is unset is refused, naming that
    /// role's setting.
    #[test]
    fn a_role_with_no_login_is_refused_by_its_setting() {
        let vars = Env::of([("DATABASE_URL", APP)]);

        let read = DatabaseConfig::read(&vars, DatabaseRole::Gateway);

        assert!(
            matches!(read, Err(ConfigError::Missing { name }) if name.starts_with("GATEWAY_DATABASE_URL"))
        );
    }

    /// Database configuration debug output omits the decoded password.
    #[test]
    fn a_login_never_prints_its_password() {
        let (config, _) = control_plane(&Env::of([("DATABASE_URL", APP)])).unwrap();

        assert!(!format!("{config:?}").contains("app@pw"));
    }

    /// An unsupported database URL is refused by setting name without its password.
    #[test]
    fn a_url_that_does_not_read_is_refused_without_repeating_it() {
        let read = control_plane(&Env::of([("DATABASE_URL", "mysql://u:hunter2@db/x")]));

        let message = read.unwrap_err().to_string();
        assert!(message.starts_with("DATABASE_URL"));
        assert!(!message.contains("hunter2"));
    }

    /// A URL with no password is refused: the roles are made with it.
    #[test]
    fn a_url_with_no_password_is_refused() {
        let read = control_plane(&Env::of([(
            "DATABASE_URL",
            "postgres://ianua_app@db/ianua",
        )]));

        assert!(matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "DATABASE_URL"));
    }

    /// An audit-purge login using the application's role is refused as
    /// contradictory, even with a different password.
    #[test]
    fn the_audit_purge_as_the_app_role_is_refused() {
        let vars = Env::of([
            ("DATABASE_URL", APP),
            (
                "AUDIT_PURGE_DATABASE_URL",
                "postgres://ianua_app:other@db.internal/ianua",
            ),
        ]);

        let read = control_plane(&vars);

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "AUDIT_PURGE_DATABASE_URL")
        );
    }

    /// A migration login cannot share the application's role; the error
    /// identifies the migration setting.
    #[test]
    fn the_owner_as_the_app_role_is_refused() {
        let vars = Env::of([
            ("DATABASE_URL", APP),
            (
                "MIGRATION_DATABASE_URL",
                "postgres://ianua_app:pw@db.internal/ianua",
            ),
        ]);

        let read = control_plane(&vars);

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "MIGRATION_DATABASE_URL")
        );
    }

    /// A gateway login using the application's role is refused by setting name.
    #[test]
    fn the_gateway_as_the_app_role_is_refused() {
        let vars = Env::of([
            ("DATABASE_URL", APP),
            (
                "GATEWAY_DATABASE_URL",
                "postgres://ianua_app:pw@db.internal/ianua",
            ),
        ]);

        let read = control_plane(&vars);

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "GATEWAY_DATABASE_URL")
        );
    }

    /// A gateway login sharing the database owner's role is refused.
    #[test]
    fn the_gateway_as_the_owner_is_refused() {
        let vars = Env::of([
            ("DATABASE_URL", APP),
            ("MIGRATION_DATABASE_URL", OWNER),
            (
                "GATEWAY_DATABASE_URL",
                "postgres://postgres:pw@db.internal/ianua",
            ),
        ]);

        let read = control_plane(&vars);

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "GATEWAY_DATABASE_URL")
        );
    }

    /// Distinct application, purge, owner, gateway and DNS logins retain their assigned roles.
    #[test]
    fn five_roles_of_their_own_are_taken() {
        let vars = Env::of([
            ("DATABASE_URL", APP),
            ("AUDIT_PURGE_DATABASE_URL", PURGE),
            ("MIGRATION_DATABASE_URL", OWNER),
            ("GATEWAY_DATABASE_URL", GATEWAY),
            ("NAMESERVER_DATABASE_URL", NAMESERVER),
        ]);

        let (_, logins) = control_plane(&vars).unwrap();

        assert_eq!(logins.audit_purge.unwrap().role, "ianua_audit_purge");
        assert_eq!(logins.owner.unwrap().role, "postgres");
        assert_eq!(logins.gateway.unwrap().role, "ianua_gateway");
        assert_eq!(logins.nameserver.unwrap().role, "ianua_nameserver");
    }

    /// The nameservers sign in with their own login and read no other.
    #[test]
    fn the_nameservers_sign_in_with_their_own_login() {
        let vars = Env::of([
            ("DATABASE_URL", APP),
            ("NAMESERVER_DATABASE_URL", NAMESERVER),
        ]);

        let config = DatabaseConfig::read(&vars, DatabaseRole::Nameserver).unwrap();

        assert_eq!(config.login.role, "ianua_nameserver");
        assert_eq!(vars.set_names(), ["NAMESERVER_DATABASE_URL"]);
    }

    /// Nameserver credentials cannot use the gateway's database role.
    #[test]
    fn the_nameservers_as_the_gateway_role_are_refused() {
        let vars = Env::of([
            ("DATABASE_URL", APP),
            ("GATEWAY_DATABASE_URL", GATEWAY),
            (
                "NAMESERVER_DATABASE_URL",
                "postgres://ianua_gateway:pw@db.internal/ianua",
            ),
        ]);

        let read = control_plane(&vars);

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "NAMESERVER_DATABASE_URL")
        );
    }

    /// Nameserver credentials cannot use the application's database role.
    #[test]
    fn the_nameservers_as_the_app_role_are_refused() {
        let vars = Env::of([
            ("DATABASE_URL", APP),
            (
                "NAMESERVER_DATABASE_URL",
                "postgres://ianua_app:pw@db.internal/ianua",
            ),
        ]);

        let read = control_plane(&vars);

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "NAMESERVER_DATABASE_URL")
        );
    }

    /// A role name the platform cannot make is refused before any grant.
    #[test]
    fn a_role_name_the_platform_cannot_make_is_refused() {
        let read = control_plane(&Env::of([(
            "DATABASE_URL",
            "postgres://Ianua-App:pw@db/ianua",
        )]));

        assert!(matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "DATABASE_URL"));
    }

    /// Production requires the app's role kept from the audit records, and
    /// reads the tenants' routes again every five minutes.
    #[test]
    fn production_requires_a_sealed_audit_log() {
        let settings = AppDatabaseSettings::read(&Env::of([]), Environment::Production).unwrap();

        assert!(settings.require_sealed);
        assert_eq!(settings.routes_reload, Duration::from_secs(300));
    }

    /// Development may run with an audit log the app could rewrite unless
    /// told otherwise.
    #[test]
    fn development_does_not_require_a_sealed_audit_log_by_default() {
        let settings = AppDatabaseSettings::read(&Env::of([]), Environment::Development).unwrap();

        assert!(!settings.require_sealed);
    }
}

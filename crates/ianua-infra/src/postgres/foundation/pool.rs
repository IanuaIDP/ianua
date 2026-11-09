//! Where a tenant's rows live: the platform database, or one of its own.
//!
//! A store knows its tenant and nothing else, so the registry of which
//! tenants have a database of their own is held here, loaded at start and
//! changed as tenants are moved. A tenant without an entry lives in the
//! platform database.
//!
//! A tenant whose own database is a schema on a shared instance has the
//! schema fixed in its connection string, never set with `SET search_path`:
//! a pooled connection keeps its search path after release, so the next
//! borrower would read the previous tenant's rows. Row-level security still
//! applies on a database of its own; neither guard is trusted alone.

use std::collections::HashMap;
use std::fmt;
use std::sync::{PoisonError, RwLock};
use std::time::Duration;

use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use crate::postgres::foundation::security::RowScope;

/// Which database a connection is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Database {
    /// The platform database, shared by every tenant without one of its own.
    Platform,
    /// The database of a tenant that has one of its own.
    Dedicated(TenantId),
}

/// Which role a set of pools signs in as.
///
/// The app's role reads and writes rows but never removes an audit record;
/// only the audit purge's role may, and it may do nothing else. The
/// gateway's role reads its configuration and writes only its request
/// records, its event inbox and the few marks its checks leave. The
/// nameservers' role reads the zones and nothing more. Each holds pools of
/// its own, and a unit of work keeps a transaction per role, so a purge
/// never runs on the app's connection, nor the app's work on the purge's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Login {
    /// The role the app connects as.
    App,
    /// The role the audit retention purge connects as.
    AuditPurge,
    /// The role the gateway connects as.
    Gateway,
    /// The role the nameservers connect as.
    Nameserver,
}

/// How the pools are sized and how long a caller waits for a connection.
#[derive(Debug, Clone, Copy)]
pub struct PoolLimits {
    /// Connections the platform pool holds at most.
    pub platform_connections: u32,
    /// Connections a tenant's own pool holds at most.
    pub dedicated_connections: u32,
    /// How long a caller waits for a free connection before it is refused.
    pub acquire_timeout: Duration,
}

/// A tenant's own database: its connection options, with any schema fixed
/// in them. The options hold the role's password, so its `Debug` names
/// where the database is and never how to sign in to it.
#[derive(Clone)]
pub struct DedicatedDatabase {
    options: PgConnectOptions,
}

impl fmt::Debug for DedicatedDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DedicatedDatabase")
            .field("host", &self.options.get_host())
            .field("port", &self.options.get_port())
            .field("database", &self.options.get_database())
            .field("options", &self.options.get_options())
            .finish_non_exhaustive()
    }
}

impl DedicatedDatabase {
    /// A tenant's own database reached with `options`, and pinned to
    /// `schema` when it shares an instance with others. The schema comes
    /// first on the search path and `public` after it, for the extensions
    /// installed there, such as `pg_trgm`, whose operators the tenant's
    /// indexes use; every table of the tenant is in its schema, so a name
    /// never falls through to the platform's.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when `schema` holds anything
    /// but ASCII letters, digits and underscores. The platform makes these
    /// names itself, so one outside that set did not come from it, and is
    /// refused rather than escaped.
    pub fn new(options: PgConnectOptions, schema: Option<&str>) -> Result<Self, DomainError> {
        let Some(schema) = schema else {
            return Ok(Self { options });
        };
        let safe = !schema.is_empty()
            && schema
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !safe {
            return Err(DomainError::infra_msg(
                "a tenant schema name is not one the platform makes",
            ));
        }
        let path = format!("{schema},public");
        let pinned = options.options([("search_path", path.as_str())]);
        Ok(Self { options: pinned })
    }

    /// How the database is reached.
    pub(crate) fn options(&self) -> PgConnectOptions {
        self.options.clone()
    }
}

/// The platform database and every tenant database of its own, reached as
/// one role.
pub struct Databases {
    platform: PgPool,
    platform_options: PgConnectOptions,
    dedicated: RwLock<HashMap<TenantId, PgPool>>,
    limits: PoolLimits,
    login: Login,
}

impl Databases {
    /// The platform database reached with `options`, the app's role's. Its
    /// pool opens connections as they are first needed.
    #[must_use]
    pub fn new(options: PgConnectOptions, limits: PoolLimits) -> Self {
        Self::signed_in(options, limits, Login::App)
    }

    /// The platform database reached with `options`, the audit purge's
    /// role's, for the retention purge and the moves of a tenant's trail
    /// that remove what a purge removed. Its routes start knowing of no
    /// tenant's own database; the purge reads them from the registry
    /// before it runs.
    #[must_use]
    pub fn audit_purge(options: PgConnectOptions, limits: PoolLimits) -> Self {
        Self::signed_in(options, limits, Login::AuditPurge)
    }

    /// The platform database reached with `options`, the gateway's role's,
    /// which reads the gateway's configuration and writes only what the
    /// gateway records. Its routes start knowing of no tenant's own
    /// database, as the app's do.
    #[must_use]
    pub fn gateway(options: PgConnectOptions, limits: PoolLimits) -> Self {
        Self::signed_in(options, limits, Login::Gateway)
    }

    /// The platform database reached with `options`, the nameservers'
    /// role's, which reads the zones tenants delegated to us and nothing
    /// more. The zones live in the platform database alone, so its routes
    /// never learn of a tenant's own.
    #[must_use]
    pub fn nameserver(options: PgConnectOptions, limits: PoolLimits) -> Self {
        Self::signed_in(options, limits, Login::Nameserver)
    }

    /// The platform database reached with `options`, signed in as `login`.
    fn signed_in(options: PgConnectOptions, limits: PoolLimits, login: Login) -> Self {
        Self {
            platform: pool(options.clone(), limits.platform_connections, limits),
            platform_options: options,
            dedicated: RwLock::new(HashMap::new()),
            limits,
            login,
        }
    }

    /// The role these pools sign in as.
    pub(crate) fn login(&self) -> Login {
        self.login
    }

    /// A schema of the platform's database, as a tenant's own database
    /// reached the way the platform's is.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when `schema` is not a name
    /// the platform makes.
    pub(crate) fn schema_of_platform(
        &self,
        schema: &str,
    ) -> Result<DedicatedDatabase, DomainError> {
        DedicatedDatabase::new(self.platform_options.clone(), Some(schema))
    }

    /// Whether this node routes `tenant` to a database of its own.
    pub(crate) fn lives_apart(&self, tenant: &TenantId) -> bool {
        self.dedicated
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(tenant)
    }

    /// Records that `tenant` lives in `database` from now on.
    pub fn register(&self, tenant: TenantId, database: DedicatedDatabase) {
        let pool = pool(
            database.options,
            self.limits.dedicated_connections,
            self.limits,
        );
        self.dedicated
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(tenant, pool);
    }

    /// Records that `tenant` lives in the platform database again.
    pub fn deregister(&self, tenant: &TenantId) {
        self.dedicated
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(tenant);
    }

    /// The tenants living in a database of their own, for platform work
    /// that reads every tenant's rows: the platform database's rows are read
    /// at once, and these tenants' each from their own.
    pub(crate) fn with_own_database(&self) -> Vec<TenantId> {
        self.dedicated
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .copied()
            .collect()
    }

    /// The database `scope`'s rows live in, and the pool that reaches it.
    pub(crate) fn for_scope(&self, scope: RowScope) -> (Database, PgPool) {
        let RowScope::Tenant(tenant) = scope else {
            return (Database::Platform, self.platform.clone());
        };
        let dedicated = self
            .dedicated
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        dedicated.get(&tenant).map_or_else(
            || (Database::Platform, self.platform.clone()),
            |pool| (Database::Dedicated(tenant), pool.clone()),
        )
    }

    /// The platform pool, for the foundation's own work such as migrations.
    pub(crate) fn platform(&self) -> &PgPool {
        &self.platform
    }
}

/// A pool of at most `connections`, opening them as they are first needed.
fn pool(options: PgConnectOptions, connections: u32, limits: PoolLimits) -> PgPool {
    PgPoolOptions::new()
        .max_connections(connections)
        .acquire_timeout(limits.acquire_timeout)
        .connect_lazy_with(options)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Debug output includes the dedicated database's host but omits its
    /// connection password.
    #[test]
    fn a_dedicated_database_never_prints_its_password() {
        let options = PgConnectOptions::new()
            .host("db.internal")
            .password("hunter2-not-for-logs");
        let database = DedicatedDatabase::new(options, Some("tenant_0123")).unwrap();

        let printed = format!("{database:?}");

        assert!(!printed.contains("hunter2-not-for-logs"));
        assert!(printed.contains("db.internal"));
    }
}

//! Bringing the schema up to date as the database's owner: the platform's
//! tables, the roles the app, the audit purge, the gateway and the
//! nameservers sign in as, and every tenant's own schema.
//!
//! The migrate command runs it and exits; the worker runs it as it starts,
//! the migrations' lock letting one process at a time do the work. Every
//! step can run again: an applied migration is skipped, a role that exists
//! is kept and given its grants again. The gateway's role is made only
//! where its login, `GATEWAY_DATABASE_URL`, is set, and the nameservers'
//! only where `NAMESERVER_DATABASE_URL` is.

use std::time::Duration;

use ianua_boot::foundation::{ControlPlaneLogins, DatabaseConfig, DatabaseLogin};
use ianua_infra::postgres::tenant::{TenantSchemaAccess, migrate_tenant_schemas};
use ianua_infra::postgres::{
    Databases, LoginRole, PlatformRoles, PoolLimits, ensure_roles, migrate_platform,
};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use crate::error::PlatformError;

/// How long the owner's connection waits to be opened.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The owner's few connections: a migration takes one at a time.
const OWNER_LIMITS: PoolLimits = PoolLimits {
    platform_connections: 2,
    dedicated_connections: 1,
    acquire_timeout: CONNECT_TIMEOUT,
};

/// The logins of the roles the migrations make and grant to.
pub(crate) struct MadeRoles<'a> {
    /// The app's.
    pub app: &'a DatabaseLogin,
    /// The audit purge's.
    pub audit_purge: &'a DatabaseLogin,
    /// The gateway's, where one is deployed.
    pub gateway: Option<&'a DatabaseLogin>,
    /// The nameservers', where they read the database.
    pub nameserver: Option<&'a DatabaseLogin>,
}

/// Brings the platform's tables up to date, makes the app's, the audit
/// purge's and, where their logins are set, the gateway's and the
/// nameservers' roles with their grants, and brings every tenant's own
/// schema up to date, all as the owner `logins` holds.
///
/// # Errors
///
/// [`PlatformError`] naming the step that failed, or the owner's or the
/// audit purge's login missing.
pub async fn migrate(
    database: &DatabaseConfig,
    logins: &ControlPlaneLogins,
) -> Result<(), PlatformError> {
    let owner = owner_of(logins)?;
    let made = made_roles(database, logins)?;
    let databases = Databases::new(owner.options.clone(), OWNER_LIMITS);
    migrate_platform(&databases)
        .await
        .map_err(PlatformError::of("the platform's tables"))?;
    roles(owner, &made).await?;
    let migrated = migrate_tenant_schemas(&databases, &schema_access(owner, &made))
        .await
        .map_err(PlatformError::of("the tenants' own schemas"))?;
    tracing::info!(tenant_schemas = migrated, "the schema is up to date");
    Ok(())
}

/// How tenants' schemas are made: by the owner, opened to the roles
/// `made` names.
#[must_use]
pub(crate) fn schema_access(owner: &DatabaseLogin, made: &MadeRoles<'_>) -> TenantSchemaAccess {
    TenantSchemaAccess {
        owner: owner.options.clone(),
        app_role: made.app.role.clone(),
        audit_purge_role: made.audit_purge.role.clone(),
        gateway_role: made.gateway.map(|gateway| gateway.role.clone()),
    }
}

/// The roles the migrations make: the app's that `database` signs in as,
/// and the audit purge's, the gateway's and the nameservers' `logins`
/// holds.
///
/// # Errors
///
/// [`PlatformError`] when the audit purge's login is missing, which a
/// checked configuration never leaves out where this runs.
pub(crate) fn made_roles<'a>(
    database: &'a DatabaseConfig,
    logins: &'a ControlPlaneLogins,
) -> Result<MadeRoles<'a>, PlatformError> {
    let audit_purge = logins
        .audit_purge
        .as_ref()
        .ok_or_else(|| missing("the audit purge's login, AUDIT_PURGE_DATABASE_URL"))?;
    Ok(MadeRoles {
        app: &database.login,
        audit_purge,
        gateway: logins.gateway.as_ref(),
        nameserver: logins.nameserver.as_ref(),
    })
}

/// The owner's login, which the configuration requires wherever this runs.
fn owner_of(logins: &ControlPlaneLogins) -> Result<&DatabaseLogin, PlatformError> {
    logins
        .owner
        .as_ref()
        .ok_or_else(|| missing("the owner's login, MIGRATION_DATABASE_URL"))
}

/// A part missing, which a checked configuration never leaves out.
fn missing(part: &'static str) -> PlatformError {
    PlatformError::Part {
        part,
        cause: "it is not set".into(),
    }
}

/// Makes the roles `made` names, with their grants, on a connection of the
/// owner's opened for it and closed after.
async fn roles(owner: &DatabaseLogin, made: &MadeRoles<'_>) -> Result<(), PlatformError> {
    let pool = owner_pool(owner).await?;
    let ensured = ensure_roles(
        &pool,
        &PlatformRoles {
            app: login_role(made.app),
            audit_purge: login_role(made.audit_purge),
            gateway: made.gateway.map(login_role),
            nameserver: made.nameserver.map(login_role),
        },
    )
    .await;
    pool.close().await;
    ensured.map_err(PlatformError::of(
        "the app's, the audit purge's, the gateway's and the nameservers' roles",
    ))
}

/// The role `login` signs in as, with its password.
fn login_role(login: &DatabaseLogin) -> LoginRole<'_> {
    LoginRole {
        name: &login.role,
        password: login.password.expose(),
    }
}

/// One connection of the owner's.
async fn owner_pool(owner: &DatabaseLogin) -> Result<PgPool, PlatformError> {
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(CONNECT_TIMEOUT)
        .connect_with(owner.options.clone())
        .await
        .map_err(PlatformError::of("the owner's connection"))
}

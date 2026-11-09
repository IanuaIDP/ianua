//! The databases: the app's, routed to every tenant's own, the audit
//! purge's where its login is held, and the schema brought up to date or
//! waited for, with the gateway's role made where its login is held.
//!
//! A process holding the owner's login (a worker, the install and the
//! operator command) migrates as it starts; the configuration keeps that login off every
//! API node, which waits until the schema is current instead.

use std::sync::Arc;

use ianua_boot::foundation::{AppDatabaseSettings, ControlPlaneLogins, DatabaseConfig};
use ianua_boot::shutdown::Shutdown;
use ianua_infra::postgres::tenant::{TenantSchemaAccess, load_tenant_databases};
use ianua_infra::postgres::{Databases, PoolLimits, audit_sealed_from, schema_is_current};

use crate::error::PlatformError;
use crate::migrate::{made_roles, migrate, schema_access};

/// The databases as the platform reaches them.
pub(super) struct DatabaseParts {
    /// The app's role's, routed to every tenant living apart.
    pub(super) app: Arc<Databases>,
    /// The audit purge's role's, where its login is held.
    pub(super) audit_purge: Option<Arc<Databases>>,
    /// How tenants' schemas are made, as the owner, where the owner's
    /// login is held.
    pub(super) schema_access: Option<TenantSchemaAccess>,
}

/// The databases, the schema brought up to date or waited for, its audit
/// log checked to be sealed, and every tenant's route loaded.
///
/// # Errors
///
/// [`PlatformError`] when a migration fails, the audit log is not sealed
/// and must be, the routes cannot be read, or a stop comes first.
pub(super) async fn databases(
    database: &DatabaseConfig,
    settings: &AppDatabaseSettings,
    logins: &ControlPlaneLogins,
    shutdown: &Shutdown,
) -> Result<DatabaseParts, PlatformError> {
    let app = Arc::new(Databases::new(
        database.login.options.clone(),
        database.pools,
    ));
    if logins.owner.is_some() {
        migrate(database, logins).await?;
    } else {
        wait_until_current(&app, database, shutdown).await?;
    }
    ensure_sealed(&app, settings.require_sealed).await?;
    load_tenant_databases(&app)
        .await
        .map_err(PlatformError::of("the tenants' routes"))?;
    Ok(DatabaseParts {
        audit_purge: audit_purge(database, logins),
        schema_access: access(database, logins),
        app,
    })
}

/// Waits until the schema holds every migration of this build, asking
/// each `ready_poll`, for a node that leaves migrating to others.
async fn wait_until_current(
    app: &Databases,
    database: &DatabaseConfig,
    shutdown: &Shutdown,
) -> Result<(), PlatformError> {
    loop {
        match schema_is_current(app).await {
            Ok(true) => return Ok(()),
            Ok(false) => tracing::info!("waiting for the migrations to run"),
            Err(error) => tracing::info!(%error, "waiting for the database"),
        }
        tokio::select! {
            () = shutdown.stopping() => return Err(PlatformError::Stopped),
            () = tokio::time::sleep(database.ready_poll) => {}
        }
    }
}

/// Refuses an audit log the app's role could rewrite when `required`, and
/// says so loudly when not.
async fn ensure_sealed(app: &Databases, required: bool) -> Result<(), PlatformError> {
    let sealed = audit_sealed_from(app)
        .await
        .map_err(PlatformError::of("the audit log's seal check"))?;
    match (sealed, required) {
        (true, _) => Ok(()),
        (false, true) => Err(PlatformError::Unsealed),
        (false, false) => {
            tracing::warn!(
                "the app's role can change or remove audit records; never run so in production"
            );
            Ok(())
        }
    }
}

/// The audit purge's databases: a small pool, with no routes loaded, since
/// the purge reads the registry each time it runs.
fn audit_purge(database: &DatabaseConfig, logins: &ControlPlaneLogins) -> Option<Arc<Databases>> {
    let login = logins.audit_purge.as_ref()?;
    let limits = PoolLimits {
        platform_connections: logins.audit_purge_connections,
        dedicated_connections: 1,
        acquire_timeout: database.pools.acquire_timeout,
    };
    Some(Arc::new(Databases::audit_purge(
        login.options.clone(),
        limits,
    )))
}

/// How tenants' schemas are made, when the owner's and the purge's logins
/// are held: opened to the gateway's role too where its login is set.
fn access(database: &DatabaseConfig, logins: &ControlPlaneLogins) -> Option<TenantSchemaAccess> {
    let owner = logins.owner.as_ref()?;
    let made = made_roles(database, logins).ok()?;
    Some(schema_access(owner, &made))
}

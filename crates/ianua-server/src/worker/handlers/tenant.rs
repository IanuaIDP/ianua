//! The handlers of tenants' setups, teardowns and clones.
//!
//! A tenant's own database is made and removed as the owner, and its audit
//! trail moved as the audit purge's role, so both handlers that touch them
//! take the purge's databases and the owner's schema access, which a worker
//! always holds.

use std::sync::Arc;

use ianua_app::ports::tenant::{TenantDatabaseProvisioner, TenantSetupStore, TenantTeardownStore};
use ianua_app::use_cases::scheduling::JobHandler;
use ianua_app::use_cases::tenant::clones::{RunCloneHandler, RunPorts, RunUseCase};
use ianua_app::use_cases::tenant::setup::{self, SETUP_STEP_JOB, SetupStepHandler, SetupSteps};
use ianua_app::use_cases::tenant::teardown::{
    self, TEARDOWN_STEP_JOB, TeardownStepHandler, TeardownSteps,
};
use ianua_infra::bus::BusSetupProgressObserver;
use ianua_infra::crypto::Pkcs8KeyGenerator;
use ianua_infra::files::FileTenantFilePurger;
use ianua_infra::postgres::Databases;
use ianua_infra::postgres::audit::PgAuditTrailMover;
use ianua_infra::postgres::authorization::PgRoleStore;
use ianua_infra::postgres::crypto::PgAssertionKeyStore;
use ianua_infra::postgres::tenant::{
    PgClonePartCopier, PgTenantCloneStore, PgTenantDataPurger, PgTenantDatabaseProvisioner,
    PgTenantSetupStore, PgTenantTeardownStore,
};

use crate::error::{PlatformError, ServerError};
use crate::worker::parts::Parts;

/// The handlers of tenants' setups, teardowns and clones.
///
/// # Errors
///
/// [`ServerError`] when one cannot be built, or the worker holds no audit
/// purge login or schema access.
pub(super) fn handlers(parts: &Parts<'_>) -> Result<Vec<Arc<dyn JobHandler>>, ServerError> {
    Ok(vec![
        setup_steps(parts)?,
        teardown_steps(parts)?,
        clone_runs(parts)?,
    ])
}

/// Why a tenant handler cannot be built.
#[derive(Debug, thiserror::Error)]
enum TenantPartsError {
    /// The worker holds no audit purge login.
    #[error("the worker holds no AUDIT_PURGE_DATABASE_URL login")]
    NoAuditPurge,
    /// The worker cannot make tenants' schemas as the owner.
    #[error("the worker holds no MIGRATION_DATABASE_URL login to make tenants' schemas with")]
    NoSchemaAccess,
}

/// The audit purge's databases.
fn audit_purge(parts: &Parts<'_>) -> Result<Arc<Databases>, ServerError> {
    let databases = parts
        .platform
        .audit_purge
        .as_ref()
        .ok_or(TenantPartsError::NoAuditPurge)
        .map_err(PlatformError::of("the audit purge's databases"))?;
    Ok(Arc::clone(databases))
}

/// The provisioner making and removing tenants' own databases.
fn provisioner(parts: &Parts<'_>) -> Result<Arc<dyn TenantDatabaseProvisioner>, ServerError> {
    let platform = parts.platform;
    let access = platform
        .schema_access
        .clone()
        .ok_or(TenantPartsError::NoSchemaAccess)
        .map_err(PlatformError::of("the tenant database provisioner"))?;
    Ok(Arc::new(PgTenantDatabaseProvisioner::new(
        Arc::clone(&platform.databases),
        audit_purge(parts)?,
        access,
        Arc::clone(&platform.bus),
    )))
}

/// The handler running each step of a new tenant's setup.
fn setup_steps(parts: &Parts<'_>) -> Result<Arc<dyn JobHandler>, ServerError> {
    let platform = parts.platform;
    let databases = &platform.databases;
    let setups: Arc<dyn TenantSetupStore> =
        Arc::new(PgTenantSetupStore::new(Arc::clone(databases)));
    let progress = Arc::new(BusSetupProgressObserver::new(
        Arc::clone(&platform.bus),
        platform.keys.broadcast_seal.clone(),
    ));
    let run = setup_run(parts, &setups, progress.clone())?;
    let fail = setup::FailStepUseCase::new(setup::FailStepPorts {
        setups,
        tenants: Arc::clone(&parts.tenants),
        progress,
        unit: Arc::clone(&platform.unit_of_work),
    });
    let handler = SetupStepHandler::new(
        SETUP_STEP_JOB,
        Arc::new(run),
        Arc::new(fail),
        Arc::clone(&parts.jobs),
    )
    .map_err(PlatformError::of("the setup step handler"))?;
    Ok(Arc::new(handler))
}

/// Builds tenant setup work with its database provisioner, starting keys and progress stream.
fn setup_run(
    parts: &Parts<'_>,
    setups: &Arc<dyn TenantSetupStore>,
    progress: Arc<BusSetupProgressObserver>,
) -> Result<setup::RunStepUseCase, ServerError> {
    let platform = parts.platform;
    let databases = &platform.databases;
    Ok(setup::RunStepUseCase::new(setup::RunStepPorts {
        setups: Arc::clone(setups),
        tenants: Arc::clone(&parts.tenants),
        databases: provisioner(parts)?,
        keys: parts.signing_keys(),
        assertion_keys: Arc::new(PgAssertionKeyStore::new(
            Arc::clone(databases),
            platform.secrets.encryptor.clone(),
        )),
        key_generator: Arc::new(Pkcs8KeyGenerator),
        roles: Arc::new(PgRoleStore::new(Arc::clone(databases))),
        progress,
        unit: Arc::clone(&platform.unit_of_work),
        steps: SetupSteps::new(SETUP_STEP_JOB, Arc::clone(&parts.jobs), parts.attempts),
    }))
}

/// The handler running each step of a deleted tenant's teardown.
fn teardown_steps(parts: &Parts<'_>) -> Result<Arc<dyn JobHandler>, ServerError> {
    let platform = parts.platform;
    let databases = &platform.databases;
    let teardowns: Arc<dyn TenantTeardownStore> =
        Arc::new(PgTenantTeardownStore::new(Arc::clone(databases)));
    let run = teardown::RunStepUseCase::new(teardown::RunStepPorts {
        teardowns: Arc::clone(&teardowns),
        tenants: Arc::clone(&parts.tenants),
        purger: Arc::new(PgTenantDataPurger::new(Arc::clone(databases))),
        files: Arc::new(FileTenantFilePurger::new(Arc::clone(&platform.files))),
        memories: Arc::clone(&platform.memory.purger),
        trails: Arc::new(PgAuditTrailMover::new(
            Arc::clone(databases),
            audit_purge(parts)?,
        )),
        databases: provisioner(parts)?,
        unit: Arc::clone(&platform.unit_of_work),
        steps: TeardownSteps::new(TEARDOWN_STEP_JOB, Arc::clone(&parts.jobs), parts.attempts),
    });
    let fail = teardown::FailStepUseCase::new(teardown::FailStepPorts {
        teardowns,
        unit: Arc::clone(&platform.unit_of_work),
    });
    let handler = TeardownStepHandler::new(
        TEARDOWN_STEP_JOB,
        Arc::new(run),
        Arc::new(fail),
        Arc::clone(&parts.jobs),
    )
    .map_err(PlatformError::of("the teardown step handler"))?;
    Ok(Arc::new(handler))
}

/// The handler copying one tenant's setup into another, part by part.
fn clone_runs(parts: &Parts<'_>) -> Result<Arc<dyn JobHandler>, ServerError> {
    let platform = parts.platform;
    let databases = &platform.databases;
    let run = RunUseCase::new(RunPorts {
        tenant_store: Arc::clone(&parts.tenants),
        clone_store: Arc::new(PgTenantCloneStore::new(Arc::clone(databases))),
        copier: Arc::new(PgClonePartCopier::new(
            databases,
            platform.digests.client_secrets.clone(),
        )),
        unit: Arc::clone(&platform.unit_of_work),
    });
    let handler =
        RunCloneHandler::new(Arc::new(run)).map_err(PlatformError::of("the clone handler"))?;
    Ok(Arc::new(handler))
}

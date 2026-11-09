//! What running and failing a step both read: the setup with its tenant,
//! and the progress a step's end makes of it.

use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::domains::tenant::setup::{SetupStep, TenantSetup};
use ianua_domain::message;
use ianua_domain::types::{OrganizationId, TenantId};

use crate::error::{AppError, OrInternal, OrNotFound as _};
use crate::ports::provisioning::{SetupProgress, StepOutcome};
use crate::ports::tenant::{TenantSetupStore, TenantStore};

/// The setup of `tenant_id` and the tenant, both of which must exist.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant or its setup is gone.
/// - `AppError::Internal` when either cannot be read.
pub(super) async fn setup_and_tenant(
    setups: &dyn TenantSetupStore,
    tenants: &dyn TenantStore,
    tenant_id: &TenantId,
) -> Result<(TenantSetup, Tenant), AppError> {
    let setup = setups
        .find(tenant_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "tenant-tenant-setup-not-found",
            "tenant setup not found"
        ))?;
    let tenant = tenants
        .find_by_id(tenant_id)
        .await
        .or_internal()?
        .or_not_found(message!("app-tenant-not-found", "tenant not found"))?;
    Ok((setup, tenant))
}

/// The progress `step` ending as `outcome` makes of `setup`, for the
/// organization `organization_id` that watches it.
pub(super) fn progress_of(
    setup: &TenantSetup,
    organization_id: OrganizationId,
    step: SetupStep,
    outcome: StepOutcome,
) -> SetupProgress {
    let count = |steps: usize| u32::try_from(steps).unwrap_or(u32::MAX);
    SetupProgress {
        tenant_id: *setup.tenant_id(),
        organization_id,
        step,
        step_outcome: outcome,
        done_steps: count(setup.done().len()),
        total_steps: count(setup.planned().len()),
        setup: setup.outcome(),
        failure_reason: setup.failure().map(|(_, why)| why.clone()),
    }
}

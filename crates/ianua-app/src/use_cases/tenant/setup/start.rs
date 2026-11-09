//! Starting a new tenant's setup, or picking it up again: the setup kept,
//! or a new one begun and saved, and a job queued for each step ready to
//! run. The planner does it when the tenant is announced, and the reconcile
//! sweep for a setup that never began or stalled, without announcing the
//! tenant again.

use ianua_domain::domains::tenant::setup::TenantSetup;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use crate::error::{AppError, OrInternal};
use crate::ports::tenant::{TenantSetupStore, TenantStore};
use crate::use_cases::scheduling::PlanReport;
use crate::use_cases::tenant::setup::job::SetupSteps;

/// What a setup is started or picked up again with.
pub(crate) struct SetupStart<'a> {
    /// Loads or creates durable provisioning progress for a restart.
    pub(crate) setups: &'a dyn TenantSetupStore,
    /// The tenants, for the one set up.
    pub(crate) tenants: &'a dyn TenantStore,
    /// Where the steps are queued.
    pub(crate) steps: &'a SetupSteps,
}

impl SetupStart<'_> {
    /// Queues the ready steps of `tenant_id`'s setup, beginning it if it has
    /// none. Nothing for a tenant gone or no longer provisioning, or a setup
    /// done or failed; a step queued already is not queued twice.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when a store cannot be read or written or a job
    /// cannot be queued.
    pub(crate) async fn queued(&self, tenant_id: TenantId) -> Result<PlanReport, AppError> {
        let Some(setup) = self.setup_of(&tenant_id).await? else {
            return Ok(PlanReport::default());
        };
        self.steps.queue_each(tenant_id, setup.ready()).await
    }

    /// The tenant's setup: the one kept, or a new one begun and saved.
    /// `None` when the tenant is gone or no longer provisioning. A start
    /// that began one at the same moment as another, the planner's and the
    /// reconcile sweep's, reads back the one kept.
    async fn setup_of(&self, tenant_id: &TenantId) -> Result<Option<TenantSetup>, AppError> {
        if let Some(kept) = self.setups.find(tenant_id).await.or_internal()? {
            return Ok(Some(kept));
        }
        let Some(tenant) = self.tenants.find_by_id(tenant_id).await.or_internal()? else {
            return Ok(None);
        };
        let Ok(begun) = TenantSetup::begin(&tenant) else {
            return Ok(None);
        };
        match self.setups.save(&begun).await {
            Ok(()) => Ok(Some(begun)),
            Err(DomainError::Conflict(_)) => self.setups.find(tenant_id).await.or_internal(),
            Err(failed) => Err(AppError::internal(failed)),
        }
    }
}

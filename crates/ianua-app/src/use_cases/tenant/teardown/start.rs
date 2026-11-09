//! Starting a deleted tenant's teardown, or picking it up again: the
//! teardown kept, or a new one begun and saved, and a job queued for each
//! step ready to run. The planner does it when the deletion is announced,
//! and the reconcile sweep for a teardown that never began or stalled.

use ianua_domain::domains::tenant::teardown::TenantTeardown;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use crate::error::{AppError, OrInternal};
use crate::ports::tenant::{TenantStore, TenantTeardownStore};
use crate::use_cases::scheduling::PlanReport;
use crate::use_cases::tenant::teardown::job::TeardownSteps;

/// What a teardown is started or picked up again with.
pub(crate) struct TeardownStart<'a> {
    /// Loads or creates durable removal progress for a restart.
    pub(crate) teardowns: &'a dyn TenantTeardownStore,
    /// The tenants, for the one torn down.
    pub(crate) tenants: &'a dyn TenantStore,
    /// Where the steps are queued.
    pub(crate) steps: &'a TeardownSteps,
}

impl TeardownStart<'_> {
    /// Queues the ready steps of `tenant_id`'s teardown, beginning it if it
    /// has none. Nothing for a tenant gone or not deleted, or a teardown
    /// done or failed; a step queued already is not queued twice.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when a store cannot be read or written or a job
    /// cannot be queued.
    pub(crate) async fn queued(&self, tenant_id: TenantId) -> Result<PlanReport, AppError> {
        let Some(teardown) = self.teardown_of(&tenant_id).await? else {
            return Ok(PlanReport::default());
        };
        self.steps.queue_each(tenant_id, teardown.ready()).await
    }

    /// The tenant's teardown: the one kept, or a new one begun and saved.
    /// `None` when the tenant is gone or not deleted. A start that began
    /// one at the same moment as another, the planner's and the reconcile
    /// sweep's, reads back the one kept.
    async fn teardown_of(&self, tenant_id: &TenantId) -> Result<Option<TenantTeardown>, AppError> {
        if let Some(kept) = self.teardowns.find(tenant_id).await.or_internal()? {
            return Ok(Some(kept));
        }
        let Some(tenant) = self.tenants.find_by_id(tenant_id).await.or_internal()? else {
            return Ok(None);
        };
        let Ok(begun) = TenantTeardown::begin(&tenant) else {
            return Ok(None);
        };
        match self.teardowns.save(&begun).await {
            Ok(()) => Ok(Some(begun)),
            Err(DomainError::Conflict(_)) => self.teardowns.find(tenant_id).await.or_internal(),
            Err(failed) => Err(AppError::internal(failed)),
        }
    }
}

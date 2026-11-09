//! Changing a stored pipeline, and the status a caller sees when the pipeline
//! refuses the change.

use ianua_domain::domains::proxy::pipeline::{Pipeline, PipelineError};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::PipelineId;

use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::proxy::PipelineStore;
use crate::use_cases::proxy::lookup::existing_pipeline;

/// A person changing one of their tenant's pipelines, and where the change
/// is recorded.
pub(super) struct PipelineChange<'a> {
    caller: &'a CallerContext,
    auditor: &'a RequestAuditor,
}

impl<'a> PipelineChange<'a> {
    /// A change by the person `caller` names, recorded through `auditor`.
    pub(super) fn by(caller: &'a CallerContext, auditor: &'a RequestAuditor) -> Self {
        Self { caller, auditor }
    }

    /// Loads the tenant's pipeline, applies `change` to it, saves the
    /// result and records what the pipeline raised. Nothing is saved or
    /// recorded when `change` refuses.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the tenant has no such pipeline.
    /// - What [`pipeline_error`] makes of the refusal.
    /// - `AppError::Internal` on storage or audit failure.
    pub(super) async fn pipeline<F>(
        &self,
        store: &dyn PipelineStore,
        pipeline_id: &PipelineId,
        change: F,
    ) -> Result<(), AppError>
    where
        F: FnOnce(&mut Pipeline<ResolvedTenant>) -> Result<(), PipelineError>,
    {
        let tenant = self.caller.tenant();
        let mut pipeline = existing_pipeline(store, &tenant, pipeline_id).await?;
        change(&mut pipeline).map_err(|error| pipeline_error(&error))?;
        store.save(&tenant, &pipeline).await.or_internal()?;
        self.auditor
            .dispatch_by(&self.caller.actor(), pipeline.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// The status a caller sees when a pipeline refuses a change.
///
/// Someone without the right, a mandatory stage or an active pipeline is a
/// `403`; an unknown stage `404`; a pipeline still in use or that would share
/// a cache on a signed-in route a `409`; a move the status cannot make an
/// invalid transition; anything else, such as an order that is not the whole
/// pipeline or settings of another kind, a bad request (`422`) the caller can
/// fix.
pub(super) fn pipeline_error(error: &PipelineError) -> AppError {
    match error {
        PipelineError::NotAllowed
        | PipelineError::CannotRemoveMandatory
        | PipelineError::CannotReconfigureMandatory
        | PipelineError::ActivePipelineImmutable => AppError::Forbidden(error.to_string().into()),
        PipelineError::StageNotFound => AppError::NotFound(error.to_string().into()),
        PipelineError::InUse | PipelineError::SharedCacheOnSignedInRoute => {
            AppError::Conflict(error.to_string().into())
        }
        PipelineError::InvalidTransition(_) => {
            AppError::Domain(DomainError::invalid_transition(error.to_string()))
        }
        PipelineError::CannotAddMandatory
        | PipelineError::OtherKind
        | PipelineError::SettingsRefused(_)
        | PipelineError::IncompleteOrder
        | PipelineError::ForeignRoute => AppError::Domain(DomainError::invalid(error.to_string())),
    }
}

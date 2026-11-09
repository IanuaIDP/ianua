//! Loading the pipeline a caller names.

use ianua_domain::domains::proxy::pipeline::Pipeline;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::PipelineId;

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::proxy::PipelineStore;
use crate::tenancy::ScopedTenant;

/// The tenant's pipeline with `pipeline_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such pipeline.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_pipeline(
    store: &dyn PipelineStore,
    tenant: &ScopedTenant,
    pipeline_id: &PipelineId,
) -> Result<Pipeline<ResolvedTenant>, AppError> {
    store
        .find(tenant, pipeline_id)
        .await
        .or_internal()?
        .or_not_found(message!("proxy-pipeline-not-found", "pipeline not found"))
}

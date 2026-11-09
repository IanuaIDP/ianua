//! Get pipeline: read one of the tenant's pipelines.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{PipelineAction, SystemPermission};
use ianua_domain::domains::proxy::pipeline::Pipeline;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::PipelineId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::proxy::PipelineStore;
use crate::use_case::Query;
use crate::use_cases::proxy::lookup::existing_pipeline;

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Where pipelines are kept.
    pub pipeline_store: Arc<dyn PipelineStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one of the tenant's pipelines.
pub struct GetUseCase {
    ports: GetPorts,
}

impl GetUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetUseCase {
    type Caller = CallerContext;
    type Input = PipelineId;
    type Output = Result<Pipeline<ResolvedTenant>, AppError>;

    /// The tenant's pipeline `pipeline_id`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view pipelines.
    /// - `AppError::NotFound` when the tenant has no such pipeline.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        pipeline_id: PipelineId,
    ) -> Result<Pipeline<ResolvedTenant>, AppError> {
        self.ports
            .tenant_authorities
            .authority(caller)
            .await?
            .ensure_holds(SystemPermission::Pipeline(PipelineAction::View))
            .map_err(AppError::from_domain)?;
        existing_pipeline(
            self.ports.pipeline_store.as_ref(),
            &caller.tenant(),
            &pipeline_id,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::{FakePipelineStore, test_pipeline, test_pipeline_id};
    use crate::test_support::{block_on, test_ctx};

    fn get(
        store: FakePipelineStore,
        authorities: FakeTenantAuthorities,
        id: PipelineId,
    ) -> Result<Pipeline<ResolvedTenant>, AppError> {
        let use_case = GetUseCase::new(GetPorts {
            pipeline_store: Arc::new(store),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), id))
    }

    fn seeded() -> FakePipelineStore {
        FakePipelineStore::holding(test_ctx().tenant_id(), test_pipeline())
    }

    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Pipeline(PipelineAction::View)])
    }

    /// Ann may view pipelines and opens the tenant's. She sees it.
    #[test]
    fn a_viewer_reads_a_pipeline() {
        let pipeline = get(seeded(), viewer(), test_pipeline_id()).unwrap();

        assert_eq!(pipeline.id(), &test_pipeline_id());
    }

    /// Ann names a pipeline the tenant does not have. It is not found.
    #[test]
    fn an_unknown_pipeline_is_not_found() {
        let result = get(FakePipelineStore::empty(), viewer(), test_pipeline_id());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Reading a stored pipeline is forbidden without pipeline view rights.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let result = get(
            seeded(),
            FakeTenantAuthorities::holding(&[]),
            test_pipeline_id(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Reading a pipeline with a signed-out session fails authentication.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = get(
            seeded(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            test_pipeline_id(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

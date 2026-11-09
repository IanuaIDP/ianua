//! The pipeline store the pipeline's evaluation reads for one request: the
//! one pipeline the matched route runs, from the table the request read.
//!
//! The evaluation asks its store for the pipeline the context names. Asking
//! the database on every request would cost a read and could answer a
//! newer pipeline than the route the table matched, so this answers the
//! table's own copy, and only for the tenant and the id it was matched
//! for. It writes nothing.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::proxy::PipelineStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::proxy::pipeline::Pipeline;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PipelineId, TenantId};

/// The pipeline a request's route matched, as a store of one.
pub(super) struct MatchedPipeline {
    tenant: TenantId,
    pipeline: Arc<Pipeline<ResolvedTenant>>,
}

impl MatchedPipeline {
    /// `pipeline`, run for `tenant`.
    pub(super) fn new(tenant: TenantId, pipeline: Arc<Pipeline<ResolvedTenant>>) -> Self {
        Self { tenant, pipeline }
    }

    /// The pipeline, when `tenant` and `pipeline_id` are the ones it was
    /// matched for.
    fn matching(
        &self,
        tenant: &ScopedTenant,
        pipeline_id: &PipelineId,
    ) -> Option<&Pipeline<ResolvedTenant>> {
        let named = **tenant == self.tenant && self.pipeline.id() == pipeline_id;
        named.then_some(self.pipeline.as_ref())
    }
}

impl TenantScoped for MatchedPipeline {}

#[async_trait]
impl PipelineStore for MatchedPipeline {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        pipeline_id: &PipelineId,
    ) -> Result<Option<Pipeline<ResolvedTenant>>, DomainError> {
        Ok(self.matching(tenant_id, pipeline_id).cloned())
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<Pipeline<ResolvedTenant>>, DomainError> {
        Ok(self
            .matching(tenant_id, self.pipeline.id())
            .cloned()
            .into_iter()
            .collect())
    }

    async fn save(
        &self,
        _tenant_id: &ScopedTenant,
        _pipeline: &Pipeline<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        Err(read_only())
    }

    async fn delete(
        &self,
        _tenant_id: &ScopedTenant,
        _pipeline_id: &PipelineId,
    ) -> Result<(), DomainError> {
        Err(read_only())
    }

    async fn route_counts(
        &self,
        _tenant_id: &ScopedTenant,
        _pipeline_ids: &[PipelineId],
    ) -> Result<HashMap<PipelineId, u64>, DomainError> {
        Err(read_only())
    }

    async fn route_count(
        &self,
        _tenant_id: &ScopedTenant,
        _pipeline_id: &PipelineId,
    ) -> Result<u64, DomainError> {
        Err(read_only())
    }
}

/// Why the store of one request writes nothing.
fn read_only() -> DomainError {
    DomainError::infra_msg("the gateway reads the pipeline a request matched and writes none")
}

#[cfg(test)]
mod tests {
    use ianua_app::test_support::proxy::test_pipeline;

    use super::*;

    /// The matched pipeline is found for its own tenant and id only: a
    /// context naming another tenant finds nothing.
    #[tokio::test]
    async fn the_matched_pipeline_is_found_for_its_tenant_only() {
        let pipeline = Arc::new(test_pipeline());
        let tenant = TenantId::new();
        let store = MatchedPipeline::new(tenant, Arc::clone(&pipeline));

        let own = store
            .find(&ScopedTenant::for_background(tenant), pipeline.id())
            .await
            .unwrap();
        let other = store
            .find(
                &ScopedTenant::for_background(TenantId::new()),
                pipeline.id(),
            )
            .await
            .unwrap();

        assert!(own.is_some());
        assert!(other.is_none());
    }
}

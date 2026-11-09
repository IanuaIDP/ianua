//! Proxy pipelines.

use std::collections::HashMap;

use async_trait::async_trait;
use ianua_domain::domains::proxy::pipeline::Pipeline;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::PipelineId;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for persisting and retrieving proxy pipelines.
#[async_trait]
pub trait PipelineStore: Send + Sync + TenantScoped {
    /// Finds one pipeline by id.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the pipeline cannot be read.
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        pipeline_id: &PipelineId,
    ) -> Result<Option<Pipeline<ResolvedTenant>>, DomainError>;

    /// Every pipeline the tenant holds, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the pipelines cannot be read.
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<Pipeline<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated pipeline.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the pipeline cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        pipeline: &Pipeline<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Removes a pipeline.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Conflict`] if any route still names it. The
    /// alternative, dropping those routes or silently repointing them,
    /// changes what runs on live traffic without anyone asking for it.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        pipeline_id: &PipelineId,
    ) -> Result<(), DomainError>;

    /// Counts routes for the requested pipelines in one read. Pipelines
    /// with no routes may be omitted; their count is zero.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the routes cannot be counted.
    async fn route_counts(
        &self,
        tenant_id: &ScopedTenant,
        pipeline_ids: &[PipelineId],
    ) -> Result<HashMap<PipelineId, u64>, DomainError>;

    /// How many routes name this pipeline.
    ///
    /// What a caller checks before offering to delete, so the refusal is a
    /// disabled button rather than an error after the fact.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the routes cannot be counted.
    async fn route_count(
        &self,
        tenant_id: &ScopedTenant,
        pipeline_id: &PipelineId,
    ) -> Result<u64, DomainError>;
}

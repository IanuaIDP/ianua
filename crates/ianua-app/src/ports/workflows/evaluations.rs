//! Where workflows' evaluation sets and their evaluations are kept.

use async_trait::async_trait;
use ianua_domain::domains::workflows::evaluation::run::Evaluation;
use ianua_domain::domains::workflows::evaluation::set::EvaluationSet;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{EvaluationId, WorkflowId};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Where each workflow's one evaluation set is kept.
#[async_trait]
pub trait EvaluationSetStore: Send + Sync + TenantScoped {
    /// The set of workflow `workflow_id`, if one was saved.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        workflow_id: &WorkflowId,
    ) -> Result<Option<EvaluationSet<ResolvedTenant>>, DomainError>;

    /// Keeps `set`, in place of the workflow's set saved before.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be
    /// written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        set: &EvaluationSet<ResolvedTenant>,
    ) -> Result<(), DomainError>;
}

/// Where evaluations are kept.
#[async_trait]
pub trait EvaluationStore: Send + Sync + TenantScoped {
    /// One evaluation.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &EvaluationId,
    ) -> Result<Option<Evaluation<ResolvedTenant>>, DomainError>;

    /// The workflow's evaluations, newest first, at most `limit` of them.
    /// The first is the one a publishing gate reads.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn latest_of(
        &self,
        tenant_id: &ScopedTenant,
        workflow_id: &WorkflowId,
        limit: u32,
    ) -> Result<Vec<Evaluation<ResolvedTenant>>, DomainError>;

    /// Adds an evaluation just started.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be
    /// written.
    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        evaluation: &Evaluation<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Writes `evaluation` over the stored one only while that is still as
    /// it was read, last changed at `read_at`, so two workers that raced
    /// never undo each other's step.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` when it changed since or is gone,
    /// and `DomainError::Infrastructure` when the store cannot be written.
    async fn save_unchanged_since(
        &self,
        tenant_id: &ScopedTenant,
        evaluation: &Evaluation<ResolvedTenant>,
        read_at: OffsetDateTime,
    ) -> Result<(), DomainError>;

    /// The tenant's evaluations still running past their deadline at `now`,
    /// oldest first, at most `limit` of them.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn overdue(
        &self,
        tenant_id: &ScopedTenant,
        now: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<Evaluation<ResolvedTenant>>, DomainError>;

    /// Removes the tenant's evaluations that ended before `cutoff`, and
    /// says how many went. Evaluations still running are kept.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be
    /// written.
    async fn purge_ended_before(
        &self,
        tenant_id: &ScopedTenant,
        cutoff: OffsetDateTime,
    ) -> Result<u64, DomainError>;
}

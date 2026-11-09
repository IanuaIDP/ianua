//! Loading the sets and evaluations a use case acts on, or saying they are
//! not there.

use ianua_domain::domains::workflows::evaluation::run::Evaluation;
use ianua_domain::domains::workflows::evaluation::set::EvaluationSet;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{EvaluationId, WorkflowId};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::workflows::{EvaluationSetStore, EvaluationStore};
use crate::tenancy::ScopedTenant;

/// The evaluation set of the tenant's workflow `workflow_id`.
///
/// # Errors
///
/// - `AppError::NotFound` when no set was saved for it.
/// - `AppError::Internal` when the store fails.
pub(super) async fn existing_set(
    store: &dyn EvaluationSetStore,
    tenant: &ScopedTenant,
    workflow_id: &WorkflowId,
) -> Result<EvaluationSet<ResolvedTenant>, AppError> {
    store
        .find(tenant, workflow_id)
        .await
        .or_internal()?
        .or_not_found(message!("workflows-evaluation-set", "evaluation set"))
}

/// The tenant's evaluation `id` of workflow `workflow_id`.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such evaluation, or it
///   tries another workflow.
/// - `AppError::Internal` when the store fails.
pub(super) async fn existing_evaluation(
    store: &dyn EvaluationStore,
    tenant: &ScopedTenant,
    workflow_id: &WorkflowId,
    id: &EvaluationId,
) -> Result<Evaluation<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .filter(|evaluation| evaluation.workflow_id() == workflow_id)
        .or_not_found(message!("workflows-evaluation", "evaluation"))
}

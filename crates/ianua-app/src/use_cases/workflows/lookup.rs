//! Loading the workflows records a use case acts on, or saying they are not
//! there.

use ianua_domain::domains::workflows::account::IntegrationAccount;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::design::workflow::{Workflow, WorkflowOrigin};
use ianua_domain::domains::workflows::execution::WorkflowExecution;
use ianua_domain::domains::workflows::integration::risk_override::OperationRiskOverride;
use ianua_domain::domains::workflows::triggers::secret::WorkflowTriggerSecret;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{
    IntegrationAccountId, OperationRiskOverrideId, WorkflowExecutionId, WorkflowId,
};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::listing::{Limit, PageRequest};
use crate::ports::workflows::{
    IntegrationAccountStore, OperationRiskOverrideStore, RunKind, WorkflowExecutionStore,
    WorkflowStore, WorkflowTriggerSecretStore,
};
use crate::tenancy::ScopedTenant;

/// The latest version of the tenant's workflow `id`.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such workflow.
/// - `AppError::Internal` when the store fails.
pub(crate) async fn latest_version(
    store: &dyn WorkflowStore,
    tenant: &ScopedTenant,
    id: &WorkflowId,
) -> Result<Workflow<ResolvedTenant>, AppError> {
    store
        .find_latest(tenant, id)
        .await
        .or_internal()?
        .or_not_found(message!("workflows-workflow", "workflow"))
}

/// Version `version` of the tenant's workflow `id`.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such version.
/// - `AppError::Internal` when the store fails.
pub(crate) async fn stored_version(
    store: &dyn WorkflowStore,
    tenant: &ScopedTenant,
    id: &WorkflowId,
    version: u32,
) -> Result<Workflow<ResolvedTenant>, AppError> {
    store
        .find_version(tenant, id, version)
        .await
        .or_internal()?
        .or_not_found(message!("workflows-workflow-version", "workflow version"))
}

/// The version of the tenant's workflow `id` in service.
///
/// # Errors
///
/// - `AppError::NotFound` when no version of it is published.
/// - `AppError::Internal` when the store fails.
pub(crate) async fn published_version(
    store: &dyn WorkflowStore,
    tenant: &ScopedTenant,
    id: &WorkflowId,
) -> Result<Workflow<ResolvedTenant>, AppError> {
    store
        .find_published(tenant, id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "workflows-published-workflow",
            "published workflow"
        ))
}

/// The version in service of the tenant's designed workflow `id`. An agent
/// flow has its one run, started as it was made, so it is not found here.
///
/// # Errors
///
/// - `AppError::NotFound` when no version of it is published, or it is an
///   agent flow.
/// - `AppError::Internal` when the store fails.
pub(crate) async fn published_designed_version(
    store: &dyn WorkflowStore,
    tenant: &ScopedTenant,
    id: &WorkflowId,
) -> Result<Workflow<ResolvedTenant>, AppError> {
    store
        .find_published(tenant, id)
        .await
        .or_internal()?
        .filter(|workflow| *workflow.origin() == WorkflowOrigin::Designed)
        .or_not_found(message!(
            "workflows-published-workflow",
            "published workflow"
        ))
}

/// The tenant's execution `id`.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such execution.
/// - `AppError::Internal` when the store fails.
pub(crate) async fn existing_execution(
    store: &dyn WorkflowExecutionStore,
    tenant: &ScopedTenant,
    id: &WorkflowExecutionId,
) -> Result<WorkflowExecution<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "workflows-workflow-execution",
            "workflow execution"
        ))
}

/// The tenant's workflow execution `id`, read as missing unless the person
/// `control` names may stop it: the person it acts for, or someone with
/// full control of workflows. Anyone else is answered as for an execution
/// that does not exist, so an id cannot be used to find out which runs
/// there are.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such execution, or the
///   person may not stop it.
/// - `AppError::Internal` when the store fails.
pub(crate) async fn owned_execution(
    store: &dyn WorkflowExecutionStore,
    tenant: &ScopedTenant,
    id: &WorkflowExecutionId,
    control: &WorkflowControl<'_>,
) -> Result<WorkflowExecution<ResolvedTenant>, AppError> {
    let execution = existing_execution(store, tenant, id).await?;
    execution.ensure_cancellable_by(control).map_err(|_| {
        AppError::NotFound(message!(
            "workflows-workflow-execution",
            "workflow execution"
        ))
    })?;
    Ok(execution)
}

/// The tenant's integration account `id`.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such account.
/// - `AppError::Internal` when the store fails.
pub(crate) async fn existing_account(
    store: &dyn IntegrationAccountStore,
    tenant: &ScopedTenant,
    id: &IntegrationAccountId,
) -> Result<IntegrationAccount<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "workflows-integration-account",
            "integration account"
        ))
}

/// The tenant's integration account `id`, read as missing unless the person
/// `control` names owns it or may connect accounts. Someone with no say
/// over it is answered as for an account that does not exist, so an id
/// cannot be used to find out which accounts are connected.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such account, or the
///   person has no say over it.
/// - `AppError::Internal` when the store fails.
pub(crate) async fn owned_account(
    store: &dyn IntegrationAccountStore,
    tenant: &ScopedTenant,
    id: &IntegrationAccountId,
    control: &WorkflowControl<'_>,
) -> Result<IntegrationAccount<ResolvedTenant>, AppError> {
    let account = existing_account(store, tenant, id).await?;
    account.ensure_owner_or_manager(control).map_err(|_| {
        AppError::NotFound(message!(
            "workflows-integration-account",
            "integration account"
        ))
    })?;
    Ok(account)
}

/// The tenant's agent flow `id`: its one version. A designed workflow is
/// not a flow, so it is not found here.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such flow.
/// - `AppError::Internal` when the store fails.
pub(crate) async fn existing_flow(
    store: &dyn WorkflowStore,
    tenant: &ScopedTenant,
    id: &WorkflowId,
) -> Result<Workflow<ResolvedTenant>, AppError> {
    store
        .find_latest(tenant, id)
        .await
        .or_internal()?
        .filter(|workflow| matches!(workflow.origin(), WorkflowOrigin::Flow(_)))
        .or_not_found(message!("workflows-agent-flow", "agent flow"))
}

/// The tenant's agent flow `id`, read as missing unless the person
/// `control` names may delete it: its maker, or someone who may delete
/// workflows. Anyone else is answered as for a flow that does not exist,
/// so an id cannot be used to find out which flows there are.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such flow, it is a
///   designed workflow, or the person may not delete it.
/// - `AppError::Internal` when the store fails.
pub(crate) async fn owned_flow(
    store: &dyn WorkflowStore,
    tenant: &ScopedTenant,
    id: &WorkflowId,
    control: &WorkflowControl<'_>,
) -> Result<Workflow<ResolvedTenant>, AppError> {
    let flow = existing_flow(store, tenant, id).await?;
    flow.ensure_deletable_by(control)
        .map_err(|_| AppError::NotFound(message!("workflows-agent-flow", "agent flow")))?;
    Ok(flow)
}

/// Where an agent flow and its run are read from.
pub(crate) struct FlowStores<'a> {
    /// The tenant's workflows.
    pub(crate) workflows: &'a dyn WorkflowStore,
    /// Loads the run associated with the stored flow definition.
    pub(crate) executions: &'a dyn WorkflowExecutionStore,
}

/// An agent flow with its one run.
pub(crate) struct FlowWithRun {
    /// The automation definition describing the flow's stages.
    pub(crate) flow: Workflow<ResolvedTenant>,
    /// The execution tracking those stages and their outcomes.
    pub(crate) run: WorkflowExecution<ResolvedTenant>,
}

/// The tenant's agent flow `id` with its run, read as missing unless the
/// person `control` names may stop the run: the person it acts for, or
/// someone with full control of workflows. Anyone else is answered as for
/// a flow that does not exist, so an id cannot be used to find out which
/// flows there are.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such flow or run, or the
///   person may not stop the run.
/// - `AppError::Internal` when a store fails.
pub(crate) async fn owned_flow_run(
    stores: FlowStores<'_>,
    tenant: &ScopedTenant,
    id: &WorkflowId,
    control: &WorkflowControl<'_>,
) -> Result<FlowWithRun, AppError> {
    let flow = existing_flow(stores.workflows, tenant, id).await?;
    let run = flow_run(stores.executions, tenant, &flow).await?;
    run.ensure_cancellable_by(control)
        .map_err(|_| AppError::NotFound(message!("workflows-agent-flow", "agent flow")))?;
    Ok(FlowWithRun { flow, run })
}

/// The version `version` of the tenant's designed workflow `id`, or its
/// latest. An agent flow is listed and read as a flow, so it is not found
/// here.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such designed workflow or
///   version.
/// - `AppError::Internal` when the store fails.
pub(crate) async fn designed_version(
    store: &dyn WorkflowStore,
    tenant: &ScopedTenant,
    id: &WorkflowId,
    version: Option<u32>,
) -> Result<Workflow<ResolvedTenant>, AppError> {
    let found = match version {
        Some(number) => store.find_version(tenant, id, number).await,
        None => store.find_latest(tenant, id).await,
    };
    found
        .or_internal()?
        .filter(|workflow| *workflow.origin() == WorkflowOrigin::Designed)
        .or_not_found(message!("workflows-workflow", "workflow"))
}

/// The one run of the tenant's agent flow `flow`.
///
/// # Errors
///
/// - `AppError::NotFound` when the flow has no run.
/// - `AppError::Internal` when the store fails.
pub(crate) async fn flow_run(
    store: &dyn WorkflowExecutionStore,
    tenant: &ScopedTenant,
    flow: &Workflow<ResolvedTenant>,
) -> Result<WorkflowExecution<ResolvedTenant>, AppError> {
    kept_flow_run(store, tenant, flow)
        .await?
        .or_not_found(message!("workflows-agent-flow-run", "agent flow run"))
}

/// The one run of the tenant's agent flow `flow`, or `None` when none is
/// kept. Reads that one run alone, never the tenant's other executions.
///
/// # Errors
///
/// - `AppError::Internal` when the store fails.
pub(crate) async fn kept_flow_run(
    store: &dyn WorkflowExecutionStore,
    tenant: &ScopedTenant,
    flow: &Workflow<ResolvedTenant>,
) -> Result<Option<WorkflowExecution<ResolvedTenant>>, AppError> {
    let runs = store
        .list_for_workflow(
            tenant,
            flow.id(),
            RunKind::Real,
            &PageRequest::first(Limit::internal(1)),
        )
        .await
        .or_internal()?;
    Ok(runs.items.into_iter().next())
}

/// The webhook secret of the tenant's workflow `workflow_id`.
///
/// # Errors
///
/// - `AppError::NotFound` when no secret was issued for it.
/// - `AppError::Internal` when the store fails.
pub(crate) async fn trigger_secret_of(
    store: &dyn WorkflowTriggerSecretStore,
    tenant: &ScopedTenant,
    workflow_id: &WorkflowId,
) -> Result<WorkflowTriggerSecret<ResolvedTenant>, AppError> {
    store
        .find_for_workflow(tenant, workflow_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "workflows-workflow-webhook-secret",
            "workflow webhook secret"
        ))
}

/// The tenant's risk override `id`.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such override.
/// - `AppError::Internal` when the store fails.
pub(crate) async fn existing_risk(
    store: &dyn OperationRiskOverrideStore,
    tenant: &ScopedTenant,
    id: &OperationRiskOverrideId,
) -> Result<OperationRiskOverride<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "workflows-operation-risk-override",
            "operation risk override"
        ))
}

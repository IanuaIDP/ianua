//! Loading the delegation (with the chain above it), delegation request,
//! credential, run, approval, tool, model provider, review assignment, task
//! template or sighting a caller names, which the use cases that act on one
//! start with. The agent itself comes from
//! [`existing_agent`](crate::services::lookup::existing_agent), or from
//! [`owned_agent`] when the person acting may reach only some agents.

use std::collections::HashSet;

use ianua_domain::domains::agents::authority::delegation::{Delegation, Lineage};
use ianua_domain::domains::agents::authority::delegation_request::DelegationRequest;
use ianua_domain::domains::agents::authority::task_template::TaskTemplate;
use ianua_domain::domains::agents::execution::model_provider::ModelProvider;
use ianua_domain::domains::agents::execution::run::AgentRun;
use ianua_domain::domains::agents::execution::tool::AgentTool;
use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::agents::identity::credential::AgentCredential;
use ianua_domain::domains::agents::identity::sighting::AgentSighting;
use ianua_domain::domains::agents::oversight::approval::ApprovalRequest;
use ianua_domain::domains::agents::oversight::review::ReviewAssignment;
use ianua_domain::domains::authorization::permission::AgentAction;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::types::{
    AgentCredentialId, AgentId, AgentRunId, AgentSightingId, AgentToolId, ApprovalId, DelegationId,
    DelegationRequestId, ModelProviderId, ReviewAssignmentId, TaskTemplateId,
};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::agents::{
    AgentCredentialStore, AgentSightingStore, AgentStore, ApprovalStore, DelegationRequestStore,
    DelegationStore, ModelProviderStore, ReviewAssignmentStore, RunStore, TaskTemplateStore,
    ToolStore,
};
use crate::services::lookup::existing_agent;
use crate::tenancy::ScopedTenant;
use crate::use_cases::agents::reject_foreign_child;

/// The most delegations a chain is followed through. A stored loop ends
/// here instead of spinning.
const MAX_CHAIN: usize = 64;

/// What the person acting wants of an agent, which decides whether they
/// reach it at all.
#[derive(Debug, Clone, Copy)]
pub(super) enum AgentReach {
    /// Taking the action on it, as its owner or holding the agent
    /// permission for it.
    Acting(AgentAction),
    /// Answering an offer of it made to them.
    Offered,
    /// Ending an offer of it, as the one it was made to, its owner, or
    /// someone allowed to manage agents.
    EndingOffer,
}

impl AgentReach {
    /// Whether `control` reaches `agent` for this.
    fn reaches(self, control: &AgentControl<'_>, agent: &AgentIdentity<ResolvedTenant>) -> bool {
        match self {
            Self::Acting(action) => control.may(agent.owner(), action),
            Self::Offered => control.is_offered(agent.offer()),
            Self::EndingOffer => {
                control.is_offered(agent.offer()) || control.may(agent.owner(), AgentAction::Manage)
            }
        }
    }
}

/// The tenant's agent with `agent_id`, provided `control` reaches it as
/// `reach` says. An agent they may not act on reads as missing, so an id
/// they name tells them nothing about whose agents exist. The aggregate
/// still checks the action in full.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such agent, or `control`
///   does not reach it.
/// - `AppError::Internal` on storage failure.
pub(super) async fn owned_agent(
    store: &dyn AgentStore,
    tenant: &ScopedTenant,
    agent_id: &AgentId,
    control: &AgentControl<'_>,
    reach: AgentReach,
) -> Result<AgentIdentity<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, agent_id)
        .await
        .or_internal()?
        .filter(|agent| reach.reaches(control, agent))
        .or_not_found(message!("app-agent-not-found", "agent not found"))
}

/// The tenant's delegation with `delegation_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such delegation.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_delegation(
    store: &dyn DelegationStore,
    tenant: &ScopedTenant,
    delegation_id: &DelegationId,
) -> Result<Delegation<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, delegation_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "agents-delegation-not-found",
            "delegation not found"
        ))
}

/// The delegation with `delegation_id`, provided `agent_id` is its delegate.
///
/// A delegation held by another agent reads as missing, so the agent segment
/// of the address cannot be used to reach a delegation it does not name.
///
/// # Errors
///
/// - `AppError::NotFound` if there is no such delegation or `agent_id` is not
///   its delegate.
/// - `AppError::Internal` on storage failure.
pub(super) async fn owned_delegation(
    store: &dyn DelegationStore,
    tenant: &ScopedTenant,
    agent_id: &AgentId,
    delegation_id: &DelegationId,
) -> Result<Delegation<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, delegation_id)
        .await
        .or_internal()?
        .filter(|delegation| delegation.delegate() == agent_id)
        .or_not_found(message!(
            "agents-delegation-not-found",
            "delegation not found"
        ))
}

/// The delegation with `delegation_id`, provided `agent_id` is its delegate
/// and the person `control` names granted it. A delegation someone else
/// granted reads as missing, so an id tells them nothing about what others
/// handed out.
///
/// # Errors
///
/// - `AppError::NotFound` if there is no such delegation, `agent_id` is not
///   its delegate, or someone else granted it.
/// - `AppError::Internal` on storage failure.
pub(super) async fn owned_granted_delegation(
    store: &dyn DelegationStore,
    tenant: &ScopedTenant,
    agent_id: &AgentId,
    delegation_id: &DelegationId,
    control: &AgentControl<'_>,
) -> Result<Delegation<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, delegation_id)
        .await
        .or_internal()?
        .filter(|delegation| delegation.delegate() == agent_id)
        .filter(|delegation| *delegation.delegator() == control.by().principal())
        .or_not_found(message!(
            "agents-delegation-not-found",
            "delegation not found"
        ))
}

/// Which delegation of which agent a caller names.
#[derive(Debug, Clone, Copy)]
pub(super) struct DelegationAddress {
    /// The agent the address names.
    pub(super) agent_id: AgentId,
    /// The delegation it holds.
    pub(super) delegation_id: DelegationId,
}

/// A delegation, with the agent it was given to.
pub(super) struct DelegationOfAgent {
    /// The rights being inspected together with their recipient.
    pub(super) delegation: Delegation<ResolvedTenant>,
    /// The agent it was given to.
    pub(super) agent: AgentIdentity<ResolvedTenant>,
}

/// The delegation `address` names, with its agent, provided `control` may
/// take it back: they granted it, own the agent, or may delegate to agents.
/// Anyone else reads it as missing, so an id tells them nothing about what
/// others handed out. The delegation still checks the revoke in full.
///
/// # Errors
///
/// - `AppError::NotFound` if there is no such delegation of the agent, the
///   agent is gone, or `control` may not take it back.
/// - `AppError::Internal` on storage failure.
pub(super) async fn owned_delegation_to_revoke(
    delegations: &dyn DelegationStore,
    agents: &dyn AgentStore,
    tenant: &ScopedTenant,
    address: DelegationAddress,
    control: &AgentControl<'_>,
) -> Result<DelegationOfAgent, AppError> {
    let delegation = owned_delegation(
        delegations,
        tenant,
        &address.agent_id,
        &address.delegation_id,
    )
    .await?;
    let agent = existing_agent(agents, tenant, delegation.delegate()).await?;
    let granted_it = *delegation.delegator() == control.by().principal();
    if !granted_it && !control.may(agent.owner(), AgentAction::Delegate) {
        return Err(AppError::NotFound(message!(
            "agents-delegation-not-found",
            "delegation not found"
        )));
    }
    Ok(DelegationOfAgent { delegation, agent })
}

/// The delegations `agent` holds that are neither revoked nor expired.
///
/// # Errors
///
/// - `AppError::Internal` on storage failure.
pub(super) async fn live_delegations(
    store: &dyn DelegationStore,
    tenant: &ScopedTenant,
    agent: &AgentId,
) -> Result<Vec<Delegation<ResolvedTenant>>, AppError> {
    let now = clock::now();
    Ok(store
        .list_for_agent(tenant, agent)
        .await
        .or_internal()?
        .into_iter()
        .filter(|delegation| delegation.is_valid(now))
        .collect())
}

/// Every delegation `delegation` was cut or minted from, all the way up,
/// as far as they still exist. A missing one is left out, so the chain
/// reads as broken and backs nothing.
///
/// # Errors
///
/// - `AppError::Internal` on storage failure.
pub(super) async fn delegations_above(
    store: &dyn DelegationStore,
    tenant: &ScopedTenant,
    delegation: &Delegation<ResolvedTenant>,
) -> Result<Vec<Delegation<ResolvedTenant>>, AppError> {
    let mut seen: HashSet<DelegationId> = HashSet::from([*delegation.id()]);
    let mut waiting = sources_of(delegation);
    let mut above = Vec::new();
    while let Some(id) = waiting.pop() {
        if above.len() >= MAX_CHAIN || !seen.insert(id) {
            continue;
        }
        let Some(found) = store.find_by_id(tenant, &id).await.or_internal()? else {
            continue;
        };
        waiting.extend(sources_of(&found));
        above.push(found);
    }
    Ok(above)
}

/// The tenant's agent credential with `credential_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such credential.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_credential(
    store: &dyn AgentCredentialStore,
    tenant: &ScopedTenant,
    credential_id: &AgentCredentialId,
) -> Result<AgentCredential<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, credential_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "agents-credential-not-found",
            "credential not found"
        ))
}

/// The credential with `credential_id`, provided it belongs to `agent_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such credential, or it belongs
///   to a different agent than the address named.
/// - `AppError::Internal` on storage failure.
pub(super) async fn owned_credential(
    store: &dyn AgentCredentialStore,
    tenant: &ScopedTenant,
    agent_id: &AgentId,
    credential_id: &AgentCredentialId,
) -> Result<AgentCredential<ResolvedTenant>, AppError> {
    let credential = existing_credential(store, tenant, credential_id).await?;
    reject_foreign_child(agent_id, credential.agent_id())?;
    Ok(credential)
}

/// The tenant's run with `run_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such run.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_run(
    store: &dyn RunStore,
    tenant: &ScopedTenant,
    run_id: &AgentRunId,
) -> Result<AgentRun<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, run_id)
        .await
        .or_internal()?
        .or_not_found(message!("agents-run-not-found", "run not found"))
}

/// The run with `run_id`, provided it belongs to `agent_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such run, or it belongs to a
///   different agent than the address named.
/// - `AppError::Internal` on storage failure.
pub(super) async fn owned_run(
    store: &dyn RunStore,
    tenant: &ScopedTenant,
    agent_id: &AgentId,
    run_id: &AgentRunId,
) -> Result<AgentRun<ResolvedTenant>, AppError> {
    let run = existing_run(store, tenant, run_id).await?;
    reject_foreign_child(agent_id, run.agent_id())?;
    Ok(run)
}

/// Which run of which agent a caller names.
#[derive(Debug, Clone, Copy)]
pub(super) struct RunAddress {
    /// The agent the address names.
    pub(super) agent_id: AgentId,
    /// The run under it.
    pub(super) run_id: AgentRunId,
}

/// Stored execution and identity loaded together for an authority check.
pub(super) struct RunOfAgent {
    /// The execution being inspected or controlled.
    pub(super) run: AgentRun<ResolvedTenant>,
    /// The identity whose ownership governs control of the execution.
    pub(super) agent: AgentIdentity<ResolvedTenant>,
}

/// The run `address` names, with its agent, provided `control` may stop
/// it: they started it, own the agent, or may update agents. Anyone else
/// reads it as missing, so an id tells them nothing about whose runs exist.
/// The run still checks the order in full.
///
/// # Errors
///
/// - `AppError::NotFound` if there is no such run under the agent, the
///   agent is gone, or `control` may not stop the run.
/// - `AppError::Internal` on storage failure.
pub(super) async fn owned_run_to_stop(
    runs: &dyn RunStore,
    agents: &dyn AgentStore,
    tenant: &ScopedTenant,
    address: RunAddress,
    control: &AgentControl<'_>,
) -> Result<RunOfAgent, AppError> {
    let run = owned_run(runs, tenant, &address.agent_id, &address.run_id).await?;
    let agent = existing_agent(agents, tenant, run.agent_id()).await?;
    let started_it = run.started_by().is(control.by());
    if !started_it && !control.may(agent.owner(), AgentAction::Update) {
        return Err(AppError::NotFound(message!(
            "agents-run-not-found",
            "run not found"
        )));
    }
    Ok(RunOfAgent { run, agent })
}

/// The tenant's approval request with `approval_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such approval request.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_approval(
    store: &dyn ApprovalStore,
    tenant: &ScopedTenant,
    approval_id: &ApprovalId,
) -> Result<ApprovalRequest<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, approval_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "agents-approval-request-not-found",
            "approval request not found"
        ))
}

/// The approval request with `approval_id`, provided it was raised for
/// `agent_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such approval request, or it
///   belongs to a different agent than the address named.
/// - `AppError::Internal` on storage failure.
pub(super) async fn owned_approval(
    store: &dyn ApprovalStore,
    tenant: &ScopedTenant,
    agent_id: &AgentId,
    approval_id: &ApprovalId,
) -> Result<ApprovalRequest<ResolvedTenant>, AppError> {
    let approval = existing_approval(store, tenant, approval_id).await?;
    reject_foreign_child(agent_id, approval.agent_id())?;
    Ok(approval)
}

/// The tenant's tool with `tool_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such tool.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_tool(
    store: &dyn ToolStore,
    tenant: &ScopedTenant,
    tool_id: &AgentToolId,
) -> Result<AgentTool<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, tool_id)
        .await
        .or_internal()?
        .or_not_found(message!("agents-tool-not-found", "tool not found"))
}

/// The tenant's model provider with `provider_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such provider.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_model_provider(
    store: &dyn ModelProviderStore,
    tenant: &ScopedTenant,
    provider_id: &ModelProviderId,
) -> Result<ModelProvider<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, provider_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "agents-model-provider-not-found",
            "model provider not found"
        ))
}

/// The review assignment with `assignment_id`, provided `reviewed` is the
/// agent it reviews and `control` may end it: they assigned it, or may
/// update agents. Anyone else reads it as missing, so an id tells them
/// nothing about which reviews exist.
///
/// # Errors
///
/// - `AppError::NotFound` if there is no such assignment, it reviews a
///   different agent than the address named, or `control` may not end it.
/// - `AppError::Internal` on storage failure.
pub(super) async fn owned_review_assignment(
    store: &dyn ReviewAssignmentStore,
    tenant: &ScopedTenant,
    reviewed: &AgentId,
    assignment_id: &ReviewAssignmentId,
    control: &AgentControl<'_>,
) -> Result<ReviewAssignment<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, assignment_id)
        .await
        .or_internal()?
        .filter(|assignment| assignment.reviewed() == reviewed)
        .filter(|assignment| {
            control.by().principal() == *assignment.assigned_by()
                || control.holds_agent(AgentAction::Update)
        })
        .or_not_found(message!(
            "agents-review-assignment-not-found",
            "review assignment not found"
        ))
}

/// The tenant's task template with `template_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such template.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_task_template(
    store: &dyn TaskTemplateStore,
    tenant: &ScopedTenant,
    template_id: &TaskTemplateId,
) -> Result<TaskTemplate<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, template_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "agents-task-template-not-found",
            "task template not found"
        ))
}

/// The tenant's task template with `template_id`, provided `control` may
/// see it: they proposed it, or may view agents. Anyone else reads it as
/// missing, so an id tells them nothing. Deciding on it is still checked
/// in full by the template.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such template, or `control`
///   may not see it.
/// - `AppError::Internal` on storage failure.
pub(super) async fn owned_task_template(
    store: &dyn TaskTemplateStore,
    tenant: &ScopedTenant,
    template_id: &TaskTemplateId,
    control: &AgentControl<'_>,
) -> Result<TaskTemplate<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, template_id)
        .await
        .or_internal()?
        .filter(|template| control.may(template.proposed_by(), AgentAction::View))
        .or_not_found(message!(
            "agents-task-template-not-found",
            "task template not found"
        ))
}

/// The delegation request with `request_id`, provided `agent_id` is the
/// agent that asked and `control` may answer it: it asked them, or they may
/// manage agents. Anyone else reads it as missing, so an id tells them
/// nothing about who was asked for what. The request still checks the
/// answer in full.
///
/// # Errors
///
/// - `AppError::NotFound` if there is no such request, another agent asked
///   it than the address named, or `control` may not answer it.
/// - `AppError::Internal` on storage failure.
pub(super) async fn owned_delegation_request(
    store: &dyn DelegationRequestStore,
    tenant: &ScopedTenant,
    agent_id: &AgentId,
    request_id: &DelegationRequestId,
    control: &AgentControl<'_>,
) -> Result<DelegationRequest<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, request_id)
        .await
        .or_internal()?
        .filter(|request| request.agent_id() == agent_id)
        .filter(|request| {
            control.by().is_same_account_as(request.asked_of())
                || control.holds_agent(AgentAction::Manage)
        })
        .or_not_found(message!(
            "agents-delegation-request-not-found",
            "delegation request not found"
        ))
}

/// The tenant's agent sighting with `sighting_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such sighting.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_sighting(
    store: &dyn AgentSightingStore,
    tenant: &ScopedTenant,
    sighting_id: &AgentSightingId,
) -> Result<AgentSighting<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, sighting_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "agents-agent-sighting-not-found",
            "agent sighting not found"
        ))
}

/// The delegations `delegation` was cut or minted from.
fn sources_of(delegation: &Delegation<ResolvedTenant>) -> Vec<DelegationId> {
    match delegation.lineage() {
        Lineage::Root => Vec::new(),
        Lineage::Under(parent) => vec![*parent],
        Lineage::Minted { from, .. } => from.clone(),
    }
}

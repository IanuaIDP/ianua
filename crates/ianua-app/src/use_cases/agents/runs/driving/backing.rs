//! Which delegation a run a person starts acts under, and whether they
//! still hold what it hands the agent.
//!
//! A delegation backs only the runs its delegator starts, which the domain
//! checks when the run starts. Two things stay with the app. The run names
//! a delegation, or one of the agent's is chosen. And the person starting
//! it must still hold everything the delegation hands over: rights taken
//! from them since they granted it are not theirs to use through an agent.

use ianua_domain::domains::agents::authority::delegation::{Delegation, HeldBy};
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::types::{AgentId, DelegationId, PrincipalRef};

use crate::error::{AppError, OrInternal};
use crate::ports::agents::{DelegationStore, RelationshipResolver, ToolStore};
use crate::tenancy::ScopedTenant;
use crate::use_cases::agents::delegation::resources::usage::held_resources;
use crate::use_cases::agents::lookup::owned_delegation;

/// What a person's hold on a delegation is checked against.
pub(in crate::use_cases::agents::runs) struct BackingSources<'a> {
    /// The resource graph, for what the person holds.
    pub(in crate::use_cases::agents::runs) resolver: &'a dyn RelationshipResolver,
    /// The tenant's tool registry.
    pub(in crate::use_cases::agents::runs) tools: &'a dyn ToolStore,
}

/// The delegation a run of `agent_id` started by `starter` acts under: the
/// one `named`, or the soonest to expire of the agent's live delegations
/// from `starter` when none is named. `None` when the agent holds none from
/// them, and the run then calls no tools.
///
/// # Errors
///
/// - `AppError::NotFound` when the named delegation does not exist or is
///   another agent's.
/// - `AppError::Forbidden` when the named delegation is revoked, expired or
///   sender-constrained.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::agents::runs) async fn backing_delegation(
    store: &dyn DelegationStore,
    tenant: &ScopedTenant,
    starter: &PrincipalRef,
    agent_id: &AgentId,
    named: Option<DelegationId>,
) -> Result<Option<Delegation<ResolvedTenant>>, AppError> {
    let Some(named) = named else {
        return chosen_delegation(store, tenant, starter, agent_id).await;
    };
    let delegation = owned_delegation(store, tenant, agent_id, &named).await?;
    ensure_can_back_a_run(&delegation)?;
    Ok(Some(delegation))
}

/// Refuses a run under `delegation` when the person `control` names no
/// longer holds everything it hands the agent.
///
/// # Errors
///
/// - `AppError::Forbidden` when they no longer hold part of it.
/// - `AppError::Internal` when the graph or the registry cannot be read.
pub(in crate::use_cases::agents::runs) async fn ensure_still_held(
    sources: &BackingSources<'_>,
    tenant: &ScopedTenant,
    control: &AgentControl<'_>,
    delegation: &Delegation<ResolvedTenant>,
) -> Result<(), AppError> {
    let wanted = delegation.granted();
    let registry = sources.tools.list(tenant).await.or_internal()?;
    let held = held_resources(
        sources.resolver,
        tenant,
        control.by().principal(),
        wanted,
        &registry,
    )
    .await?;
    let held_by =
        HeldBy::worked_out(control, wanted, &held, &registry).map_err(AppError::from_domain)?;
    if wanted.subset_of(held_by.caps()) {
        return Ok(());
    }
    Err(AppError::Forbidden(message!(
        "agents-cannot-start-a-run-under-authority",
        "cannot start a run under authority you no longer hold"
    )))
}

/// Refuses a delegation that is revoked, expired or sender-constrained.
/// The server cannot make the proof a sender-constrained one needs, so
/// backing a run with it would turn it into a bearer token.
fn ensure_can_back_a_run(delegation: &Delegation<ResolvedTenant>) -> Result<(), AppError> {
    if !delegation.is_valid(clock::now()) {
        return Err(AppError::Forbidden(message!(
            "agents-delegation-is-revoked-or-expired",
            "delegation is revoked or expired"
        )));
    }
    if delegation.constraints().is_sender_constrained() {
        return Err(AppError::Forbidden(message!(
            "agents-a-sender-constrained-delegation-cannot-back",
            "a sender-constrained delegation cannot back a run"
        )));
    }
    Ok(())
}

/// The soonest to expire of `agent_id`'s live, bearer delegations from
/// `starter`, the id breaking ties, so the choice is the narrowest and
/// never an accident of store order.
async fn chosen_delegation(
    store: &dyn DelegationStore,
    tenant: &ScopedTenant,
    starter: &PrincipalRef,
    agent_id: &AgentId,
) -> Result<Option<Delegation<ResolvedTenant>>, AppError> {
    let now = clock::now();
    let held = store.list_for_agent(tenant, agent_id).await.or_internal()?;
    Ok(held
        .into_iter()
        .filter(|d| d.delegator() == starter)
        .filter(|d| d.is_valid(now) && !d.constraints().is_sender_constrained())
        .min_by(|a, b| {
            a.expires_at()
                .cmp(&b.expires_at())
                .then_with(|| a.id().as_uuid().cmp(b.id().as_uuid()))
        }))
}

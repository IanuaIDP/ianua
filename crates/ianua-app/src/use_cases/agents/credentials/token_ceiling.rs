//! What an agent may mint a task token from: the live delegations one
//! person granted it, while that person may still sign in, and nothing past
//! what they give.
//!
//! Authentication says which agent is calling, not what it may do. The
//! request names its own capabilities, so they are capped to what the
//! agent was given. A delegation the agent minted for itself is not part
//! of the ceiling, or each exchange would widen the next. A token carries
//! one person's authority, never Ann's and Bob's added together.

use ianua_domain::domains::agents::authority::capability::CapabilitySet;
use ianua_domain::domains::agents::authority::delegation::Delegation;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::types::{AgentId, PrincipalRef};

use crate::error::{AppError, OrInternal};
use crate::ports::agents::DelegationStore;
use crate::ports::identity::UserStore;
use crate::ports::organization::OrgUserStore;
use crate::tenancy::ScopedTenant;

/// Where the ceiling is read from.
pub(super) struct CeilingSources<'a> {
    /// The delegations the agent holds.
    pub(super) delegations: &'a dyn DelegationStore,
    /// Tenant users, for a delegator's standing.
    pub(super) users: &'a dyn UserStore,
    /// Organization members, for a delegator's standing.
    pub(super) org_users: &'a dyn OrgUserStore,
}

/// The delegations a token is cut from, and what it may carry.
pub(super) struct Ceiling {
    /// The live delegations of one delegator the token is cut from.
    pub(super) delegations: Vec<Delegation<ResolvedTenant>>,
    /// What was asked for, narrowed to what they give.
    pub(super) granted: CapabilitySet,
}

/// The ceiling for a token `agent_id` asks to carry `wanted` under.
///
/// The delegator is the first whose delegations give everything asked
/// for, or, when none does, the first whose delegations give part of it.
///
/// # Errors
///
/// - `AppError::Forbidden` when no live delegation from someone who may
///   still sign in gives the agent any of what it asked for.
/// - `AppError::Internal` on storage failure.
pub(super) async fn token_ceiling(
    sources: &CeilingSources<'_>,
    tenant: &ScopedTenant,
    agent_id: &AgentId,
    wanted: &CapabilitySet,
) -> Result<Ceiling, AppError> {
    let held = held_authority(sources, tenant, agent_id).await?;
    let by_delegator = grouped_by_delegator(held);
    let chosen = by_delegator
        .iter()
        .position(|group| wanted.subset_of(&union_of(group)))
        .or_else(|| {
            by_delegator
                .iter()
                .position(|group| !wanted.intersect(&union_of(group)).is_empty())
        });
    let delegations = chosen
        .and_then(|chosen| by_delegator.into_iter().nth(chosen))
        .unwrap_or_default();
    let granted = wanted.intersect(&union_of(&delegations));
    if granted.is_empty() {
        return Err(AppError::Forbidden(message!(
            "agents-requested-capabilities-exceed-the-agent-s",
            "requested capabilities exceed the agent's authority"
        )));
    }
    Ok(Ceiling {
        delegations,
        granted,
    })
}

/// The live delegations others granted `agent_id`, from delegators who may
/// still sign in.
async fn held_authority(
    sources: &CeilingSources<'_>,
    tenant: &ScopedTenant,
    agent_id: &AgentId,
) -> Result<Vec<Delegation<ResolvedTenant>>, AppError> {
    let now = clock::now();
    let held = sources
        .delegations
        .list_for_agent(tenant, agent_id)
        .await
        .or_internal()?;
    let mut live = Vec::new();
    for delegation in held
        .into_iter()
        .filter(|d| d.is_valid(now) && !d.is_self_rooted())
    {
        if delegator_has_standing(sources, tenant, delegation.delegator()).await? {
            live.push(delegation);
        }
    }
    Ok(live)
}

/// Whether `delegator` may still sign in, and so still lends authority.
/// Someone with no record no longer exists, and lends nothing.
async fn delegator_has_standing(
    sources: &CeilingSources<'_>,
    tenant: &ScopedTenant,
    delegator: &PrincipalRef,
) -> Result<bool, AppError> {
    match delegator {
        PrincipalRef::User(user_id) => Ok(sources
            .users
            .find_by_id(tenant, user_id)
            .await
            .or_internal()?
            .is_some_and(|user| user.status().can_authenticate())),
        PrincipalRef::OrgUser(member) => Ok(sources
            .org_users
            .find_by_id(member)
            .await
            .or_internal()?
            .is_some_and(|member| member.status().can_authenticate())),
        PrincipalRef::Agent(_) | PrincipalRef::Consumer(_) => Ok(true),
    }
}

/// `held` in groups of one delegator each, in the order first met.
fn grouped_by_delegator(
    held: Vec<Delegation<ResolvedTenant>>,
) -> Vec<Vec<Delegation<ResolvedTenant>>> {
    let mut groups: Vec<Vec<Delegation<ResolvedTenant>>> = Vec::new();
    for delegation in held {
        let found = groups.iter_mut().find(|group| {
            group
                .first()
                .is_some_and(|first| first.delegator() == delegation.delegator())
        });
        match found {
            Some(group) => group.push(delegation),
            None => groups.push(vec![delegation]),
        }
    }
    groups
}

/// Everything the delegations in `group` give between them.
fn union_of(group: &[Delegation<ResolvedTenant>]) -> CapabilitySet {
    group
        .iter()
        .fold(CapabilitySet::empty(), |held, d| held.union(d.granted()))
}

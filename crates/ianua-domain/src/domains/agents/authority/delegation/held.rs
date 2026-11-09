//! What an agent may mint a task token from: the live delegations others
//! granted it, and nothing past what they give.

use time::OffsetDateTime;

use crate::domains::agents::authority::capability::CapabilitySet;
use crate::domains::agents::authority::delegation::Delegation;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::AgentId;

/// Refuses a `ceiling` holding anything but live delegations someone else
/// granted to `agent_id`. Also refuses `granted` when it asks for more than
/// they give.
pub(super) fn ensure_owned_and_held<T: TenantScope>(
    agent_id: AgentId,
    granted: &CapabilitySet,
    ceiling: &[Delegation<T>],
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    let foreign = ceiling.iter().any(|parent| {
        !parent.is_valid(now) || *parent.delegate() != agent_id || parent.is_self_rooted()
    });
    if foreign {
        return Err(DomainError::forbidden(message!(
            "agents-a-token-is-minted-only-from",
            "a token is minted only from live delegations granted to this agent by someone else"
        )));
    }
    ensure_one_delegator(ceiling)?;
    ensure_held(granted, ceiling)
}

/// Refuses a ceiling of delegations from more than one delegator.
///
/// Ann lets the agent read salaries and Bob lets it send email outside.
/// Added together, one token could do what neither of them allowed: mail
/// the salaries out.
fn ensure_one_delegator<T: TenantScope>(ceiling: &[Delegation<T>]) -> Result<(), DomainError> {
    let Some(first) = ceiling.first() else {
        return Ok(());
    };
    if ceiling
        .iter()
        .all(|parent| parent.delegator() == first.delegator())
    {
        return Ok(());
    }
    Err(DomainError::forbidden(message!(
        "agents-a-token-carries-the-authority-of",
        "a token carries the authority of one delegator, not several added together"
    )))
}

/// Refuses `granted` when it holds anything that no delegation in `ceiling`
/// gives.
fn ensure_held<T: TenantScope>(
    granted: &CapabilitySet,
    ceiling: &[Delegation<T>],
) -> Result<(), DomainError> {
    let held = ceiling.iter().fold(CapabilitySet::empty(), |held, parent| {
        held.union(parent.granted())
    });
    if granted.subset_of(&held) {
        return Ok(());
    }
    Err(DomainError::forbidden(message!(
        "agents-an-agent-cannot-grant-itself-more",
        "an agent cannot grant itself more than its delegations give it"
    )))
}

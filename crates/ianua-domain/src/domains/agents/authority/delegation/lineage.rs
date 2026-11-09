//! Where a delegation sits in its chain, and whether the chain above it
//! still stands.
//!
//! A delegation is cut from something: a person's rights at the top of a
//! chain, a parent another agent holds, or, for a task token, the
//! delegations the agent minted it from. Revoking what it was cut from ends
//! it. Ann revokes her agent's delegation. Without the minted link, the task
//! token her agent exchanged a minute earlier would still read as live.

use time::OffsetDateTime;

use crate::domains::agents::authority::capability::CapabilitySet;
use crate::domains::agents::authority::delegation::Delegation;
use crate::isolation::scope::TenantScope;
use crate::shared::validation::distinct::{first_repeat, without_repeats};
use crate::types::{AgentCredentialId, DelegationId, PrincipalRef};

/// Where a delegation sits in its chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lineage {
    /// Granted straight from a principal: the top of a chain.
    Root,
    /// Carved out of this parent, and revoked with it.
    Under(DelegationId),
    /// Minted by its agent for a task token from these delegations, and
    /// revoked with any of them.
    Minted {
        /// The delegations it was cut from, each granted to the agent.
        from: Vec<DelegationId>,
        /// Who granted every one of them.
        delegator: PrincipalRef,
        /// The credential whose key signed the agent in to mint it. A bound
        /// token is bound to that key, and the token stands only while that
        /// credential is not revoked.
        signed_in_with: AgentCredentialId,
    },
}

/// The lineage of a task token minted from `ceiling`, all of it granted by
/// `first`'s delegator, by an agent `signed_in_with` one of its keys.
pub(super) fn minted_from<T: TenantScope>(
    ceiling: &[Delegation<T>],
    first: &Delegation<T>,
    signed_in_with: AgentCredentialId,
) -> Lineage {
    Lineage::Minted {
        from: ceiling.iter().map(|source| *source.id()).collect(),
        delegator: *first.delegator(),
        signed_in_with,
    }
}

/// Whether `delegation` is live at `now` and every delegation it was cut
/// from reaches a live root within `hops` more links. The bound stops a
/// stored loop.
pub(super) fn live_within<T: TenantScope>(
    delegation: &Delegation<T>,
    above: &[Delegation<T>],
    now: OffsetDateTime,
    hops: usize,
) -> bool {
    if !delegation.is_valid(now) {
        return false;
    }
    match delegation.lineage() {
        Lineage::Root => true,
        Lineage::Under(parent) => {
            sources_hold(delegation, std::slice::from_ref(parent), above, now, hops)
        }
        Lineage::Minted {
            from, delegator, ..
        } => {
            every_source_from(from, delegator, above)
                && sources_hold(delegation, from, above, now, hops)
        }
    }
}

/// Whether each of `sources` is in `above` and live, and together they still
/// grant all `delegation` grants.
fn sources_hold<T: TenantScope>(
    delegation: &Delegation<T>,
    sources: &[DelegationId],
    above: &[Delegation<T>],
    now: OffsetDateTime,
    hops: usize,
) -> bool {
    let Some(next) = hops.checked_sub(1) else {
        return false;
    };
    let found: Vec<&Delegation<T>> = sources
        .iter()
        .filter_map(|id| above.iter().find(|candidate| candidate.id() == id))
        .collect();
    let granted = found.iter().fold(CapabilitySet::empty(), |held, source| {
        held.union(source.granted())
    });
    !sources.is_empty()
        && found.len() == sources.len()
        && delegation.granted().subset_of(&granted)
        && found
            .iter()
            .all(|source| live_within(source, above, now, next))
}

/// Whether every source of a minted delegation found in `above` was granted
/// by `delegator`. A stored link swapped to another person's delegation does
/// not count.
fn every_source_from<T: TenantScope>(
    sources: &[DelegationId],
    delegator: &PrincipalRef,
    above: &[Delegation<T>],
) -> bool {
    above
        .iter()
        .filter(|candidate| sources.contains(candidate.id()))
        .all(|source| source.delegator() == delegator)
}

/// The people at the top of the chain `delegation` was cut from, each named
/// once, as far as `above` reaches.
///
/// A sub-delegation follows its parent, and a minted one each delegation it
/// was cut from. A root granted by a person names that person. One an agent
/// made for itself names nobody.
pub(crate) fn people_behind<T: TenantScope>(
    delegation: &Delegation<T>,
    above: &[Delegation<T>],
) -> Vec<PrincipalRef> {
    without_repeats(roots_of(delegation, above, above.len()))
}

/// The root delegators of `delegation`, following at most `hops` links.
fn roots_of<T: TenantScope>(
    delegation: &Delegation<T>,
    above: &[Delegation<T>],
    hops: usize,
) -> Vec<PrincipalRef> {
    let sources: &[DelegationId] = match delegation.lineage() {
        Lineage::Root if delegation.is_self_rooted() => return Vec::new(),
        Lineage::Root => return vec![*delegation.delegator()],
        Lineage::Under(parent) => std::slice::from_ref(parent),
        Lineage::Minted { from, .. } => from,
    };
    let Some(next) = hops.checked_sub(1) else {
        return Vec::new();
    };
    above
        .iter()
        .filter(|candidate| sources.contains(candidate.id()))
        .flat_map(|source| roots_of(source, above, next))
        .collect()
}

/// Whether a stored minted lineage names at least one source, none twice,
/// never the delegation itself, and a delegator other than the agent.
pub(super) fn minted_fits(
    id: DelegationId,
    agent: PrincipalRef,
    from: &[DelegationId],
    delegator: &PrincipalRef,
) -> bool {
    !from.is_empty()
        && first_repeat(from.iter().copied()).is_none()
        && !from.contains(&id)
        && *delegator != agent
}

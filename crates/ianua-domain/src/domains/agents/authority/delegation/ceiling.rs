//! Who passes part of a delegation on, and how far a delegation may grow
//! when a resource is added to it.

use crate::domains::agents::authority::capability::CapabilitySet;
use crate::domains::agents::authority::delegation::Delegation;
use crate::domains::agents::authority::delegation::held_by::HeldBy;
use crate::domains::agents::authority::delegation::held_now::HeldNow;
use crate::domains::agents::authority::delegation::lineage::Lineage;
use crate::domains::agents::identity::acting::ActingAgent;
use crate::domains::agents::identity::agent::AgentIdentity;
use crate::domains::agents::identity::control::AgentControl;
use crate::domains::authorization::permission::AgentAction;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;

/// Who passes part of a delegation on, or widens a child passed on from it.
///
/// The child is always the holding agent's: its delegator is that agent,
/// whoever asked. A person who passes it on only speaks for the agent.
#[derive(Debug)]
pub enum Attenuator<'a, T: TenantScope> {
    /// The agent holding the delegation, signed in as itself.
    Agent(&'a ActingAgent),
    /// The person who owns the agent holding it. The agent could pass the
    /// delegation on itself, so its owner may too.
    Owner {
        /// The person acting.
        control: AgentControl<'a>,
        /// The agent holding the delegation.
        holder: &'a AgentIdentity<T>,
    },
    /// Someone allowed to delegate to agents who does not own the agent
    /// holding it. They pass on no more than they hold themselves.
    Steward {
        /// The person acting.
        control: AgentControl<'a>,
        /// The agent holding the delegation.
        holder: &'a AgentIdentity<T>,
        /// What the person holds, worked out for what they pass on.
        held: &'a HeldBy,
    },
}

impl<T: TenantScope> Attenuator<'_, T> {
    /// Refuses anyone who neither holds `delegation` nor has a say over the
    /// agent that does.
    ///
    /// Mallory's agent learns that Ann's agent holds ledger access. Signed
    /// in as itself, or as Mallory with no say over Ann's agent, it would
    /// otherwise pass that access on to an agent of hers.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when an agent other than the holder
    ///   asks.
    /// - [`DomainError::Forbidden`] when a person names an agent other than
    ///   the holder, speaks as its owner without owning it, or as a steward
    ///   without being allowed to delegate to agents.
    pub(super) fn ensure_speaks_for(&self, delegation: &Delegation<T>) -> Result<(), DomainError> {
        match self {
            Self::Agent(agent) => ensure_holder(agent, delegation),
            Self::Owner { control, holder } => {
                ensure_holding(holder, delegation)?;
                ensure_owns(control, holder)
            }
            Self::Steward {
                control, holder, ..
            } => {
                ensure_holding(holder, delegation)?;
                control.ensure_may(holder.owner(), AgentAction::Delegate)
            }
        }
    }

    /// Refuses a steward passing on, or widening a child to, anything they
    /// do not hold themselves.
    ///
    /// Sam grants his agent ledger access. Mallory may delegate to agents
    /// but holds no ledger access. Without this she passes Sam's agent's
    /// access on to an agent of hers, which then reads the ledger she may
    /// not.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when what the steward holds was worked
    ///   out for someone else.
    /// - [`DomainError::Forbidden`] when `passed` reaches past it.
    pub(super) fn ensure_may_pass_on(&self, passed: &CapabilitySet) -> Result<(), DomainError> {
        let Self::Steward { control, held, .. } = self else {
            return Ok(());
        };
        if held.holder() != control.by().principal() {
            return Err(DomainError::forbidden(message!(
                "agents-what-the-person-holds-was-worked",
                "what the person holds was worked out for someone else"
            )));
        }
        if passed.subset_of(held.caps()) {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "agents-someone-who-does-not-own-the",
            "someone who does not own the agent passes on only what they hold themselves"
        )))
    }
}

/// Refuses an agent that does not hold `delegation`.
fn ensure_holder<T: TenantScope>(
    agent: &ActingAgent,
    delegation: &Delegation<T>,
) -> Result<(), DomainError> {
    if agent.agent() == delegation.delegate() {
        return Ok(());
    }
    Err(DomainError::forbidden(message!(
        "agents-only-the-agent-holding-a-delegation",
        "only the agent holding a delegation passes part of it on"
    )))
}

/// Refuses a `holder` that does not hold `delegation`.
fn ensure_holding<T: TenantScope>(
    holder: &AgentIdentity<T>,
    delegation: &Delegation<T>,
) -> Result<(), DomainError> {
    if holder.id() == delegation.delegate() {
        return Ok(());
    }
    Err(DomainError::forbidden(message!(
        "agents-the-agent-named-is-not-the",
        "the agent named is not the one holding the delegation"
    )))
}

/// Refuses a person who does not own `holder`.
fn ensure_owns<T: TenantScope>(
    control: &AgentControl<'_>,
    holder: &AgentIdentity<T>,
) -> Result<(), DomainError> {
    if control.by().is_same_person_as(holder.owner()) {
        return Ok(());
    }
    Err(DomainError::forbidden(message!(
        "agents-only-the-agent-s-owner-speaks",
        "only the agent's owner speaks for it as its owner"
    )))
}

/// The most a delegation may grow to when a resource is added to it.
///
/// For a root, it is what the person who granted it holds, or, for an agent
/// administrator, what both they and that person hold now. For a
/// sub-delegation, it is its parent, widened by the agent holding that
/// parent or a person with a say over it.
pub enum ResourceCeiling<'a, T: TenantScope> {
    /// What the delegator holds, for a root delegation.
    Delegator(HeldBy),
    /// The parent delegation, for a sub-delegation, widened by `by`.
    Parent {
        /// The parent delegation.
        parent: &'a Delegation<T>,
        /// Who widens the child. They must hold `parent` or speak for the
        /// agent that does.
        by: Attenuator<'a, T>,
    },
    /// An agent administrator widening a root someone else granted.
    Administrator {
        /// What the administrator holds.
        admin: HeldBy,
        /// What the root's delegator holds now.
        delegator: HeldNow,
    },
}

/// Refuses `widened` for `delegation` unless `ceiling` matches where it
/// sits in its chain and holds all of `widened`.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when `delegation` was made by its agent for
///   itself.
/// - [`DomainError::Forbidden`] when `ceiling` is not what this
///   delegation's own delegator holds for a root, or not its parent for a
///   sub-delegation.
/// - [`DomainError::Forbidden`] when whoever widens it may not.
/// - [`DomainError::Forbidden`] when `widened` reaches past the ceiling.
pub(super) fn ensure_within<T: TenantScope>(
    delegation: &Delegation<T>,
    widened: &CapabilitySet,
    ceiling: &ResourceCeiling<'_, T>,
) -> Result<(), DomainError> {
    if delegation.is_self_rooted() {
        return Err(DomainError::forbidden(message!(
            "agents-a-self-rooted-delegation-is-not",
            "a self-rooted delegation is not widened in place"
        )));
    }
    match (delegation.lineage(), ceiling) {
        (Lineage::Root, ResourceCeiling::Delegator(held))
            if held.holder() == *delegation.delegator() =>
        {
            ensure_fits(widened, held.caps())
        }
        (Lineage::Root, ResourceCeiling::Administrator { admin, delegator }) => {
            ensure_administers(delegation, admin, delegator)?;
            ensure_fits(widened, admin.caps())?;
            ensure_fits(widened, delegator.caps())
        }
        (Lineage::Under(id), ResourceCeiling::Parent { parent, by }) if id == parent.id() => {
            by.ensure_speaks_for(parent)?;
            by.ensure_may_pass_on(widened)?;
            ensure_fits(widened, parent.granted())
        }
        _ => Err(DomainError::forbidden(message!(
            "agents-the-ceiling-given-is-not-where",
            "the ceiling given is not where this delegation sits"
        ))),
    }
}

/// Refuses an administrator who may not manage agents, or a delegator's
/// holdings worked out for someone other than who granted `delegation`.
///
/// Sam may delegate to agents but not manage them. Without this, he widens
/// Ann's delegation to her agent with what he holds and she does too.
fn ensure_administers<T: TenantScope>(
    delegation: &Delegation<T>,
    admin: &HeldBy,
    delegator: &HeldNow,
) -> Result<(), DomainError> {
    if !admin.manages_agents() {
        return Err(DomainError::forbidden(message!(
            "agents-only-an-agent-administrator-widens-a",
            "only an agent administrator widens a delegation someone else granted"
        )));
    }
    if delegator.holder() != *delegation.delegator() {
        return Err(DomainError::forbidden(message!(
            "agents-what-the-delegator-holds-was-worked",
            "what the delegator holds was worked out for someone else"
        )));
    }
    Ok(())
}

/// Refuses `widened` when it holds anything `ceiling` does not.
fn ensure_fits(widened: &CapabilitySet, ceiling: &CapabilitySet) -> Result<(), DomainError> {
    if widened.subset_of(ceiling) {
        return Ok(());
    }
    Err(DomainError::forbidden(message!(
        "agents-the-resource-reaches-past-what-the",
        "the resource reaches past what the delegator holds"
    )))
}

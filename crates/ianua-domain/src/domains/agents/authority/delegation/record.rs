//! What a delegation is made from, where it sits in its chain, and how it
//! is stored.

use time::OffsetDateTime;

use crate::domains::agents::authority::capability::{CapabilitySet, DelegationConstraints};
use crate::domains::agents::authority::delegation::lineage::{Lineage, minted_fits};
use crate::domains::agents::identity::acting::ActingAgent;
use crate::domains::agents::identity::agent::AgentIdentity;
use crate::domains::agents::identity::control::AgentControl;
use crate::domains::authorization::permission::AgentAction;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::shared::model::transition::{InvalidTransition, checked};
use crate::types::{AgentId, DelegationId, EventLabel, Human, Label, Lifetime, PrincipalRef};

/// Whether the agent receiving a delegation is reviewing another agent.
///
/// A reviewer reads evidence and acts on nothing. One that held a delegation
/// could act on what it reviews, so a reviewer is given none while it
/// reviews.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewDuty {
    /// It reviews no agent.
    NotReviewing,
    /// It is assigned to review another agent.
    Reviewing,
}

impl ReviewDuty {
    /// Refuses giving a delegation to an agent that is reviewing.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the agent is reviewing.
    fn ensure_free(self) -> Result<(), DomainError> {
        match self {
            Self::NotReviewing => Ok(()),
            Self::Reviewing => Err(DomainError::forbidden(message!(
                "agents-an-agent-reviewing-another-is-given",
                "an agent reviewing another is given no delegation"
            ))),
        }
    }
}

/// The agent receiving a delegation, and whether it is reviewing another.
pub struct Delegate<'a, T: TenantScope> {
    /// The recipient whose standing is checked before authority is granted.
    pub agent: &'a AgentIdentity<T>,
    /// Whether it reviews another agent.
    pub duty: ReviewDuty,
}

impl<T: TenantScope> Delegate<'_, T> {
    /// The agent's id.
    #[must_use]
    pub fn id(&self) -> AgentId {
        *self.agent.id()
    }

    /// The agent's name, as the record of what it receives shows it.
    pub(super) fn label(&self) -> EventLabel {
        EventLabel::of(self.agent.name().as_str())
    }

    /// Refuses an agent that is reviewing, or that may not act now.
    ///
    /// A suspended or revoked agent, or one owing a re-attestation, is given
    /// nothing. Ann's
    /// agent is revoked after a leak. Without this check, Bob grants it a
    /// fresh delegation that lies ready for whoever gets it back.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the agent is reviewing.
    /// - [`DomainError::Forbidden`] when the agent may not act now.
    pub(super) fn ensure_may_receive(&self) -> Result<(), DomainError> {
        self.duty.ensure_free()?;
        if self.agent.may_act_at(crate::shared::clock::now()) {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "agents-a-delegation-is-given-only-to",
            "a delegation is given only to an agent that may act"
        )))
    }
}

/// Who takes authority back from an agent.
#[derive(Debug, Clone, Copy)]
pub enum Revoker<'a> {
    /// A person. The delegator may, and so may the agent's owner or someone
    /// allowed to delegate to agents.
    Person {
        /// The person acting, with what they hold.
        control: AgentControl<'a>,
        /// The owner of the agent the delegation was given to.
        agent_owner: &'a Human,
    },
    /// The platform, when what the delegation rests on ends: its delegator
    /// is deactivated, or its agent, its parent or a delegation it was
    /// minted from is revoked.
    Platform,
    /// One of the platform's own monitors, which caught the agent drifting
    /// from the purpose the delegation declared.
    ///
    /// Taking authority back is the safe direction, so a monitor needs no
    /// person. Giving it back always does.
    Monitor,
}

impl Revoker<'_> {
    /// Refuses a person who neither granted `delegation` nor has a say over
    /// its agent.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not take it back.
    pub(super) fn ensure_may_revoke(&self, delegator: &PrincipalRef) -> Result<(), DomainError> {
        let Self::Person {
            control,
            agent_owner,
        } = self
        else {
            return Ok(());
        };
        if control.by().principal() == *delegator {
            return Ok(());
        }
        control.ensure_may(agent_owner, AgentAction::Delegate)
    }
}

/// What an agent asks for when it makes the delegation behind a task token.
pub struct OwnedTokenRequest<'a> {
    /// The agent asking, signed in as itself.
    pub agent: &'a ActingAgent,
    /// The agent's name, as the record of the token it mints shows it.
    pub agent_label: EventLabel,
    /// The capabilities it asks for.
    pub granted: CapabilitySet,
    /// The limits it asks for. None of them is trusted.
    pub requested: DelegationConstraints,
    /// The longest a task token may live.
    pub max_ttl: Lifetime,
}

/// What a person gives to start a delegation to an agent.
pub struct GrantDelegationParams {
    /// The capabilities to hand over. They must all be ones the delegator
    /// holds.
    pub granted: CapabilitySet,
    /// The limits on the delegation, such as its lifetime, depth and task.
    pub constraints: DelegationConstraints,
    /// A title people see, such as "Q1 reconciliation delegation". `None`
    /// when it has none.
    pub name: Option<Label>,
}

/// What an agent gives to pass part of its delegation to another agent.
pub struct AttenuateParams {
    /// The capabilities to hand over. They must all be ones the parent
    /// delegation grants.
    pub granted: CapabilitySet,
    /// The limits the child asks for. They are held inside the parent's.
    pub constraints: DelegationConstraints,
    /// A title people see for the child. `None` when it has none.
    pub name: Option<Label>,
}

/// Whether a delegation still grants anything.
///
/// A revoked delegation stays on record, so an audit can still see what it
/// allowed. It allows nothing now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationStatus {
    /// It grants what it says.
    Active,
    /// It is revoked and grants nothing.
    Revoked,
}

impl DelegationStatus {
    /// Moves to `to` when the move is allowed. The only allowed move is from
    /// active to revoked.
    ///
    /// # Errors
    ///
    /// - [`InvalidTransition`] for any other move.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
        checked(self, to, |from, to| {
            from == Self::Active && to == Self::Revoked
        })
    }
}

/// Whether a person renewed a delegation since it was issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationRenewal {
    /// It lives the lifetime it was issued with.
    NotRenewed,
    /// Its delegator renewed it at this time, for its lifetime from then.
    RenewedAt(OffsetDateTime),
}

impl DelegationRenewal {
    /// When it was last renewed, if it was.
    #[must_use]
    pub fn at(self) -> Option<OffsetDateTime> {
        match self {
            Self::NotRenewed => None,
            Self::RenewedAt(at) => Some(at),
        }
    }
}

/// A delegation as storage keeps it. `Delegation::reconstitute` checks it
/// and reads it back.
pub struct DelegationRow {
    /// The delegation's id.
    pub id: DelegationId,
    /// Who handed over the authority.
    pub delegator: PrincipalRef,
    /// The agent receiving authority.
    pub delegate: AgentId,
    /// The capabilities it grants.
    pub granted: CapabilitySet,
    /// The limits on it, such as its lifetime, depth and task.
    pub constraints: DelegationConstraints,
    /// Where the delegation sits in its chain.
    pub lineage: Lineage,
    /// How many links it sits below the top of its chain. A root is 0.
    pub depth: u8,
    /// Whether the delegation still grants anything.
    pub status: DelegationStatus,
    /// When it was issued.
    pub issued_at: OffsetDateTime,
    /// When it expires.
    pub expires_at: OffsetDateTime,
    /// Whether its delegator renewed it, and when last.
    pub renewed: DelegationRenewal,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
    /// A title people see. `None` when it has none.
    pub name: Option<Label>,
}

/// Whether a stored lineage and depth agree.
///
/// A sub-delegation has a depth above zero and is never its own parent. A root
/// sits at depth zero, granted by a person or by an agent to itself. A minted
/// delegation is the agent's own and may sit deeper, because it keeps the
/// depth of the authority it was cut from, which someone else granted.
fn lineage_fits_depth(row: &DelegationRow) -> bool {
    match &row.lineage {
        Lineage::Under(parent) => {
            *parent != row.id && row.depth > 0 && matches!(row.delegator, PrincipalRef::Agent(_))
        }
        Lineage::Minted {
            from, delegator, ..
        } => is_self_rooted(row) && minted_fits(row.id, row.delegator, from, delegator),
        Lineage::Root if is_self_rooted(row) => row.depth == 0,
        Lineage::Root => row.depth == 0 && is_person(&row.delegator),
    }
}

/// Whether a stored delegation expires no later than its lifetime allows
/// from when it was issued, or last renewed.
fn lives_within_its_lifetime(row: &DelegationRow) -> bool {
    let lifetime = time::Duration::seconds(i64::from(row.constraints.ttl_seconds().get()));
    let from = row.renewed.at().unwrap_or(row.issued_at);
    row.expires_at <= from.saturating_add(lifetime)
}

/// Whether a renewed delegation is one a person granted at the top of its
/// chain, the only kind a renewal reaches.
fn renewed_only_as_a_root(row: &DelegationRow) -> bool {
    row.renewed == DelegationRenewal::NotRenewed
        || (row.lineage == Lineage::Root && is_person(&row.delegator))
}

fn is_self_rooted(row: &DelegationRow) -> bool {
    matches!(row.delegator, PrincipalRef::Agent(id) if id == row.delegate)
}

/// Whether `principal` is a person. Only a person starts a chain of
/// authority for someone else.
fn is_person(principal: &PrincipalRef) -> bool {
    matches!(principal, PrincipalRef::User(_) | PrincipalRef::OrgUser(_))
}

/// Refuses a stored row that breaks a rule this keeps.
pub(super) fn ensure_consistent(row: &DelegationRow) -> Result<(), DomainError> {
    RowCheck::of("delegation")
        .holds(lineage_fits_depth(row), "a lineage its depth contradicts")
        .holds(
            row.depth <= row.constraints.max_depth(),
            "deeper than its own depth limit",
        )
        .holds(
            row.issued_at < row.expires_at,
            "expires before it was issued",
        )
        .holds(
            lives_within_its_lifetime(row),
            "outlives the lifetime it was given",
        )
        .holds(
            renewed_only_as_a_root(row),
            "renewed though no person granted it",
        )
        .in_order_if(
            row.issued_at,
            row.renewed.at(),
            "renewed before it was issued",
        )
        .in_order(
            row.issued_at,
            row.updated_at,
            "changed before it was issued",
        )
        .finish()
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::types::{Seconds, UserId};

    /// A sub-delegation one link below its root, passed on by an agent,
    /// living ten minutes of its ten-minute lifetime.
    fn child_row() -> DelegationRow {
        let now = crate::shared::clock::now();
        DelegationRow {
            id: DelegationId::new(),
            delegator: PrincipalRef::Agent(AgentId::new()),
            delegate: AgentId::new(),
            granted: CapabilitySet::new(Vec::new(), Vec::new()),
            constraints: DelegationConstraints::new(Seconds::new(600), 1).unwrap(),
            lineage: Lineage::Under(DelegationId::new()),
            depth: 1,
            status: DelegationStatus::Active,
            issued_at: now,
            expires_at: now + Duration::minutes(10),
            renewed: DelegationRenewal::NotRenewed,
            updated_at: now,
            name: None,
        }
    }

    /// A sub-delegation stored as it was made passes the check.
    #[test]
    fn a_stored_sub_delegation_passes() {
        assert!(ensure_consistent(&child_row()).is_ok());
    }

    /// A stored child at depth two with a depth limit of one is refused
    /// as corrupt.
    #[test]
    fn a_stored_delegation_deeper_than_its_limit_is_refused() {
        let mut row = child_row();
        row.depth = 2;

        assert!(refused_as_corrupt(&ensure_consistent(&row)));
    }

    /// A stored child naming a user as its delegator is refused as corrupt,
    /// because a sub-delegation must be passed on by an agent.
    #[test]
    fn a_stored_sub_delegation_a_person_passed_on_is_refused() {
        let mut row = child_row();
        row.delegator = PrincipalRef::User(UserId::new());

        assert!(refused_as_corrupt(&ensure_consistent(&row)));
    }

    /// A stored delegation expiring one second beyond its ten-minute
    /// lifetime is refused as corrupt.
    #[test]
    fn a_stored_delegation_outliving_its_lifetime_is_refused() {
        let mut row = child_row();
        row.expires_at += Duration::SECOND;

        assert!(refused_as_corrupt(&ensure_consistent(&row)));
    }
}

use crate::domains::organization::members::membership::OrgRole;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{OrgUserId, OrganizationId};

/// Whether an organization is active, suspended or closed.
///
/// An active organization can be suspended, for example over a billing
/// problem, and made active again. An active or suspended one can be closed.
/// Closed is final.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OrganizationStatus {
    /// The organization works normally.
    Active,
    /// The organization is paused. It can be made active again or closed.
    Suspended,
    /// The organization is closed for good. No status follows it.
    Closed,
}

impl OrganizationStatus {
    /// The stable name the audit record carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Closed => "closed",
        }
    }

    /// Attempts a state transition.
    ///
    /// # Errors
    ///
    /// - [`InvalidOrganizationTransition`] when `to` is the current state, or
    ///   the organization is closed.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidOrganizationTransition> {
        let allowed = matches!(
            (self, to),
            (Self::Active, Self::Suspended | Self::Closed)
                | (Self::Suspended, Self::Active | Self::Closed)
        );

        if allowed {
            Ok(to)
        } else {
            Err(InvalidOrganizationTransition { from: self, to })
        }
    }

    /// Whether this organization can operate normally.
    #[must_use]
    pub fn is_active(&self) -> bool {
        *self == Self::Active
    }
}

/// An organization as a member acting on it finds it: which one it is, and
/// its status.
///
/// A control copies it when it is made, so it borrows nothing from the
/// organization it then changes. Only [`Organization::standing`] makes one.
///
/// [`Organization::standing`]: crate::domains::organization::lifecycle::Organization::standing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrgStanding {
    id: OrganizationId,
    status: OrganizationStatus,
}

impl OrgStanding {
    /// Organization `id`, standing at `status`.
    pub(crate) fn new(id: OrganizationId, status: OrganizationStatus) -> Self {
        Self { id, status }
    }

    /// Which organization it is.
    #[must_use]
    pub fn id(&self) -> &OrganizationId {
        &self.id
    }

    /// The current standing used to admit or refuse members by role.
    #[must_use]
    pub fn status(&self) -> OrganizationStatus {
        self.status
    }

    /// Refuses a member holding `role` whom the status keeps out: everyone
    /// once it is closed, and everyone but its owners and its billing
    /// contact while it is suspended, so they can settle what caused it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] in each of those cases.
    pub(crate) fn ensure_admits(&self, role: OrgRole) -> Result<(), DomainError> {
        match self.status {
            OrganizationStatus::Active => Ok(()),
            OrganizationStatus::Suspended if role.acts_while_suspended() => Ok(()),
            OrganizationStatus::Suspended => Err(DomainError::forbidden(message!(
                "organization-while-the-organization-is-suspended-only",
                "while the organization is suspended only its owners and billing contact act"
            ))),
            OrganizationStatus::Closed => Err(DomainError::forbidden(message!(
                "organization-the-organization-is-closed-so-nobody",
                "the organization is closed, so nobody acts on it"
            ))),
        }
    }
}

/// Who suspended an organization, which decides who may lift it.
///
/// An owner may pause their own organization and switch it back on. A
/// suspension the platform made, such as over an unpaid bill, only the
/// platform lifts. Without the difference, Acme's owner switches Acme back
/// on the moment it is suspended for not paying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suspension {
    /// The organization is not suspended.
    NotSuspended,
    /// A member suspended it.
    ByMember(OrgUserId),
    /// The platform suspended it, for this reason.
    ByPlatform(OrgSuspensionReason),
}

/// Why the platform suspended an organization, which decides whether
/// paying lifts it.
///
/// Settling the debt lifts a suspension made for not paying, and never one
/// an operator made. Without the difference, Mallory's organization,
/// suspended by an operator for abuse, pays a small bill and is back on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrgSuspensionReason {
    /// A payment was owed past the grace the platform allows.
    NonPayment,
    /// An operator suspended it, for whatever cause they had.
    Operator,
}

impl OrgSuspensionReason {
    /// The stable name the store and the audit record carry.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NonPayment => "non_payment",
            Self::Operator => "operator",
        }
    }
}

/// Rejected organization status transition.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move an organization from {from:?} to {to:?}")]
pub struct InvalidOrganizationTransition {
    /// The current state.
    pub from: OrganizationStatus,
    /// The attempted target state.
    pub to: OrganizationStatus,
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidOrganizationTransition);

#[cfg(test)]
mod tests {
    use super::*;

    /// Acme is suspended over an unpaid bill. Only an active organization
    /// reads as active, so a suspended or closed Acme is never treated as usable.
    #[test]
    fn only_the_active_state_reads_as_active() {
        assert!(OrganizationStatus::Active.is_active());
        assert!(!OrganizationStatus::Suspended.is_active());
        assert!(!OrganizationStatus::Closed.is_active());
    }

    /// An active organization stops paying. It may be suspended.
    #[test]
    fn active_to_suspended() {
        assert!(
            OrganizationStatus::Active
                .try_transition(OrganizationStatus::Suspended)
                .is_ok()
        );
    }

    /// An active organization asks to leave. It may be closed straight away,
    /// without being suspended first.
    #[test]
    fn active_to_closed() {
        assert!(
            OrganizationStatus::Active
                .try_transition(OrganizationStatus::Closed)
                .is_ok()
        );
    }

    /// A suspended organization pays its bill. It may be made active again.
    #[test]
    fn suspended_to_active() {
        assert!(
            OrganizationStatus::Suspended
                .try_transition(OrganizationStatus::Active)
                .is_ok()
        );
    }

    /// A suspended organization never pays. It may be closed.
    #[test]
    fn suspended_to_closed() {
        assert!(
            OrganizationStatus::Suspended
                .try_transition(OrganizationStatus::Closed)
                .is_ok()
        );
    }

    /// A closed organization is asked to become active, suspended or closed
    /// again. Every move is refused, so a closed organization never reopens.
    #[test]
    fn closed_is_terminal() {
        for to in [
            OrganizationStatus::Active,
            OrganizationStatus::Suspended,
            OrganizationStatus::Closed,
        ] {
            assert!(OrganizationStatus::Closed.try_transition(to).is_err());
        }
    }

    /// An active organization is activated, or a suspended one suspended.
    /// Both are refused, so no record claims a change that did not happen.
    #[test]
    fn no_self_transitions() {
        assert!(
            OrganizationStatus::Active
                .try_transition(OrganizationStatus::Active)
                .is_err()
        );
        assert!(
            OrganizationStatus::Suspended
                .try_transition(OrganizationStatus::Suspended)
                .is_err()
        );
    }
}

use std::fmt;

use crate::types::Joining;

/// Org user lifecycle state.
///
/// ```text
/// Invited ─────────────→ Active ←──→ Locked
/// PendingVerification ──↗   ↕
///                     Deactivated
/// ```
///
/// `Invited`, `PendingVerification` and `Locked` can also go straight to
/// `Deactivated`. A deactivated account goes back to `Invited` when someone
/// invites its address again. An active member goes to `Closing` when their
/// erasure is asked for, and back to `Active` if it is cancelled; a closing
/// member may also be deactivated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OrgUserStatus {
    /// Invited but has not yet accepted. Cannot log in.
    Invited,

    /// Created with an address nobody has vouched for. Cannot log in until
    /// the user follows the verification link, which activates the account.
    PendingVerification,

    /// Fully operational. Can authenticate and manage tenants.
    Active,

    /// Blocked after too many failed sign-ins, or by an admin. Can be
    /// unlocked.
    Locked,

    /// Disabled. Cannot log in. Can be reactivated.
    Deactivated,

    /// Waiting to be erased. Cannot log in, so an account due to be deleted
    /// is not used meanwhile. Active again if the erasure is cancelled.
    Closing,
}

/// A refused org user status change.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("cannot transition org user from {from} to {to}")]
pub struct InvalidOrgUserTransition {
    /// The current status.
    pub from: OrgUserStatus,
    /// The attempted target status.
    pub to: OrgUserStatus,
}

impl OrgUserStatus {
    /// The stable name the store and the audit record carry, and a list
    /// sorted by status orders by.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Invited => "invited",
            Self::PendingVerification => "pending_verification",
            Self::Active => "active",
            Self::Locked => "locked",
            Self::Deactivated => "deactivated",
            Self::Closing => "closing",
        }
    }

    /// Whether a user in this status may sign in. Only `Active` may.
    #[must_use]
    pub fn can_authenticate(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Every status this one can move to.
    #[must_use]
    pub fn allowed_transitions(&self) -> &'static [OrgUserStatus] {
        match self {
            Self::Invited | Self::PendingVerification | Self::Locked => {
                &[Self::Active, Self::Deactivated]
            }
            Self::Active => &[Self::Locked, Self::Deactivated, Self::Closing],
            Self::Deactivated => &[Self::Active, Self::Invited],
            Self::Closing => &[Self::Active, Self::Deactivated],
        }
    }

    /// Whether a member in this status may have `joining` as their join
    /// record.
    ///
    /// One still waiting to confirm their address has none. One active,
    /// locked or closing has been active, so it has one. A deactivated
    /// member may have been either, and so may an invited one, who may be an
    /// account that joined, was closed and was invited again.
    #[must_use]
    pub fn fits(self, joining: Joining) -> bool {
        match self {
            Self::PendingVerification => joining == Joining::NotYet,
            Self::Active | Self::Locked | Self::Closing => joining != Joining::NotYet,
            Self::Invited | Self::Deactivated => true,
        }
    }

    /// Whether this status can move to `target`.
    #[must_use]
    pub fn can_transition_to(&self, target: OrgUserStatus) -> bool {
        self.allowed_transitions().contains(&target)
    }

    /// Moves to `to` when this status allows it.
    ///
    /// # Errors
    ///
    /// - [`InvalidOrgUserTransition`] when `to` is not in
    ///   [`allowed_transitions`](Self::allowed_transitions).
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidOrgUserTransition> {
        if !self.can_transition_to(to) {
            return Err(InvalidOrgUserTransition { from: self, to });
        }
        Ok(to)
    }
}

impl fmt::Display for OrgUserStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invited => f.write_str("Invited"),
            Self::PendingVerification => f.write_str("PendingVerification"),
            Self::Active => f.write_str("Active"),
            Self::Locked => f.write_str("Locked"),
            Self::Deactivated => f.write_str("Deactivated"),
            Self::Closing => f.write_str("Closing"),
        }
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidOrgUserTransition);

#[cfg(test)]
mod tests {
    use super::*;

    /// Each status is asked whether it may sign in. Only active says yes, so
    /// an invited, unverified, locked or deactivated member is kept out.
    #[test]
    fn only_active_can_authenticate() {
        assert!(OrgUserStatus::Active.can_authenticate());
        assert!(!OrgUserStatus::Invited.can_authenticate());
        assert!(!OrgUserStatus::PendingVerification.can_authenticate());
        assert!(!OrgUserStatus::Locked.can_authenticate());
        assert!(!OrgUserStatus::Deactivated.can_authenticate());
    }

    /// A member waiting to confirm their address follows the link. Moving to
    /// active is allowed.
    #[test]
    fn pending_verification_can_activate() {
        assert_eq!(
            OrgUserStatus::PendingVerification.try_transition(OrgUserStatus::Active),
            Ok(OrgUserStatus::Active)
        );
    }

    /// A member who has not confirmed their address cannot be locked, since
    /// they cannot sign in to begin with.
    #[test]
    fn pending_verification_cannot_lock() {
        assert!(
            OrgUserStatus::PendingVerification
                .try_transition(OrgUserStatus::Locked)
                .is_err()
        );
    }

    /// An invited member accepts. Moving to active is allowed.
    #[test]
    fn invited_can_activate() {
        assert_eq!(
            OrgUserStatus::Invited.try_transition(OrgUserStatus::Active),
            Ok(OrgUserStatus::Active)
        );
    }

    /// An owner deactivates someone who never accepted their invitation. That
    /// is allowed.
    #[test]
    fn invited_can_deactivate() {
        assert_eq!(
            OrgUserStatus::Invited.try_transition(OrgUserStatus::Deactivated),
            Ok(OrgUserStatus::Deactivated)
        );
    }

    /// An invited member cannot be locked, since they have never signed in.
    #[test]
    fn invited_cannot_lock() {
        assert!(
            OrgUserStatus::Invited
                .try_transition(OrgUserStatus::Locked)
                .is_err()
        );
    }

    /// An active member fails too many sign-ins. Moving to locked is allowed.
    #[test]
    fn active_can_lock() {
        assert_eq!(
            OrgUserStatus::Active.try_transition(OrgUserStatus::Locked),
            Ok(OrgUserStatus::Locked)
        );
    }

    /// An owner deactivates an active member who left. That is allowed.
    #[test]
    fn active_can_deactivate() {
        assert_eq!(
            OrgUserStatus::Active.try_transition(OrgUserStatus::Deactivated),
            Ok(OrgUserStatus::Deactivated)
        );
    }

    /// A locked member is unlocked. Moving back to active is allowed.
    #[test]
    fn locked_can_unlock() {
        assert_eq!(
            OrgUserStatus::Locked.try_transition(OrgUserStatus::Active),
            Ok(OrgUserStatus::Active)
        );
    }

    /// An owner deactivates a locked member without unlocking them first.
    /// That is allowed.
    #[test]
    fn locked_can_deactivate() {
        assert_eq!(
            OrgUserStatus::Locked.try_transition(OrgUserStatus::Deactivated),
            Ok(OrgUserStatus::Deactivated)
        );
    }

    /// A deactivated member comes back. Moving to active is allowed.
    #[test]
    fn deactivated_can_reactivate() {
        assert_eq!(
            OrgUserStatus::Deactivated.try_transition(OrgUserStatus::Active),
            Ok(OrgUserStatus::Active)
        );
    }

    /// Bob's account was closed, and an owner invites his address again.
    /// Moving back to invited is allowed, and only from deactivated: an
    /// active or locked account is never sent back to waiting.
    #[test]
    fn only_a_deactivated_member_is_invited_again() {
        assert_eq!(
            OrgUserStatus::Deactivated.try_transition(OrgUserStatus::Invited),
            Ok(OrgUserStatus::Invited)
        );
        assert!(
            OrgUserStatus::Active
                .try_transition(OrgUserStatus::Invited)
                .is_err()
        );
        assert!(
            OrgUserStatus::Locked
                .try_transition(OrgUserStatus::Invited)
                .is_err()
        );
    }

    /// Ann asks to be erased. Her account closes, cannot sign in, comes back
    /// if she cancels, and may be deactivated meanwhile. Only an active
    /// account closes, and a closing one is never locked or invited.
    #[test]
    fn an_active_member_closes_while_their_erasure_waits() {
        assert_eq!(
            OrgUserStatus::Active.try_transition(OrgUserStatus::Closing),
            Ok(OrgUserStatus::Closing)
        );
        assert!(!OrgUserStatus::Closing.can_authenticate());
        assert_eq!(
            OrgUserStatus::Closing.allowed_transitions(),
            [OrgUserStatus::Active, OrgUserStatus::Deactivated]
        );
        for from in [
            OrgUserStatus::Invited,
            OrgUserStatus::PendingVerification,
            OrgUserStatus::Locked,
            OrgUserStatus::Deactivated,
        ] {
            assert!(
                from.try_transition(OrgUserStatus::Closing).is_err(),
                "{from}"
            );
        }
        assert!(!OrgUserStatus::Closing.fits(Joining::NotYet));
    }

    /// A deactivated member cannot be locked, since they cannot sign in.
    #[test]
    fn deactivated_cannot_lock() {
        assert!(
            OrgUserStatus::Deactivated
                .try_transition(OrgUserStatus::Locked)
                .is_err()
        );
    }

    /// An active member is moved to active again. It is refused, so no record
    /// claims a change that did not happen.
    #[test]
    fn self_transition_is_rejected() {
        assert!(
            OrgUserStatus::Active
                .try_transition(OrgUserStatus::Active)
                .is_err()
        );
    }

    /// Each status prints as its variant name, such as `PendingVerification`,
    /// which is the form stored in the database.
    #[test]
    fn display_matches_db_format() {
        assert_eq!(OrgUserStatus::Invited.to_string(), "Invited");
        assert_eq!(
            OrgUserStatus::PendingVerification.to_string(),
            "PendingVerification"
        );
        assert_eq!(OrgUserStatus::Active.to_string(), "Active");
        assert_eq!(OrgUserStatus::Locked.to_string(), "Locked");
        assert_eq!(OrgUserStatus::Deactivated.to_string(), "Deactivated");
    }

    /// A deactivated member is locked, which is refused. The message names
    /// both states, "Deactivated" and "Locked".
    #[test]
    fn error_message_shows_both_states() {
        let err = OrgUserStatus::Deactivated
            .try_transition(OrgUserStatus::Locked)
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "cannot transition org user from Deactivated to Locked"
        );
    }
}

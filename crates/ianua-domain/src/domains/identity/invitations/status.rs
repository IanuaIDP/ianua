use crate::types::TokenStatus;

/// Where an invitation stands.
///
/// The allowed moves are from `Pending` to `Accepted`, `Declined`, `Expired`
/// or `Revoked`. Every other status goes nowhere.
///
/// The moves to `Declined` and `Expired` are allowed, but no domain method
/// makes them. Only accepting and revoking change the status. Expiry is
/// read from the clock, see [`InvitationLifecycle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum InvitationStatus {
    /// Sent and waiting for an answer.
    Pending,
    /// The invitee accepted.
    Accepted,
    /// The invitee said no.
    Declined,
    /// It ran out before the invitee answered.
    Expired,
    /// An admin withdrew it.
    Revoked,
}

/// What following an invitation's link gets you.
///
/// `status` alone cannot answer this. Expiry is judged against `expires_at`
/// at the moment of asking, not stored. So a row can still read `Pending`
/// long after its link has run out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum InvitationLifecycle {
    /// Unspent and in date. Following the link accepts the invitation.
    Pending,
    /// Past its expiry while storage still reads `Pending`.
    ///
    /// Nothing else is wrong with it, so a fresh one can be sent.
    Expired,
    /// Already accepted, declined or revoked.
    ///
    /// A new link cannot change that.
    Closed,
}

impl From<InvitationLifecycle> for TokenStatus {
    /// A page reading a link needs the same three answers for an invitation
    /// as for any other token.
    ///
    /// A closed invitation was accepted, declined or revoked. A new link
    /// would fix none of these, so it reads as used.
    fn from(lifecycle: InvitationLifecycle) -> Self {
        match lifecycle {
            InvitationLifecycle::Pending => Self::Valid,
            InvitationLifecycle::Expired => Self::Expired,
            InvitationLifecycle::Closed => Self::AlreadyUsed,
        }
    }
}

/// A refused invitation status change.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move an invitation from {from:?} to {to:?}")]
pub struct InvalidInvitationTransition {
    /// The current status.
    pub from: InvitationStatus,
    /// The status asked for.
    pub to: InvitationStatus,
}

impl InvitationStatus {
    /// Moves to `to`.
    ///
    /// # Errors
    ///
    /// - [`InvalidInvitationTransition`] for any move that does not start
    ///   from `Pending`, or that goes back to `Pending`.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidInvitationTransition> {
        let allowed = matches!(
            (self, to),
            (
                Self::Pending,
                Self::Accepted | Self::Declined | Self::Expired | Self::Revoked
            )
        );

        if allowed {
            Ok(to)
        } else {
            Err(InvalidInvitationTransition { from: self, to })
        }
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidInvitationTransition);

#[cfg(test)]
mod tests {
    use super::*;

    /// A pending invitation reads as a valid link and an expired one as
    /// expired. A closed one reads as already used, since an accepted,
    /// declined or revoked invitation cannot be offered again.
    #[test]
    fn every_invitation_lifecycle_has_a_status() {
        assert_eq!(
            TokenStatus::from(InvitationLifecycle::Pending),
            TokenStatus::Valid
        );
        assert_eq!(
            TokenStatus::from(InvitationLifecycle::Expired),
            TokenStatus::Expired
        );
        assert_eq!(
            TokenStatus::from(InvitationLifecycle::Closed),
            TokenStatus::AlreadyUsed
        );
    }

    /// A pending invitation may move to accepted.
    #[test]
    fn pending_can_be_accepted() {
        assert!(
            InvitationStatus::Pending
                .try_transition(InvitationStatus::Accepted)
                .is_ok()
        );
    }

    /// A pending invitation may move to declined.
    #[test]
    fn pending_can_be_declined() {
        assert!(
            InvitationStatus::Pending
                .try_transition(InvitationStatus::Declined)
                .is_ok()
        );
    }

    /// A pending invitation may move to expired.
    #[test]
    fn pending_can_expire() {
        assert!(
            InvitationStatus::Pending
                .try_transition(InvitationStatus::Expired)
                .is_ok()
        );
    }

    /// A pending invitation may be revoked by an admin.
    #[test]
    fn pending_can_be_revoked() {
        assert!(
            InvitationStatus::Pending
                .try_transition(InvitationStatus::Revoked)
                .is_ok()
        );
    }

    /// Moving pending to pending is refused, since nothing would change.
    #[test]
    fn pending_cannot_self_transition() {
        assert!(
            InvitationStatus::Pending
                .try_transition(InvitationStatus::Pending)
                .is_err()
        );
    }

    /// An accepted invitation cannot move to any status, so it cannot be
    /// reopened.
    #[test]
    fn accepted_is_terminal() {
        for to in [
            InvitationStatus::Pending,
            InvitationStatus::Accepted,
            InvitationStatus::Declined,
            InvitationStatus::Expired,
            InvitationStatus::Revoked,
        ] {
            assert!(InvitationStatus::Accepted.try_transition(to).is_err());
        }
    }

    /// A declined invitation cannot move to any status, so it cannot be
    /// accepted later.
    #[test]
    fn declined_is_terminal() {
        for to in [
            InvitationStatus::Pending,
            InvitationStatus::Accepted,
            InvitationStatus::Declined,
            InvitationStatus::Expired,
            InvitationStatus::Revoked,
        ] {
            assert!(InvitationStatus::Declined.try_transition(to).is_err());
        }
    }

    /// An expired invitation cannot move to any status. A new invitation is
    /// sent instead.
    #[test]
    fn expired_is_terminal() {
        for to in [
            InvitationStatus::Pending,
            InvitationStatus::Accepted,
            InvitationStatus::Declined,
            InvitationStatus::Expired,
            InvitationStatus::Revoked,
        ] {
            assert!(InvitationStatus::Expired.try_transition(to).is_err());
        }
    }

    /// A revoked invitation cannot move to any status, so it cannot be
    /// accepted after an admin withdrew it.
    #[test]
    fn revoked_is_terminal() {
        for to in [
            InvitationStatus::Pending,
            InvitationStatus::Accepted,
            InvitationStatus::Declined,
            InvitationStatus::Expired,
            InvitationStatus::Revoked,
        ] {
            assert!(InvitationStatus::Revoked.try_transition(to).is_err());
        }
    }
}

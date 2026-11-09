use std::fmt;

/// Where a user's account in a tenant stands.
///
/// It decides what the user may do. Every move is checked by
/// [`can_transition_to`](Self::can_transition_to).
///
/// The allowed moves:
/// - `Invited`, `PendingVerification` and `Locked` go to `Active` or
///   `Deactivated`.
/// - `Active` goes to `Locked` or `Deactivated`.
/// - `Deactivated` goes back to `Active`, when someone lets it in again.
/// - `Active` goes to `Closing` when its holder asks to be erased, and back
///   to `Active` if the request is cancelled. `Closing` may also be
///   deactivated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UserStatus {
    /// Invited, but has not verified their email or set up how they sign
    /// in. Cannot sign in.
    Invited,

    /// Registered, but the email address is not confirmed yet.
    ///
    /// The account cannot sign in until the verification link is followed.
    PendingVerification,

    /// Fully working. Can sign in and reach what the tenant allows.
    Active,

    /// Blocked for now by someone who may act on the account.
    ///
    /// The caller ends existing sessions. Unlocking moves it back to
    /// `Active`.
    Locked,

    /// Switched off. Cannot sign in until someone lets it in again. The
    /// caller ends all sessions.
    Deactivated,

    /// Waiting to be erased. Cannot sign in, so an account due to be
    /// deleted is not used meanwhile. The caller ends all sessions. It is
    /// active again if the erasure is cancelled.
    Closing,
}

/// A user status change the rules refused.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("cannot transition user from {from} to {to}")]
pub struct InvalidUserTransition {
    /// The current status.
    pub from: UserStatus,
    /// The status asked for.
    pub to: UserStatus,
}

impl UserStatus {
    /// Whether a user in this status may sign in. Only `Active` may.
    #[must_use]
    pub fn can_authenticate(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Every status this one may move to.
    #[must_use]
    pub fn allowed_transitions(&self) -> &'static [UserStatus] {
        match self {
            Self::Invited | Self::PendingVerification | Self::Locked => {
                &[Self::Active, Self::Deactivated]
            }
            Self::Active => &[Self::Locked, Self::Deactivated, Self::Closing],
            Self::Deactivated => &[Self::Active],
            Self::Closing => &[Self::Active, Self::Deactivated],
        }
    }

    /// Whether this status may move to `target`.
    #[must_use]
    pub fn can_transition_to(&self, target: UserStatus) -> bool {
        self.allowed_transitions().contains(&target)
    }

    /// Moves to `to`.
    ///
    /// # Errors
    ///
    /// - [`InvalidUserTransition`] when `to` is not one of
    ///   [`allowed_transitions`](Self::allowed_transitions).
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidUserTransition> {
        if !self.can_transition_to(to) {
            return Err(InvalidUserTransition { from: self, to });
        }
        Ok(to)
    }
}

impl fmt::Display for UserStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invited => f.write_str("invited"),
            Self::PendingVerification => f.write_str("pending_verification"),
            Self::Active => f.write_str("active"),
            Self::Locked => f.write_str("locked"),
            Self::Deactivated => f.write_str("deactivated"),
            Self::Closing => f.write_str("closing"),
        }
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidUserTransition);

#[cfg(test)]
mod tests {
    use super::*;

    /// Active may sign in. Invited, locked and deactivated may not.
    #[test]
    fn only_active_can_authenticate() {
        assert!(UserStatus::Active.can_authenticate());
        assert!(!UserStatus::Invited.can_authenticate());
        assert!(!UserStatus::Locked.can_authenticate());
        assert!(!UserStatus::Deactivated.can_authenticate());
    }

    /// An invited account may move to active when the person accepts.
    #[test]
    fn invited_can_activate() {
        assert_eq!(
            UserStatus::Invited.try_transition(UserStatus::Active),
            Ok(UserStatus::Active)
        );
    }

    /// An invited account may be switched off before the person accepts.
    #[test]
    fn invited_can_deactivate() {
        assert_eq!(
            UserStatus::Invited.try_transition(UserStatus::Deactivated),
            Ok(UserStatus::Deactivated)
        );
    }

    /// An active account may be locked, as after too many failed sign-ins.
    #[test]
    fn active_can_lock() {
        assert_eq!(
            UserStatus::Active.try_transition(UserStatus::Locked),
            Ok(UserStatus::Locked)
        );
    }

    /// An active account may be switched off.
    #[test]
    fn active_can_deactivate() {
        assert_eq!(
            UserStatus::Active.try_transition(UserStatus::Deactivated),
            Ok(UserStatus::Deactivated)
        );
    }

    /// A locked account may go back to active when it is unlocked.
    #[test]
    fn locked_can_unlock() {
        assert_eq!(
            UserStatus::Locked.try_transition(UserStatus::Active),
            Ok(UserStatus::Active)
        );
    }

    /// A locked account may be switched off without unlocking it first.
    #[test]
    fn locked_can_deactivate() {
        assert_eq!(
            UserStatus::Locked.try_transition(UserStatus::Deactivated),
            Ok(UserStatus::Deactivated)
        );
    }

    /// An invited account cannot be locked. Only an active one can.
    #[test]
    fn invited_cannot_lock() {
        assert!(
            UserStatus::Invited
                .try_transition(UserStatus::Locked)
                .is_err()
        );
    }

    /// An active account cannot be sent back to invited.
    #[test]
    fn active_cannot_return_to_invited() {
        assert!(
            UserStatus::Active
                .try_transition(UserStatus::Invited)
                .is_err()
        );
    }

    /// A deactivated account switched off by mistake may be made active
    /// again. It cannot move to invited or locked, since it never signs in
    /// until it is let back in.
    #[test]
    fn deactivated_only_comes_back_to_active() {
        assert_eq!(
            UserStatus::Deactivated.try_transition(UserStatus::Active),
            Ok(UserStatus::Active)
        );
        assert!(
            UserStatus::Deactivated
                .try_transition(UserStatus::Invited)
                .is_err()
        );
        assert!(
            UserStatus::Deactivated
                .try_transition(UserStatus::Locked)
                .is_err()
        );
    }

    /// Moving active to active, or locked to locked, is refused. A move must
    /// change something.
    #[test]
    fn self_transition_is_rejected() {
        assert!(
            UserStatus::Active
                .try_transition(UserStatus::Active)
                .is_err()
        );
        assert!(
            UserStatus::Locked
                .try_transition(UserStatus::Locked)
                .is_err()
        );
    }

    /// The one move out of deactivated is back to active, so a screen offers
    /// only that.
    #[test]
    fn deactivated_offers_only_reactivation() {
        assert_eq!(
            UserStatus::Deactivated.allowed_transitions(),
            &[UserStatus::Active]
        );
    }

    /// Each status prints as one lowercase word, such as "invited" or
    /// "locked".
    #[test]
    fn display_is_lowercase() {
        assert_eq!(UserStatus::Invited.to_string(), "invited");
        assert_eq!(UserStatus::Active.to_string(), "active");
        assert_eq!(UserStatus::Locked.to_string(), "locked");
        assert_eq!(UserStatus::Deactivated.to_string(), "deactivated");
    }

    /// A refused move from active to invited says both statuses in its
    /// message.
    #[test]
    fn error_message_shows_both_states() {
        let err = UserStatus::Active
            .try_transition(UserStatus::Invited)
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "cannot transition user from active to invited"
        );
    }

    /// A refused move from deactivated to locked reads exactly "cannot
    /// transition user from deactivated to locked". Callers show it to
    /// people, so the wording is fixed.
    #[test]
    fn the_refusal_message_is_unchanged() {
        let refusal = UserStatus::Deactivated
            .try_transition(UserStatus::Locked)
            .unwrap_err();

        assert_eq!(
            refusal.to_string(),
            "cannot transition user from deactivated to locked"
        );
    }

    /// An active account closes for erasure and comes back if the request
    /// is cancelled, or is deactivated. A closing account cannot sign in or
    /// be locked.
    #[test]
    fn a_closing_account_waits_for_its_erasure() {
        assert!(UserStatus::Active.can_transition_to(UserStatus::Closing));
        assert_eq!(
            UserStatus::Closing.allowed_transitions(),
            &[UserStatus::Active, UserStatus::Deactivated]
        );
        assert!(!UserStatus::Closing.can_authenticate());
        assert!(!UserStatus::Closing.can_transition_to(UserStatus::Locked));
    }
}

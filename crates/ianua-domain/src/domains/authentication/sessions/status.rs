/// Lifecycle status of an authentication session.
///
/// Valid transitions:
/// - `Active` → `Suspended`, on a binding violation or a rise in risk.
/// - `Active` → `Revoked`, on logout, an admin action or token theft.
/// - `Suspended` → `Active`, when the user proves a second factor again.
/// - `Suspended` → `Revoked`, on an admin action or a timeout.
///
/// Expiry is not a status. It follows from `expires_at`, so a session can be
/// `Active` and expired at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SessionStatus {
    /// Session is valid and accepting requests.
    Active,

    /// Session is paused after a binding violation or a rise in risk. The
    /// user must prove a second factor again to go on.
    Suspended,

    /// Session has ended for good and cannot be made active again.
    Revoked,
}

/// Rejected session status transition.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move a session from {from:?} to {to:?}")]
pub struct InvalidSessionTransition {
    /// The current state.
    pub from: SessionStatus,
    /// The attempted target state.
    pub to: SessionStatus,
}

impl SessionStatus {
    /// Moves to `to` when the transition is allowed.
    ///
    /// # Errors
    ///
    /// - [`InvalidSessionTransition`] when the transition is not allowed.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidSessionTransition> {
        let allowed = matches!(
            (self, to),
            (Self::Active, Self::Suspended | Self::Revoked)
                | (Self::Suspended, Self::Active | Self::Revoked)
        );

        if allowed {
            Ok(to)
        } else {
            Err(InvalidSessionTransition { from: self, to })
        }
    }

    /// Whether this session can accept requests.
    #[must_use]
    pub fn is_active(&self) -> bool {
        *self == Self::Active
    }

    /// Whether this session is paused until the user proves a factor again.
    #[must_use]
    pub fn is_suspended(&self) -> bool {
        *self == Self::Suspended
    }

    /// Whether this session has ended for good.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        *self == Self::Revoked
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidSessionTransition);

#[cfg(test)]
mod tests {
    use super::*;

    /// Each status answers yes to its own question only. A revoked session
    /// that also answered "active" would keep working after logout.
    #[test]
    fn each_predicate_answers_for_exactly_the_states_it_names() {
        let cases = [
            (SessionStatus::Active, (true, false, false)),
            (SessionStatus::Suspended, (false, true, false)),
            (SessionStatus::Revoked, (false, false, true)),
        ];

        for (status, (active, suspended, revoked)) in cases {
            assert_eq!(status.is_active(), active, "{status:?}");
            assert_eq!(status.is_suspended(), suspended, "{status:?}");
            assert_eq!(status.is_revoked(), revoked, "{status:?}");
        }
    }

    /// Ann's session sees a request that breaks its binding. An active
    /// session may be suspended.
    #[test]
    fn active_to_suspended() {
        assert!(
            SessionStatus::Active
                .try_transition(SessionStatus::Suspended)
                .is_ok()
        );
    }

    /// Ann logs out. An active session may be revoked.
    #[test]
    fn active_to_revoked() {
        assert!(
            SessionStatus::Active
                .try_transition(SessionStatus::Revoked)
                .is_ok()
        );
    }

    /// Ann proves herself again after a suspension. A suspended session may
    /// become active.
    #[test]
    fn suspended_to_active() {
        assert!(
            SessionStatus::Suspended
                .try_transition(SessionStatus::Active)
                .is_ok()
        );
    }

    /// An admin ends Ann's suspended session. A suspended session may be
    /// revoked.
    #[test]
    fn suspended_to_revoked() {
        assert!(
            SessionStatus::Suspended
                .try_transition(SessionStatus::Revoked)
                .is_ok()
        );
    }

    /// Revocation is terminal: transitions to active, suspended and revoked
    /// are all rejected.
    #[test]
    fn revoked_is_terminal() {
        for to in [
            SessionStatus::Active,
            SessionStatus::Suspended,
            SessionStatus::Revoked,
        ] {
            assert!(SessionStatus::Revoked.try_transition(to).is_err());
        }
    }

    /// Moving active to active, or suspended to suspended, is refused, so a
    /// no-op is never recorded as a change.
    #[test]
    fn no_self_transitions() {
        assert!(
            SessionStatus::Active
                .try_transition(SessionStatus::Active)
                .is_err()
        );
        assert!(
            SessionStatus::Suspended
                .try_transition(SessionStatus::Suspended)
                .is_err()
        );
    }

    /// An active session is active and neither suspended nor revoked.
    #[test]
    fn active_is_active() {
        assert!(SessionStatus::Active.is_active());
        assert!(!SessionStatus::Active.is_suspended());
        assert!(!SessionStatus::Active.is_revoked());
    }

    /// A suspended session is suspended and neither active nor revoked.
    #[test]
    fn suspended_is_suspended() {
        assert!(!SessionStatus::Suspended.is_active());
        assert!(SessionStatus::Suspended.is_suspended());
        assert!(!SessionStatus::Suspended.is_revoked());
    }

    /// A revoked session is revoked and neither active nor suspended.
    #[test]
    fn revoked_is_revoked() {
        assert!(!SessionStatus::Revoked.is_active());
        assert!(!SessionStatus::Revoked.is_suspended());
        assert!(SessionStatus::Revoked.is_revoked());
    }

    /// Each status is written as `"Active"`, `"Suspended"` or `"Revoked"` and
    /// read back from the same text. Renaming a variant fails here instead of
    /// breaking saved sessions.
    #[cfg(feature = "serde")]
    #[test]
    fn session_status_is_stored_under_its_variant_name() {
        assert_eq!(
            serde_json::to_string(&SessionStatus::Active).unwrap(),
            r#""Active""#
        );
        assert_eq!(
            serde_json::to_string(&SessionStatus::Suspended).unwrap(),
            r#""Suspended""#
        );
        assert_eq!(
            serde_json::to_string(&SessionStatus::Revoked).unwrap(),
            r#""Revoked""#
        );
        assert_eq!(
            serde_json::from_str::<SessionStatus>(r#""Active""#).unwrap(),
            SessionStatus::Active
        );
        assert_eq!(
            serde_json::from_str::<SessionStatus>(r#""Suspended""#).unwrap(),
            SessionStatus::Suspended
        );
        assert_eq!(
            serde_json::from_str::<SessionStatus>(r#""Revoked""#).unwrap(),
            SessionStatus::Revoked
        );
    }
}

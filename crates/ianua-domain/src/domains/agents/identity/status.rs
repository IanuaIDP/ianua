/// Where an agent identity stands.
///
/// Allowed moves:
/// - `Active` → `Suspended`, which can be undone.
/// - `Suspended` → `Active`, a resume.
/// - `Active` → `Revoked`, which is permanent.
/// - `Suspended` → `Revoked`, which is permanent.
///
/// `Revoked` is final. To act again, the agent must be created anew.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AgentStatus {
    /// Active and able to hold delegations.
    Active,

    /// Suspended for now. No delegation works until it is resumed.
    Suspended,

    /// Revoked for good. Nothing moves it out of this state.
    Revoked,
}

/// A refused move between two agent states.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move an agent from {from:?} to {to:?}")]
pub struct InvalidAgentTransition {
    /// The current state.
    pub from: AgentStatus,
    /// The attempted target state.
    pub to: AgentStatus,
}

impl AgentStatus {
    /// Moves to `to` when the move is allowed.
    ///
    /// # Errors
    ///
    /// - [`InvalidAgentTransition`] when the move is not in the list on
    ///   [`AgentStatus`].
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidAgentTransition> {
        let allowed = matches!(
            (self, to),
            (Self::Active, Self::Suspended)
                | (Self::Suspended, Self::Active)
                | (Self::Active, Self::Revoked)
                | (Self::Suspended, Self::Revoked)
        );

        if allowed {
            Ok(to)
        } else {
            Err(InvalidAgentTransition { from: self, to })
        }
    }

    /// Whether the agent is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        *self == Self::Active
    }

    /// Whether the agent is suspended.
    #[must_use]
    pub fn is_suspended(&self) -> bool {
        *self == Self::Suspended
    }

    /// Whether the agent is revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        *self == Self::Revoked
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidAgentTransition);

#[cfg(test)]
mod tests {
    use super::*;

    /// Each of the three states answers yes to its own question only. If
    /// `is_active` said yes for a suspended agent, every check built on it
    /// would let that agent act.
    #[test]
    fn each_predicate_answers_for_exactly_the_states_it_names() {
        let cases = [
            (AgentStatus::Active, (true, false, false)),
            (AgentStatus::Suspended, (false, true, false)),
            (AgentStatus::Revoked, (false, false, true)),
        ];

        for (status, (active, suspended, revoked)) in cases {
            assert_eq!(status.is_active(), active, "{status:?}");
            assert_eq!(status.is_suspended(), suspended, "{status:?}");
            assert_eq!(status.is_revoked(), revoked, "{status:?}");
        }
    }

    /// An active agent may be suspended, and may be revoked.
    #[test]
    fn active_can_suspend_and_revoke() {
        assert!(
            AgentStatus::Active
                .try_transition(AgentStatus::Suspended)
                .is_ok()
        );
        assert!(
            AgentStatus::Active
                .try_transition(AgentStatus::Revoked)
                .is_ok()
        );
    }

    /// A suspended agent may be resumed to active, and may be revoked.
    #[test]
    fn suspended_can_resume_and_revoke() {
        assert!(
            AgentStatus::Suspended
                .try_transition(AgentStatus::Active)
                .is_ok()
        );
        assert!(
            AgentStatus::Suspended
                .try_transition(AgentStatus::Revoked)
                .is_ok()
        );
    }

    /// A revoked agent cannot move to active, suspended or revoked again. A
    /// revocation is never undone.
    #[test]
    fn revoked_is_terminal() {
        for to in [
            AgentStatus::Active,
            AgentStatus::Suspended,
            AgentStatus::Revoked,
        ] {
            assert!(AgentStatus::Revoked.try_transition(to).is_err());
        }
    }

    /// Suspending a suspended agent, or activating an active one, is refused.
    #[test]
    fn no_self_transitions() {
        for status in [AgentStatus::Active, AgentStatus::Suspended] {
            assert!(status.try_transition(status).is_err());
        }
    }

    /// Each status is written to JSON as its variant name and reads back from
    /// it. Renaming a variant fails here instead of breaking saved data.
    #[cfg(feature = "serde")]
    #[test]
    fn agent_status_is_stored_under_its_variant_name() {
        assert_eq!(
            serde_json::to_string(&AgentStatus::Active).unwrap(),
            r#""Active""#
        );
        assert_eq!(
            serde_json::to_string(&AgentStatus::Suspended).unwrap(),
            r#""Suspended""#
        );
        assert_eq!(
            serde_json::to_string(&AgentStatus::Revoked).unwrap(),
            r#""Revoked""#
        );
        assert_eq!(
            serde_json::from_str::<AgentStatus>(r#""Active""#).unwrap(),
            AgentStatus::Active
        );
        assert_eq!(
            serde_json::from_str::<AgentStatus>(r#""Suspended""#).unwrap(),
            AgentStatus::Suspended
        );
        assert_eq!(
            serde_json::from_str::<AgentStatus>(r#""Revoked""#).unwrap(),
            AgentStatus::Revoked
        );
    }
}

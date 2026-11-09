/// Whether a connection to an external `IdP` can be used.
///
/// A tenant admin switches a connection between `Active` and `Disabled`,
/// either way, for example during a security incident. A move to the state
/// it is already in is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ConnectionStatus {
    /// The connection works. Users can sign in through it.
    Active,

    /// A tenant admin turned the connection off. Users cannot sign in
    /// through it until it is turned back on.
    Disabled,
}

/// Rejected connection status transition.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move a federation connection from {from:?} to {to:?}")]
pub struct InvalidConnectionTransition {
    /// The current state.
    pub from: ConnectionStatus,
    /// The attempted target state.
    pub to: ConnectionStatus,
}

impl ConnectionStatus {
    /// Attempts a state transition.
    ///
    /// # Errors
    ///
    /// - [`InvalidConnectionTransition`] when `to` is the current state.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidConnectionTransition> {
        let allowed = matches!(
            (self, to),
            (Self::Active, Self::Disabled) | (Self::Disabled, Self::Active)
        );

        if allowed {
            Ok(to)
        } else {
            Err(InvalidConnectionTransition { from: self, to })
        }
    }

    /// Whether this connection is operational.
    #[must_use]
    pub fn is_active(&self) -> bool {
        *self == Self::Active
    }

    /// Whether this connection is disabled.
    #[must_use]
    pub fn is_disabled(&self) -> bool {
        *self == Self::Disabled
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidConnectionTransition);

#[cfg(test)]
mod tests {
    use super::*;

    /// Each status is asked whether it is active and whether it is disabled.
    /// Each answers yes only for itself, since a wrong yes would let a
    /// disabled connection pass every check built on it.
    #[test]
    fn each_predicate_answers_for_exactly_the_states_it_names() {
        let cases = [
            (ConnectionStatus::Active, (true, false)),
            (ConnectionStatus::Disabled, (false, true)),
        ];

        for (status, (active, disabled)) in cases {
            assert_eq!(status.is_active(), active, "{status:?}");
            assert_eq!(status.is_disabled(), disabled, "{status:?}");
        }
    }

    /// An admin turns off a working connection during an incident. The move
    /// from active to disabled is allowed.
    #[test]
    fn active_to_disabled() {
        assert!(
            ConnectionStatus::Active
                .try_transition(ConnectionStatus::Disabled)
                .is_ok()
        );
    }

    /// An admin turns a disabled connection back on. The move from disabled
    /// to active is allowed.
    #[test]
    fn disabled_to_active() {
        assert!(
            ConnectionStatus::Disabled
                .try_transition(ConnectionStatus::Active)
                .is_ok()
        );
    }

    /// An admin disables a connection that is already disabled, or activates
    /// one already active. Both are refused, so the caller learns nothing changed.
    #[test]
    fn no_self_transitions() {
        assert!(
            ConnectionStatus::Active
                .try_transition(ConnectionStatus::Active)
                .is_err()
        );
        assert!(
            ConnectionStatus::Disabled
                .try_transition(ConnectionStatus::Disabled)
                .is_err()
        );
    }

    /// Each status is written as `"Active"` or `"Disabled"` and read back. A
    /// renamed variant fails here instead of breaking rows already saved.
    #[cfg(feature = "serde")]
    #[test]
    fn connection_status_is_stored_under_its_variant_name() {
        assert_eq!(
            serde_json::to_string(&ConnectionStatus::Active).unwrap(),
            r#""Active""#
        );
        assert_eq!(
            serde_json::to_string(&ConnectionStatus::Disabled).unwrap(),
            r#""Disabled""#
        );
        assert_eq!(
            serde_json::from_str::<ConnectionStatus>(r#""Active""#).unwrap(),
            ConnectionStatus::Active
        );
        assert_eq!(
            serde_json::from_str::<ConnectionStatus>(r#""Disabled""#).unwrap(),
            ConnectionStatus::Disabled
        );
    }
}

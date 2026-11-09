/// Operational status of a platform operator account.
///
/// An admin can disable an active operator and re-enable a disabled one.
/// No other move is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OperatorStatus {
    /// Operator can log in and perform platform actions.
    Active,
    /// Operator account has been disabled.
    Disabled,
}

/// Rejected operator status transition.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move an operator from {from:?} to {to:?}")]
pub struct InvalidOperatorTransition {
    /// The current state.
    pub from: OperatorStatus,
    /// The attempted target state.
    pub to: OperatorStatus,
}

impl OperatorStatus {
    /// Gives the new status when moving from `self` to `to` is allowed.
    ///
    /// # Errors
    ///
    /// - [`InvalidOperatorTransition`] when the move is not allowed, including
    ///   a move to the same status.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidOperatorTransition> {
        let allowed = matches!(
            (self, to),
            (Self::Active, Self::Disabled) | (Self::Disabled, Self::Active)
        );

        if allowed {
            Ok(to)
        } else {
            Err(InvalidOperatorTransition { from: self, to })
        }
    }

    /// Whether this operator is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        *self == Self::Active
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidOperatorTransition);

#[cfg(test)]
mod tests {
    use super::*;

    /// `Active` reads as active and `Disabled` does not.
    #[test]
    fn only_the_active_state_reads_as_active() {
        assert!(OperatorStatus::Active.is_active());
        assert!(!OperatorStatus::Disabled.is_active());
    }

    /// An admin disables an active operator. The move is allowed.
    #[test]
    fn active_to_disabled() {
        assert!(
            OperatorStatus::Active
                .try_transition(OperatorStatus::Disabled)
                .is_ok()
        );
    }

    /// An admin re-enables a disabled operator. The move is allowed.
    #[test]
    fn disabled_to_active() {
        assert!(
            OperatorStatus::Disabled
                .try_transition(OperatorStatus::Active)
                .is_ok()
        );
    }

    /// Disabling a disabled operator or enabling an active one is refused,
    /// so a repeated click does not record a change that never happened.
    #[test]
    fn no_self_transitions() {
        assert!(
            OperatorStatus::Active
                .try_transition(OperatorStatus::Active)
                .is_err()
        );
        assert!(
            OperatorStatus::Disabled
                .try_transition(OperatorStatus::Disabled)
                .is_err()
        );
    }

    /// Each status is written as `"Active"` or `"Disabled"` and read back
    /// from the same text. Renaming a variant fails here before it breaks
    /// stored rows.
    #[cfg(feature = "serde")]
    #[test]
    fn operator_status_is_stored_under_its_variant_name() {
        assert_eq!(
            serde_json::to_string(&OperatorStatus::Active).unwrap(),
            r#""Active""#
        );
        assert_eq!(
            serde_json::to_string(&OperatorStatus::Disabled).unwrap(),
            r#""Disabled""#
        );
        assert_eq!(
            serde_json::from_str::<OperatorStatus>(r#""Active""#).unwrap(),
            OperatorStatus::Active
        );
        assert_eq!(
            serde_json::from_str::<OperatorStatus>(r#""Disabled""#).unwrap(),
            OperatorStatus::Disabled
        );
    }
}

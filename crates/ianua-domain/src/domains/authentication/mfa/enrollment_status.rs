/// The lifecycle state of an MFA enrollment.
///
/// Valid transitions:
/// - `Pending` → `Verified`, when the user confirms with a valid code.
/// - `Pending` → `Disabled`, when setup is abandoned before it is confirmed.
/// - `Verified` → `Disabled`, when the user or an admin turns MFA off.
/// - `Disabled` → `Pending`, when the user enrolls again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MfaEnrollmentStatus {
    /// The user started enrollment but has not confirmed it with a valid
    /// code.
    Pending,
    /// The user confirmed enrollment with a valid code. MFA is active for
    /// this user.
    Verified,
    /// MFA is off. Either setup was abandoned or MFA was turned off.
    Disabled,
}

/// Rejected transition between MFA enrollment states.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move an MFA enrollment from {from:?} to {to:?}")]
pub struct InvalidMfaTransition {
    /// The current state.
    pub from: MfaEnrollmentStatus,
    /// The attempted target state.
    pub to: MfaEnrollmentStatus,
}

impl MfaEnrollmentStatus {
    /// Moves to `to` when the transition is allowed.
    ///
    /// # Errors
    ///
    /// - [`InvalidMfaTransition`] when the transition is not allowed.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidMfaTransition> {
        let allowed = matches!(
            (self, to),
            (Self::Pending, Self::Verified)
                | (Self::Pending, Self::Disabled)
                | (Self::Verified, Self::Disabled)
                | (Self::Disabled, Self::Pending)
        );

        if allowed {
            Ok(to)
        } else {
            Err(InvalidMfaTransition { from: self, to })
        }
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidMfaTransition);

#[cfg(test)]
mod tests {
    use super::*;

    /// Ann scans the QR code and types a correct code. Her pending enrollment
    /// becomes verified.
    #[test]
    fn pending_to_verified() {
        assert!(
            MfaEnrollmentStatus::Pending
                .try_transition(MfaEnrollmentStatus::Verified)
                .is_ok()
        );
    }

    /// An admin turns off Ann's working MFA. A verified enrollment may become
    /// disabled.
    #[test]
    fn verified_to_disabled() {
        assert!(
            MfaEnrollmentStatus::Verified
                .try_transition(MfaEnrollmentStatus::Disabled)
                .is_ok()
        );
    }

    /// Ann had MFA turned off and starts setup again. A disabled enrollment
    /// may go back to pending.
    #[test]
    fn disabled_to_pending_re_enroll() {
        assert!(
            MfaEnrollmentStatus::Disabled
                .try_transition(MfaEnrollmentStatus::Pending)
                .is_ok()
        );
    }

    /// Ann starts setup and never types a code. A pending enrollment may be
    /// disabled without ever being verified.
    #[test]
    fn pending_can_be_abandoned() {
        assert!(
            MfaEnrollmentStatus::Pending
                .try_transition(MfaEnrollmentStatus::Disabled)
                .is_ok()
        );
    }

    /// A verified enrollment cannot drop back to pending. Starting over means
    /// turning it off first.
    #[test]
    fn verified_cannot_go_back_to_pending() {
        assert!(
            MfaEnrollmentStatus::Verified
                .try_transition(MfaEnrollmentStatus::Pending)
                .is_err()
        );
    }

    /// Moving pending to pending, verified to verified or disabled to
    /// disabled is refused, so a no-op is never recorded as a change.
    #[test]
    fn no_self_transitions() {
        assert!(
            MfaEnrollmentStatus::Pending
                .try_transition(MfaEnrollmentStatus::Pending)
                .is_err()
        );
        assert!(
            MfaEnrollmentStatus::Verified
                .try_transition(MfaEnrollmentStatus::Verified)
                .is_err()
        );
        assert!(
            MfaEnrollmentStatus::Disabled
                .try_transition(MfaEnrollmentStatus::Disabled)
                .is_err()
        );
    }

    /// A disabled enrollment cannot jump straight to verified. It goes
    /// through pending and a confirming code first, so MFA never turns back
    /// on unchecked.
    #[test]
    fn disabled_cannot_skip_to_verified() {
        assert!(
            MfaEnrollmentStatus::Disabled
                .try_transition(MfaEnrollmentStatus::Verified)
                .is_err()
        );
    }
}

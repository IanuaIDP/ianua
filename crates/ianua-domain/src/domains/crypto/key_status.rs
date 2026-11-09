use crate::shared::errors::DomainError;
use crate::types::{Expiry, Lifetime};

/// Lifecycle status of a signing key.
///
/// Valid transitions:
/// - `Active` → `Rotated`, when a new key takes over. The old key stays for
///   verification.
/// - `Active` → `Revoked`, in an emergency.
/// - `Rotated` → `Revoked`, when the grace period is over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum KeyStatus {
    /// The key signs new tokens.
    Active,
    /// The key has been rotated out. It stays in the JWKS so tokens it
    /// signed still verify during the grace period.
    Rotated,
    /// The key is revoked for good and gone from the JWKS.
    Revoked,
}

/// Where a key stands, with the time it was rotated out if it was.
///
/// It is one value, not a status beside an optional time. So a rotated key
/// always says when it stopped signing. A rotated key with no rotation time
/// could never finish its grace period, or would verify everything it ever
/// signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// Signs new tokens.
    Active,
    /// Rotated out at `at`. It still verifies what it signed before then.
    Rotated {
        /// When it stopped signing.
        at: time::OffsetDateTime,
    },
    /// Out of service. It verifies nothing.
    Revoked {
        /// Whether it had been rotated out first, kept for the record.
        before: PriorRotation,
    },
}

/// Whether a revoked key had been rotated out before it was revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorRotation {
    /// Revoked straight from active.
    NotRotated,
    /// Rotated out at this instant first.
    RotatedAt(time::OffsetDateTime),
}

impl KeyState {
    /// The status label this state carries.
    #[must_use]
    pub fn status(self) -> KeyStatus {
        match self {
            Self::Active => KeyStatus::Active,
            Self::Rotated { .. } => KeyStatus::Rotated,
            Self::Revoked { .. } => KeyStatus::Revoked,
        }
    }

    /// This key revoked now, keeping when it was rotated if it was.
    #[must_use]
    pub fn revoked(self) -> Self {
        let before = match self {
            Self::Rotated { at } => PriorRotation::RotatedAt(at),
            Self::Revoked { before } => before,
            Self::Active => PriorRotation::NotRotated,
        };
        Self::Revoked { before }
    }

    /// Reads a state back from its stored status and rotation time. A
    /// revoked key may have been rotated first, and keeps that time.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when a rotated key has no rotation
    ///   time.
    /// - [`DomainError::Infrastructure`] when an active key has one.
    pub fn from_stored(
        status: KeyStatus,
        rotated_at: Option<time::OffsetDateTime>,
    ) -> Result<Self, DomainError> {
        match (status, rotated_at) {
            (KeyStatus::Active, None) => Ok(Self::Active),
            (KeyStatus::Rotated, Some(at)) => Ok(Self::Rotated { at }),
            (KeyStatus::Revoked, None) => Ok(Self::Revoked {
                before: PriorRotation::NotRotated,
            }),
            (KeyStatus::Revoked, Some(at)) => Ok(Self::Revoked {
                before: PriorRotation::RotatedAt(at),
            }),
            (status, _) => Err(DomainError::infra_msg(format!(
                "stored {status:?} key has a rotation time that contradicts it"
            ))),
        }
    }

    /// Whether the JWKS publishes, at `now`, a key in this state that stops
    /// signing at `expires_at`: whether a verifier may still accept the
    /// tokens it signed.
    ///
    /// A key stops signing when it is rotated out or when it expires. Either
    /// way it stays published for `grace` after that, so tokens it signed
    /// just before have time to run out, and no longer. A revoked key never
    /// is. This is judged from the clock, not from whether a job has since
    /// rotated or revoked the key, so a key a failed job left behind is not
    /// published forever.
    #[must_use]
    pub fn is_published(
        self,
        expires_at: Expiry,
        grace: Lifetime,
        now: time::OffsetDateTime,
    ) -> bool {
        match self {
            Self::Active => expires_at
                .instant()
                .is_none_or(|expiry| now < grace.ends_after(expiry)),
            Self::Rotated { at } => now < grace.ends_after(at),
            Self::Revoked { .. } => false,
        }
    }

    /// When it was rotated out, if it ever was. This is the form storage
    /// keeps.
    #[must_use]
    pub fn rotated_at(self) -> Option<time::OffsetDateTime> {
        match self {
            Self::Rotated { at }
            | Self::Revoked {
                before: PriorRotation::RotatedAt(at),
            } => Some(at),
            Self::Active
            | Self::Revoked {
                before: PriorRotation::NotRotated,
            } => None,
        }
    }
}

/// Rejected transition between key states.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move a key from {from:?} to {to:?}")]
pub struct InvalidKeyTransition {
    /// The current state.
    pub from: KeyStatus,
    /// The attempted target state.
    pub to: KeyStatus,
}

impl KeyStatus {
    /// Moves to `to` when the transition is allowed.
    ///
    /// # Errors
    ///
    /// - [`InvalidKeyTransition`] when the transition is not allowed.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidKeyTransition> {
        let allowed = matches!(
            (self, to),
            (Self::Active, Self::Rotated | Self::Revoked) | (Self::Rotated, Self::Revoked)
        );

        if allowed {
            Ok(to)
        } else {
            Err(InvalidKeyTransition { from: self, to })
        }
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidKeyTransition);

#[cfg(test)]
mod tests {
    use super::*;

    /// A new key takes over. The active key may move to rotated.
    #[test]
    fn active_to_rotated() {
        assert!(KeyStatus::Active.try_transition(KeyStatus::Rotated).is_ok());
    }

    /// An active key leaks and is pulled in an emergency. It may move
    /// straight to revoked.
    #[test]
    fn active_to_revoked() {
        assert!(KeyStatus::Active.try_transition(KeyStatus::Revoked).is_ok());
    }

    /// A rotated key's grace period ends. It may move to revoked.
    #[test]
    fn rotated_to_revoked() {
        assert!(
            KeyStatus::Rotated
                .try_transition(KeyStatus::Revoked)
                .is_ok()
        );
    }

    /// A revoked key can never sign or verify again. It cannot move back to
    /// active or to rotated.
    #[test]
    fn revoked_is_terminal() {
        assert!(
            KeyStatus::Revoked
                .try_transition(KeyStatus::Active)
                .is_err()
        );
        assert!(
            KeyStatus::Revoked
                .try_transition(KeyStatus::Rotated)
                .is_err()
        );
    }

    /// A rotated key cannot become the signing key again. A new key is made
    /// instead.
    #[test]
    fn rotated_cannot_reactivate() {
        assert!(
            KeyStatus::Rotated
                .try_transition(KeyStatus::Active)
                .is_err()
        );
    }

    /// Moving a key to the status it already has is refused, for all three
    /// statuses.
    #[test]
    fn no_self_transitions() {
        assert!(KeyStatus::Active.try_transition(KeyStatus::Active).is_err());
        assert!(
            KeyStatus::Rotated
                .try_transition(KeyStatus::Rotated)
                .is_err()
        );
        assert!(
            KeyStatus::Revoked
                .try_transition(KeyStatus::Revoked)
                .is_err()
        );
    }

    /// A rotated key with a time and a revoked key keeping its rotation time
    /// both load. A rotated key with no time, or an active key with one, is
    /// refused, because it could never finish its grace period.
    #[test]
    fn a_stored_key_status_and_rotation_time_must_agree() {
        let now = time::OffsetDateTime::UNIX_EPOCH;

        assert_eq!(
            KeyState::from_stored(KeyStatus::Rotated, Some(now)).unwrap(),
            KeyState::Rotated { at: now }
        );
        assert_eq!(
            KeyState::from_stored(KeyStatus::Revoked, Some(now))
                .unwrap()
                .rotated_at(),
            Some(now)
        );
        assert!(KeyState::from_stored(KeyStatus::Rotated, None).is_err());
        assert!(KeyState::from_stored(KeyStatus::Active, Some(now)).is_err());
    }
}

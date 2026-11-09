/// Lifecycle status of a trusted device.
///
/// Valid transitions:
/// - `Trusted` → `Revoked`, when the user or an admin removes the device.
///
/// `Revoked` is final. To use the device again, the user trusts it again as
/// a new device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DeviceStatus {
    /// Device is trusted and can skip MFA challenges.
    Trusted,

    /// Device has been revoked. The next login from it counts as unknown.
    Revoked,
}

/// Rejected device status transition.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move a trusted device from {from:?} to {to:?}")]
pub struct InvalidDeviceTransition {
    /// The current state.
    pub from: DeviceStatus,
    /// The attempted target state.
    pub to: DeviceStatus,
}

impl DeviceStatus {
    /// Moves to `to` when the transition is allowed.
    ///
    /// # Errors
    ///
    /// - [`InvalidDeviceTransition`] when the transition is not allowed.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidDeviceTransition> {
        let allowed = matches!((self, to), (Self::Trusted, Self::Revoked));

        if allowed {
            Ok(to)
        } else {
            Err(InvalidDeviceTransition { from: self, to })
        }
    }

    /// Whether this device is trusted.
    #[must_use]
    pub fn is_trusted(&self) -> bool {
        *self == Self::Trusted
    }

    /// Whether this device has been revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        *self == Self::Revoked
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidDeviceTransition);

#[cfg(test)]
mod tests {
    use super::*;

    /// A trusted device answers only `is_trusted` and a revoked one only
    /// `is_revoked`. A revoked device that also answered "trusted" would
    /// still skip the second factor.
    #[test]
    fn each_predicate_answers_for_exactly_the_states_it_names() {
        let cases = [
            (DeviceStatus::Trusted, (true, false)),
            (DeviceStatus::Revoked, (false, true)),
        ];

        for (status, (trusted, revoked)) in cases {
            assert_eq!(status.is_trusted(), trusted, "{status:?}");
            assert_eq!(status.is_revoked(), revoked, "{status:?}");
        }
    }

    /// Ann removes her laptop from her device list. A trusted device may move
    /// to revoked.
    #[test]
    fn trusted_to_revoked() {
        assert!(
            DeviceStatus::Trusted
                .try_transition(DeviceStatus::Revoked)
                .is_ok()
        );
    }

    /// A revoked device can move nowhere, not back to trusted and not to
    /// revoked again. Trusting it again makes a new device record.
    #[test]
    fn revoked_is_terminal() {
        for to in [DeviceStatus::Trusted, DeviceStatus::Revoked] {
            assert!(DeviceStatus::Revoked.try_transition(to).is_err());
        }
    }

    /// Moving a trusted device to trusted is refused, so a no-op is never
    /// recorded as a change.
    #[test]
    fn no_self_transitions() {
        assert!(
            DeviceStatus::Trusted
                .try_transition(DeviceStatus::Trusted)
                .is_err()
        );
    }

    /// Each status is written as `"Trusted"` or `"Revoked"` and read back
    /// from the same text. Renaming a variant fails here instead of breaking
    /// saved devices.
    #[cfg(feature = "serde")]
    #[test]
    fn device_status_is_stored_under_its_variant_name() {
        assert_eq!(
            serde_json::to_string(&DeviceStatus::Trusted).unwrap(),
            r#""Trusted""#
        );
        assert_eq!(
            serde_json::to_string(&DeviceStatus::Revoked).unwrap(),
            r#""Revoked""#
        );
        assert_eq!(
            serde_json::from_str::<DeviceStatus>(r#""Trusted""#).unwrap(),
            DeviceStatus::Trusted
        );
        assert_eq!(
            serde_json::from_str::<DeviceStatus>(r#""Revoked""#).unwrap(),
            DeviceStatus::Revoked
        );
    }
}

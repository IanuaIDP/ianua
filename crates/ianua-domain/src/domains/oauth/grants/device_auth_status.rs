/// Where a device authorization request stands.
///
/// The allowed moves:
/// - `Pending` to `Approved`, when the user approves on their device.
/// - `Pending` to `Denied`, when the user says no.
/// - `Pending` to `Expired`, when the request times out.
/// - `Approved` to `Redeemed`, when the device collects the approval.
///
/// `Denied`, `Expired` and `Redeemed` go nowhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DeviceAuthStatus {
    /// Waiting for the user to approve on another device.
    Pending,
    /// The user approved the request.
    Approved,
    /// The user denied the request.
    Denied,
    /// The request expired before the user acted.
    Expired,
    /// The approval was handed to the device.
    ///
    /// A device code is good for one approval. Polling with it again gets
    /// nothing.
    Redeemed,
}

/// A refused device authorization status change.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move a device authorization from {from:?} to {to:?}")]
pub struct InvalidDeviceAuthTransition {
    /// The current status.
    pub from: DeviceAuthStatus,
    /// The status asked for.
    pub to: DeviceAuthStatus,
}

impl DeviceAuthStatus {
    /// Moves to `to`.
    ///
    /// # Errors
    ///
    /// - [`InvalidDeviceAuthTransition`] for any move not listed on
    ///   [`DeviceAuthStatus`].
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidDeviceAuthTransition> {
        let allowed = matches!(
            (self, to),
            (Self::Pending, Self::Approved | Self::Denied | Self::Expired)
                | (Self::Approved, Self::Redeemed)
        );

        if allowed {
            Ok(to)
        } else {
            Err(InvalidDeviceAuthTransition { from: self, to })
        }
    }

    /// Whether the request still waits for the user.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        *self == Self::Pending
    }

    /// Whether the user is done with the request, so it is not pending.
    ///
    /// An `Approved` request counts, though the device has yet to redeem it.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Approved | Self::Denied | Self::Expired | Self::Redeemed
        )
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidDeviceAuthTransition);

#[cfg(test)]
mod tests {
    use super::*;

    /// Only pending is pending. Approved, denied, expired and redeemed are
    /// all terminal. A check that answered for an extra status would let it
    /// through everywhere it is asked.
    #[test]
    fn each_predicate_answers_for_exactly_the_states_it_names() {
        let cases = [
            (DeviceAuthStatus::Pending, (true, false)),
            (DeviceAuthStatus::Approved, (false, true)),
            (DeviceAuthStatus::Denied, (false, true)),
            (DeviceAuthStatus::Expired, (false, true)),
            (DeviceAuthStatus::Redeemed, (false, true)),
        ];

        for (status, (pending, terminal)) in cases {
            assert_eq!(status.is_pending(), pending, "{status:?}");
            assert_eq!(status.is_terminal(), terminal, "{status:?}");
        }
    }

    /// A pending request may be approved.
    #[test]
    fn pending_to_approved() {
        assert!(
            DeviceAuthStatus::Pending
                .try_transition(DeviceAuthStatus::Approved)
                .is_ok()
        );
    }

    /// A pending request may be denied.
    #[test]
    fn pending_to_denied() {
        assert!(
            DeviceAuthStatus::Pending
                .try_transition(DeviceAuthStatus::Denied)
                .is_ok()
        );
    }

    /// A pending request may expire.
    #[test]
    fn pending_to_expired() {
        assert!(
            DeviceAuthStatus::Pending
                .try_transition(DeviceAuthStatus::Expired)
                .is_ok()
        );
    }

    /// An approved request may be redeemed when the device collects it.
    #[test]
    fn approved_to_redeemed() {
        assert!(
            DeviceAuthStatus::Approved
                .try_transition(DeviceAuthStatus::Redeemed)
                .is_ok()
        );
    }

    /// A redeemed request cannot move to any status, so its device code
    /// cannot get a second set of tokens.
    #[test]
    fn a_redeemed_approval_goes_nowhere() {
        for to in [
            DeviceAuthStatus::Pending,
            DeviceAuthStatus::Approved,
            DeviceAuthStatus::Denied,
            DeviceAuthStatus::Expired,
            DeviceAuthStatus::Redeemed,
        ] {
            assert!(DeviceAuthStatus::Redeemed.try_transition(to).is_err());
        }
    }

    /// A pending device authorization cannot transition directly to redeemed
    /// without first being approved.
    #[test]
    fn only_a_pending_request_can_be_redeemed_once_approved() {
        assert!(
            DeviceAuthStatus::Pending
                .try_transition(DeviceAuthStatus::Redeemed)
                .is_err()
        );
    }

    /// An approved request cannot go back to pending, or move to approved,
    /// denied or expired. Its only move is to redeemed.
    #[test]
    fn approved_is_terminal() {
        for to in [
            DeviceAuthStatus::Pending,
            DeviceAuthStatus::Approved,
            DeviceAuthStatus::Denied,
            DeviceAuthStatus::Expired,
        ] {
            assert!(DeviceAuthStatus::Approved.try_transition(to).is_err());
        }
    }

    /// A denied request cannot be approved later or move anywhere else.
    #[test]
    fn denied_is_terminal() {
        for to in [
            DeviceAuthStatus::Pending,
            DeviceAuthStatus::Approved,
            DeviceAuthStatus::Denied,
            DeviceAuthStatus::Expired,
        ] {
            assert!(DeviceAuthStatus::Denied.try_transition(to).is_err());
        }
    }

    /// An expired request cannot be approved later or move anywhere else.
    #[test]
    fn expired_is_terminal() {
        for to in [
            DeviceAuthStatus::Pending,
            DeviceAuthStatus::Approved,
            DeviceAuthStatus::Denied,
            DeviceAuthStatus::Expired,
        ] {
            assert!(DeviceAuthStatus::Expired.try_transition(to).is_err());
        }
    }

    /// Moving pending to pending is refused.
    #[test]
    fn no_self_transition_from_pending() {
        assert!(
            DeviceAuthStatus::Pending
                .try_transition(DeviceAuthStatus::Pending)
                .is_err()
        );
    }

    /// A pending request is pending and not terminal.
    #[test]
    fn pending_is_not_terminal() {
        assert!(DeviceAuthStatus::Pending.is_pending());
        assert!(!DeviceAuthStatus::Pending.is_terminal());
    }

    /// Approved, denied and expired requests are terminal, since the user is
    /// done with them.
    #[test]
    fn decided_or_expired_authorizations_are_terminal() {
        assert!(DeviceAuthStatus::Approved.is_terminal());
        assert!(DeviceAuthStatus::Denied.is_terminal());
        assert!(DeviceAuthStatus::Expired.is_terminal());
    }

    /// Each status turns into JSON as its variant name, such as "Redeemed",
    /// and reads back. Renaming a variant fails here instead of changing
    /// stored data.
    #[cfg(feature = "serde")]
    #[test]
    fn device_auth_status_is_stored_under_its_variant_name() {
        for (status, json) in [
            (DeviceAuthStatus::Pending, r#""Pending""#),
            (DeviceAuthStatus::Approved, r#""Approved""#),
            (DeviceAuthStatus::Denied, r#""Denied""#),
            (DeviceAuthStatus::Expired, r#""Expired""#),
            (DeviceAuthStatus::Redeemed, r#""Redeemed""#),
        ] {
            assert_eq!(serde_json::to_string(&status).unwrap(), json);
            assert_eq!(
                serde_json::from_str::<DeviceAuthStatus>(json).unwrap(),
                status
            );
        }
    }
}

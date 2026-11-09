/// Where a request for a person to approve one action stands.
///
/// Allowed moves:
/// - `Pending` → `Approved`, when a person allows the action.
/// - `Pending` → `Denied`, when a person refuses it.
/// - `Pending` → `Expired`, when nobody decides in time.
/// - `Pending` → `Withdrawn`, when a person stops the run that raised it.
/// - `Approved` → `Consumed`, when the one action it allowed runs.
///
/// `Denied`, `Expired`, `Withdrawn` and `Consumed` are final. A retry makes
/// a new request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ApprovalStatus {
    /// Waiting for a person to decide.
    Pending,

    /// A person allowed the action.
    Approved,

    /// A person refused the action.
    Denied,

    /// Nobody decided in time.
    Expired,

    /// Approved, and the one action it allowed has run. An approval lets an
    /// action through once. It is not a lasting permission.
    Consumed,

    /// A person stopped the run that raised it, so the action will never be
    /// taken. Nobody approved or refused it.
    Withdrawn,
}

/// A refused move between two approval states.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move an approval from {from:?} to {to:?}")]
pub struct InvalidApprovalTransition {
    /// The current state.
    pub from: ApprovalStatus,
    /// The attempted target state.
    pub to: ApprovalStatus,
}

impl ApprovalStatus {
    /// Moves to `to` when the move is allowed.
    ///
    /// # Errors
    ///
    /// - [`InvalidApprovalTransition`] when the move is not in the list on
    ///   [`ApprovalStatus`].
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidApprovalTransition> {
        let allowed = matches!(
            (self, to),
            (Self::Pending, Self::Approved)
                | (Self::Pending, Self::Denied)
                | (Self::Pending, Self::Expired)
                | (Self::Pending, Self::Withdrawn)
                | (Self::Approved, Self::Consumed)
        );

        if allowed {
            Ok(to)
        } else {
            Err(InvalidApprovalTransition { from: self, to })
        }
    }

    /// Whether the request still waits for a decision.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        *self == Self::Pending
    }

    /// Whether the action is approved and not yet run.
    #[must_use]
    pub fn is_approved(&self) -> bool {
        *self == Self::Approved
    }

    /// Whether the request is anything but pending: approved, denied,
    /// expired, withdrawn or consumed.
    #[must_use]
    pub fn is_decided(&self) -> bool {
        *self != Self::Pending
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidApprovalTransition);

#[cfg(test)]
mod tests {
    use super::*;

    /// Each of the five states answers the three questions as named. If
    /// `is_approved` said yes for a consumed approval, every check built on
    /// it would run the action twice.
    #[test]
    fn each_predicate_answers_for_exactly_the_states_it_names() {
        let cases = [
            (ApprovalStatus::Pending, (true, false, false)),
            (ApprovalStatus::Approved, (false, true, true)),
            (ApprovalStatus::Denied, (false, false, true)),
            (ApprovalStatus::Expired, (false, false, true)),
            (ApprovalStatus::Consumed, (false, false, true)),
            (ApprovalStatus::Withdrawn, (false, false, true)),
        ];

        for (status, (pending, approved, decided)) in cases {
            assert_eq!(status.is_pending(), pending, "{status:?}");
            assert_eq!(status.is_approved(), approved, "{status:?}");
            assert_eq!(status.is_decided(), decided, "{status:?}");
        }
    }

    /// A pending request may move to approved, denied, expired or
    /// withdrawn.
    #[test]
    fn pending_can_be_approved_denied_expired_or_withdrawn() {
        for to in [
            ApprovalStatus::Approved,
            ApprovalStatus::Denied,
            ApprovalStatus::Expired,
            ApprovalStatus::Withdrawn,
        ] {
            assert!(ApprovalStatus::Pending.try_transition(to).is_ok());
        }
    }

    /// Approved, denied, expired, consumed and withdrawn requests cannot
    /// return to pending or move to an approval, denial, expiry or withdrawal.
    #[test]
    fn decisions_cannot_be_changed() {
        for from in [
            ApprovalStatus::Approved,
            ApprovalStatus::Denied,
            ApprovalStatus::Expired,
            ApprovalStatus::Consumed,
            ApprovalStatus::Withdrawn,
        ] {
            for to in [
                ApprovalStatus::Pending,
                ApprovalStatus::Approved,
                ApprovalStatus::Denied,
                ApprovalStatus::Expired,
                ApprovalStatus::Withdrawn,
            ] {
                assert!(from.try_transition(to).is_err());
            }
        }
    }

    /// An approved request may be consumed. A pending, denied, expired or
    /// already consumed one may not, so one approval runs one action.
    #[test]
    fn only_an_approval_can_be_consumed_and_only_once() {
        assert!(
            ApprovalStatus::Approved
                .try_transition(ApprovalStatus::Consumed)
                .is_ok()
        );
        for from in [
            ApprovalStatus::Pending,
            ApprovalStatus::Denied,
            ApprovalStatus::Expired,
            ApprovalStatus::Consumed,
        ] {
            assert!(from.try_transition(ApprovalStatus::Consumed).is_err());
        }
    }

    /// Each status is written to JSON as its variant name and reads back from
    /// it. Renaming a variant fails here instead of breaking saved data.
    #[cfg(feature = "serde")]
    #[test]
    fn approval_status_is_stored_under_its_variant_name() {
        for (status, json) in [
            (ApprovalStatus::Pending, r#""Pending""#),
            (ApprovalStatus::Approved, r#""Approved""#),
            (ApprovalStatus::Denied, r#""Denied""#),
            (ApprovalStatus::Expired, r#""Expired""#),
            (ApprovalStatus::Consumed, r#""Consumed""#),
        ] {
            assert_eq!(serde_json::to_string(&status).unwrap(), json);
            assert_eq!(
                serde_json::from_str::<ApprovalStatus>(json).unwrap(),
                status
            );
        }
        assert_eq!(
            serde_json::to_string(&ApprovalStatus::Withdrawn).unwrap(),
            r#""Withdrawn""#
        );
    }
}

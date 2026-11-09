/// Where a request to erase a person's data stands (GDPR Article 17).
///
/// The allowed moves:
/// - `Pending` to `Processing`, when the waiting period ends and erasing
///   starts.
/// - `Pending` to `Cancelled`, when the user withdraws the request.
/// - `Pending` to `Held`, when a legal hold pauses it, and back to `Pending`
///   when the hold is lifted.
/// - `Held` to `Cancelled`, when the user withdraws it while it is held.
/// - `Processing` to `Completed`, when all data is erased.
/// - `Processing` to `Failed`, when erasing stops part way.
/// - `Failed` to `Processing`, to try again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ErasureStatus {
    /// Asked for, and waiting for the waiting period to end.
    ///
    /// The user can still cancel.
    Pending,

    /// The waiting period ended and data is being deleted.
    Processing,

    /// All of the user's data was deleted for good.
    Completed,

    /// The user cancelled the request.
    Cancelled,

    /// Paused by a legal hold, such as a court order or an audit duty to
    /// keep the person's records. It waits, past its grace period, until the
    /// hold is lifted.
    Held,

    /// Erasing stopped part way. It needs another try.
    Failed,
}

/// An erasure status change the rules refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move an erasure request from {from:?} to {to:?}")]
pub struct InvalidErasureTransition {
    /// The current status.
    pub from: ErasureStatus,
    /// The status asked for.
    pub to: ErasureStatus,
}

impl ErasureStatus {
    /// Moves to `to`.
    ///
    /// # Errors
    ///
    /// - [`InvalidErasureTransition`] when the move is not one of the allowed
    ///   moves listed on [`ErasureStatus`].
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidErasureTransition> {
        let allowed = matches!(
            (self, to),
            (
                Self::Pending,
                Self::Processing | Self::Cancelled | Self::Held
            ) | (Self::Held, Self::Pending | Self::Cancelled)
                | (Self::Processing, Self::Completed | Self::Failed)
                | (Self::Failed, Self::Processing)
        );

        if allowed {
            Ok(to)
        } else {
            Err(InvalidErasureTransition { from: self, to })
        }
    }

    /// Whether the request is still open: pending, held, processing or
    /// failed.
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Held | Self::Processing | Self::Failed
        )
    }

    /// Whether the request is finished for good: completed or cancelled.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled)
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidErasureTransition);

#[cfg(test)]
mod tests {
    use super::*;

    /// Pending, held, processing and failed are open. Completed and
    /// cancelled are finished. Mixing up failed and cancelled would drop a request that
    /// needs another try, or keep trying one nobody wants.
    #[test]
    fn each_predicate_answers_for_exactly_the_states_it_names() {
        let cases = [
            (ErasureStatus::Pending, (true, false)),
            (ErasureStatus::Held, (true, false)),
            (ErasureStatus::Processing, (true, false)),
            (ErasureStatus::Completed, (false, true)),
            (ErasureStatus::Cancelled, (false, true)),
            (ErasureStatus::Failed, (true, false)),
        ];

        for (status, (active, terminal)) in cases {
            assert_eq!(status.is_active(), active, "{status:?}");
            assert_eq!(status.is_terminal(), terminal, "{status:?}");
        }
    }

    /// The waiting period ends, so a pending request may start processing.
    #[test]
    fn pending_to_processing() {
        assert!(
            ErasureStatus::Pending
                .try_transition(ErasureStatus::Processing)
                .is_ok()
        );
    }

    /// A user may cancel a request that is still pending.
    #[test]
    fn pending_to_cancelled() {
        assert!(
            ErasureStatus::Pending
                .try_transition(ErasureStatus::Cancelled)
                .is_ok()
        );
    }

    /// A processing request may complete once all data is erased.
    #[test]
    fn processing_to_completed() {
        assert!(
            ErasureStatus::Processing
                .try_transition(ErasureStatus::Completed)
                .is_ok()
        );
    }

    /// A processing request may fail when erasing stops part way.
    #[test]
    fn processing_to_failed() {
        assert!(
            ErasureStatus::Processing
                .try_transition(ErasureStatus::Failed)
                .is_ok()
        );
    }

    /// A failed request may go back to processing for another try.
    #[test]
    fn failed_to_processing_retry() {
        assert!(
            ErasureStatus::Failed
                .try_transition(ErasureStatus::Processing)
                .is_ok()
        );
    }

    /// A completed request cannot move to any status, itself included.
    #[test]
    fn completed_is_terminal() {
        for to in [
            ErasureStatus::Pending,
            ErasureStatus::Processing,
            ErasureStatus::Completed,
            ErasureStatus::Cancelled,
            ErasureStatus::Failed,
        ] {
            assert!(ErasureStatus::Completed.try_transition(to).is_err());
        }
    }

    /// A cancelled request cannot move to any status, so it cannot be
    /// started again.
    #[test]
    fn cancelled_is_terminal() {
        for to in [
            ErasureStatus::Pending,
            ErasureStatus::Processing,
            ErasureStatus::Completed,
            ErasureStatus::Cancelled,
            ErasureStatus::Failed,
        ] {
            assert!(ErasureStatus::Cancelled.try_transition(to).is_err());
        }
    }

    /// Moving pending to pending, or processing to processing, is refused.
    #[test]
    fn no_self_transitions() {
        assert!(
            ErasureStatus::Pending
                .try_transition(ErasureStatus::Pending)
                .is_err()
        );
        assert!(
            ErasureStatus::Processing
                .try_transition(ErasureStatus::Processing)
                .is_err()
        );
    }

    /// Each status turns into JSON as its variant name, such as "Pending",
    /// and reads back. Renaming a variant fails here instead of changing
    /// stored data.
    #[cfg(feature = "serde")]
    #[test]
    fn erasure_status_is_stored_under_its_variant_name() {
        for (status, json) in [
            (ErasureStatus::Pending, r#""Pending""#),
            (ErasureStatus::Processing, r#""Processing""#),
            (ErasureStatus::Completed, r#""Completed""#),
            (ErasureStatus::Cancelled, r#""Cancelled""#),
            (ErasureStatus::Failed, r#""Failed""#),
        ] {
            assert_eq!(serde_json::to_string(&status).unwrap(), json);
            assert_eq!(serde_json::from_str::<ErasureStatus>(json).unwrap(), status);
        }
    }

    /// A legal hold pauses a pending request and is lifted again. A held
    /// request cannot start deleting, but the person may still cancel it.
    #[test]
    fn a_hold_pauses_a_request_until_it_is_lifted() {
        assert_eq!(
            ErasureStatus::Pending.try_transition(ErasureStatus::Held),
            Ok(ErasureStatus::Held)
        );
        assert_eq!(
            ErasureStatus::Held.try_transition(ErasureStatus::Pending),
            Ok(ErasureStatus::Pending)
        );
        assert!(
            ErasureStatus::Held
                .try_transition(ErasureStatus::Processing)
                .is_err()
        );
        assert!(
            ErasureStatus::Held
                .try_transition(ErasureStatus::Cancelled)
                .is_ok()
        );
    }
}

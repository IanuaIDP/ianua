/// Status of a proxy pipeline.
///
/// Valid transitions:
/// - `Draft` → `Active`, once it is configured
/// - `Active` → `Disabled`, to stop it in an emergency or to change it
/// - `Disabled` → `Active`, to turn it back on after changes
/// - `Disabled` → `Draft`, for a larger rework
///
/// Stages may be added, removed or reordered only in `Draft` or `Disabled`,
/// never while the pipeline is `Active`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PipelineStatus {
    /// Being configured. Traffic on its routes is denied.
    Draft,

    /// Enforced on all tenant traffic.
    Active,

    /// Turned off for now. Traffic on its routes is denied.
    Disabled,
}

/// A pipeline status move that [`PipelineStatus`] does not allow.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move a pipeline from {from:?} to {to:?}")]
pub struct InvalidPipelineTransition {
    /// The status it is in.
    pub from: PipelineStatus,
    /// The status it was asked to move to.
    pub to: PipelineStatus,
}

impl PipelineStatus {
    /// The status `to`, when moving there from this one is allowed.
    ///
    /// # Errors
    ///
    /// - [`InvalidPipelineTransition`] if the transition is not allowed.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidPipelineTransition> {
        let allowed = matches!(
            (self, to),
            (Self::Draft, Self::Active)
                | (Self::Active, Self::Disabled)
                | (Self::Disabled, Self::Active)
                | (Self::Disabled, Self::Draft)
        );

        if allowed {
            Ok(to)
        } else {
            Err(InvalidPipelineTransition { from: self, to })
        }
    }

    /// Whether the pipeline is enforced on traffic.
    #[must_use]
    pub fn is_active(self) -> bool {
        self == Self::Active
    }

    /// Whether stages may be added, removed or reordered.
    #[must_use]
    pub fn allows_mutation(self) -> bool {
        matches!(self, Self::Draft | Self::Disabled)
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidPipelineTransition);

#[cfg(test)]
mod tests {
    use super::*;

    /// A configured draft pipeline may go live.
    #[test]
    fn draft_to_active() {
        assert!(
            PipelineStatus::Draft
                .try_transition(PipelineStatus::Active)
                .is_ok()
        );
    }

    /// An admin may switch off a live pipeline, for an emergency or to edit
    /// it.
    #[test]
    fn active_to_disabled() {
        assert!(
            PipelineStatus::Active
                .try_transition(PipelineStatus::Disabled)
                .is_ok()
        );
    }

    /// A disabled pipeline may be switched back on after edits.
    #[test]
    fn disabled_to_active() {
        assert!(
            PipelineStatus::Disabled
                .try_transition(PipelineStatus::Active)
                .is_ok()
        );
    }

    /// A disabled pipeline may go back to draft for a larger rework.
    #[test]
    fn disabled_to_draft() {
        assert!(
            PipelineStatus::Disabled
                .try_transition(PipelineStatus::Draft)
                .is_ok()
        );
    }

    /// A draft that was never live cannot be disabled. It has nothing to
    /// switch off.
    #[test]
    fn draft_to_disabled_rejected() {
        assert!(
            PipelineStatus::Draft
                .try_transition(PipelineStatus::Disabled)
                .is_err()
        );
    }

    /// An active pipeline cannot transition directly to draft; that move
    /// requires disabling it first.
    #[test]
    fn active_to_draft_rejected() {
        assert!(
            PipelineStatus::Active
                .try_transition(PipelineStatus::Draft)
                .is_err()
        );
    }

    /// Moving a pipeline to the status it already has is refused for each
    /// status, so no event claims a change that did not happen.
    #[test]
    fn self_transitions_rejected() {
        assert!(
            PipelineStatus::Draft
                .try_transition(PipelineStatus::Draft)
                .is_err()
        );
        assert!(
            PipelineStatus::Active
                .try_transition(PipelineStatus::Active)
                .is_err()
        );
        assert!(
            PipelineStatus::Disabled
                .try_transition(PipelineStatus::Disabled)
                .is_err()
        );
    }

    /// Stages may change in a draft or disabled pipeline, never in an active
    /// one that carries traffic.
    #[test]
    fn mutation_allowed_in_draft_and_disabled() {
        assert!(PipelineStatus::Draft.allows_mutation());
        assert!(PipelineStatus::Disabled.allows_mutation());
        assert!(!PipelineStatus::Active.allows_mutation());
    }

    /// Each status is written and read as `"Draft"`, `"Active"` or
    /// `"Disabled"`. Renaming a variant fails here instead of changing saved
    /// data.
    #[cfg(feature = "serde")]
    #[test]
    fn pipeline_status_is_stored_under_its_variant_name() {
        assert_eq!(
            serde_json::to_string(&PipelineStatus::Draft).unwrap(),
            r#""Draft""#
        );
        assert_eq!(
            serde_json::to_string(&PipelineStatus::Active).unwrap(),
            r#""Active""#
        );
        assert_eq!(
            serde_json::to_string(&PipelineStatus::Disabled).unwrap(),
            r#""Disabled""#
        );
        assert_eq!(
            serde_json::from_str::<PipelineStatus>(r#""Draft""#).unwrap(),
            PipelineStatus::Draft
        );
        assert_eq!(
            serde_json::from_str::<PipelineStatus>(r#""Active""#).unwrap(),
            PipelineStatus::Active
        );
        assert_eq!(
            serde_json::from_str::<PipelineStatus>(r#""Disabled""#).unwrap(),
            PipelineStatus::Disabled
        );
    }
}

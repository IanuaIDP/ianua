/// Lifecycle status of an access policy.
///
/// Allowed moves:
/// - `Draft` to `Review`: submitted for review.
/// - `Review` to `Active`: approved, and goes live.
/// - `Review` to `Draft`: rejected, and sent back for edits.
/// - `Active` to `Archived`: replaced by a new version, or taken out of use.
/// - `Draft` to `Archived`: abandoned without going live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PolicyStatus {
    /// Policy is being edited. Not enforced.
    Draft,

    /// Policy is submitted for review. Not yet enforced.
    Review,

    /// Policy is live and enforced on every request.
    Active,

    /// Policy was replaced or abandoned. Kept for the audit trail.
    Archived,
}

/// A policy status move that is not allowed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("a policy that is {from} cannot become {to}")]
pub struct InvalidPolicyTransition {
    /// The current state.
    pub from: PolicyStatus,
    /// The attempted target state.
    pub to: PolicyStatus,
}

impl core::fmt::Display for PolicyStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            Self::Draft => "a draft",
            Self::Review => "in review",
            Self::Active => "live",
            Self::Archived => "archived",
        };

        f.write_str(name)
    }
}

impl PolicyStatus {
    /// Moves to `to`, when [`PolicyStatus`] lists that move.
    ///
    /// # Errors
    ///
    /// - [`InvalidPolicyTransition`] when the move is not one listed.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidPolicyTransition> {
        let allowed = matches!(
            (self, to),
            (Self::Draft, Self::Review | Self::Archived)
                | (Self::Review, Self::Active | Self::Draft)
                | (Self::Active, Self::Archived)
        );

        if !allowed {
            return Err(InvalidPolicyTransition { from: self, to });
        }
        Ok(to)
    }

    /// Whether this policy is enforced on requests.
    #[must_use]
    pub fn is_active(&self) -> bool {
        *self == Self::Active
    }

    /// Whether rules may be written over this policy.
    ///
    /// Only a draft is edited in place. A policy under review, in force or
    /// archived is never rewritten, so what was reviewed or enforced stays as
    /// it was. The next version starts from a copy made by
    /// [`PolicySet::start_draft`](crate::domains::authorization::policy::set::PolicySet::start_draft).
    #[must_use]
    pub fn is_editable(&self) -> bool {
        matches!(self, Self::Draft)
    }

    /// Whether this is the tenant's open draft: being written, or in review.
    /// A tenant has at most one beside its live policy.
    #[must_use]
    pub fn is_open(&self) -> bool {
        matches!(self, Self::Draft | Self::Review)
    }

    /// Whether this policy is in a terminal state.
    #[must_use]
    pub fn is_archived(&self) -> bool {
        *self == Self::Archived
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidPolicyTransition);

#[cfg(test)]
mod tests {
    use super::*;

    /// Only a live policy is active, only a draft is editable, and only an
    /// archived policy is archived. A policy in review answers no to all
    /// three, so nobody rewrites what a reviewer is reading. A draft and a
    /// policy in review are both the tenant's open draft.
    #[test]
    fn each_predicate_answers_for_exactly_the_states_it_names() {
        let cases = [
            (PolicyStatus::Draft, (false, true, false, true)),
            (PolicyStatus::Review, (false, false, false, true)),
            (PolicyStatus::Active, (true, false, false, false)),
            (PolicyStatus::Archived, (false, false, true, false)),
        ];

        for (status, (active, editable, archived, open)) in cases {
            assert_eq!(status.is_active(), active, "{status:?}");
            assert_eq!(status.is_editable(), editable, "{status:?}");
            assert_eq!(status.is_archived(), archived, "{status:?}");
            assert_eq!(status.is_open(), open, "{status:?}");
        }
    }

    /// An admin submits a draft policy. It moves to review.
    #[test]
    fn draft_to_review() {
        assert!(
            PolicyStatus::Draft
                .try_transition(PolicyStatus::Review)
                .is_ok()
        );
    }

    /// An admin abandons a draft that never went live. It moves to archived.
    #[test]
    fn draft_to_archived() {
        assert!(
            PolicyStatus::Draft
                .try_transition(PolicyStatus::Archived)
                .is_ok()
        );
    }

    /// A reviewer approves a policy in review. It goes live.
    #[test]
    fn review_to_active() {
        assert!(
            PolicyStatus::Review
                .try_transition(PolicyStatus::Active)
                .is_ok()
        );
    }

    /// A reviewer rejects a policy in review. It goes back to draft for
    /// edits.
    #[test]
    fn review_to_draft_rejected() {
        assert!(
            PolicyStatus::Review
                .try_transition(PolicyStatus::Draft)
                .is_ok()
        );
    }

    /// A new version replaces the live policy. The old one moves to
    /// archived.
    #[test]
    fn active_to_archived() {
        assert!(
            PolicyStatus::Active
                .try_transition(PolicyStatus::Archived)
                .is_ok()
        );
    }

    /// An archived policy cannot move to any status, itself included. It
    /// stays in the audit trail as it was.
    #[test]
    fn archived_is_terminal() {
        for to in [
            PolicyStatus::Draft,
            PolicyStatus::Review,
            PolicyStatus::Active,
            PolicyStatus::Archived,
        ] {
            assert!(PolicyStatus::Archived.try_transition(to).is_err());
        }
    }

    /// A draft policy cannot become active without passing through review.
    #[test]
    fn draft_cannot_skip_to_active() {
        assert!(
            PolicyStatus::Draft
                .try_transition(PolicyStatus::Active)
                .is_err()
        );
    }

    /// An active policy cannot return to draft status for editing.
    #[test]
    fn active_cannot_go_back_to_draft() {
        assert!(
            PolicyStatus::Active
                .try_transition(PolicyStatus::Draft)
                .is_err()
        );
    }

    /// A draft, a policy in review and a live policy are each moved to the
    /// status they already have. Each move is refused.
    #[test]
    fn no_self_transitions() {
        assert!(
            PolicyStatus::Draft
                .try_transition(PolicyStatus::Draft)
                .is_err()
        );
        assert!(
            PolicyStatus::Review
                .try_transition(PolicyStatus::Review)
                .is_err()
        );
        assert!(
            PolicyStatus::Active
                .try_transition(PolicyStatus::Active)
                .is_err()
        );
    }

    /// Of the four statuses, only a live policy is enforced on requests.
    #[test]
    fn only_active_is_enforced() {
        assert!(!PolicyStatus::Draft.is_active());
        assert!(!PolicyStatus::Review.is_active());
        assert!(PolicyStatus::Active.is_active());
        assert!(!PolicyStatus::Archived.is_active());
    }

    /// Only a draft takes rule edits. A policy in review, live or archived
    /// refuses them, so what was reviewed or enforced stays as it was.
    #[test]
    fn rules_are_written_over_a_draft_or_an_archived_policy_only() {
        assert!(PolicyStatus::Draft.is_editable());
        assert!(!PolicyStatus::Review.is_editable());
        assert!(!PolicyStatus::Active.is_editable());
        assert!(!PolicyStatus::Archived.is_editable());
    }

    /// Each status is written to JSON as its variant name, such as `"Draft"`,
    /// and read back from it. A renamed variant fails here before it breaks
    /// saved policies.
    #[cfg(feature = "serde")]
    #[test]
    fn policy_status_is_stored_under_its_variant_name() {
        for (status, json) in [
            (PolicyStatus::Draft, r#""Draft""#),
            (PolicyStatus::Review, r#""Review""#),
            (PolicyStatus::Active, r#""Active""#),
            (PolicyStatus::Archived, r#""Archived""#),
        ] {
            assert_eq!(serde_json::to_string(&status).unwrap(), json);
            assert_eq!(serde_json::from_str::<PolicyStatus>(json).unwrap(), status);
        }
    }
}

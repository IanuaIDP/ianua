/// Lifecycle status of an algorithm migration.
///
/// Valid transitions:
/// - `Planned` → `InProgress`, when the new key with the target algorithm is
///   created.
/// - `Planned` → `Cancelled`, when the plan is dropped before any key is
///   created.
/// - `InProgress` → `Validating`, when the target key becomes the primary
///   signer.
/// - `InProgress` → `RolledBack`, when the migration is stopped and the
///   source key signs again.
/// - `Validating` → `Completed`, when the source key is revoked.
///
/// There is no rollback once the target key is promoted. Promotion rotates
/// the source key out, and a rotated key does not become active again. To go
/// back from there, start a new migration to the source algorithm.
///
/// Terminal states: `Completed`, `RolledBack`, `Cancelled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MigrationStatus {
    /// The migration is planned but has not started. The source and target
    /// algorithms are chosen.
    Planned,

    /// A new key with the target algorithm exists. Both keys are in the
    /// JWKS, and the old key is still the primary signer.
    InProgress,

    /// The new key is the primary signer. The old key stays in the JWKS so
    /// tokens signed before the switch still verify. Relying parties get time
    /// to refresh their JWKS cache.
    Validating,

    /// The migration finished. The old key is revoked and gone from the
    /// JWKS.
    Completed,

    /// The migration was stopped. The old key is the primary signer again,
    /// and any new key made for it is revoked.
    RolledBack,

    /// The migration was cancelled before it started. No keys were made for
    /// it.
    Cancelled,
}

/// Rejected migration status transition.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move an algorithm migration from {from:?} to {to:?}")]
pub struct InvalidMigrationTransition {
    /// The current state.
    pub from: MigrationStatus,
    /// The attempted target state.
    pub to: MigrationStatus,
}

impl MigrationStatus {
    /// Moves to `to` when the transition is allowed.
    ///
    /// # Errors
    ///
    /// - [`InvalidMigrationTransition`] when the transition is not allowed.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidMigrationTransition> {
        let allowed = matches!(
            (self, to),
            (Self::Planned, Self::InProgress | Self::Cancelled)
                | (Self::InProgress, Self::Validating | Self::RolledBack)
                | (Self::Validating, Self::Completed)
        );

        if allowed {
            Ok(to)
        } else {
            Err(InvalidMigrationTransition { from: self, to })
        }
    }

    /// Whether the migration has not reached a terminal state.
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Planned | Self::InProgress | Self::Validating)
    }

    /// Whether the migration reached a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::RolledBack | Self::Cancelled)
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidMigrationTransition);

#[cfg(test)]
mod tests {
    use super::*;

    /// Planned, in progress and validating are active and not terminal.
    /// Completed, rolled back and cancelled are terminal and not active. No
    /// status answers yes to both.
    #[test]
    fn each_predicate_answers_for_exactly_the_states_it_names() {
        let cases = [
            (MigrationStatus::Planned, (true, false)),
            (MigrationStatus::InProgress, (true, false)),
            (MigrationStatus::Validating, (true, false)),
            (MigrationStatus::Completed, (false, true)),
            (MigrationStatus::RolledBack, (false, true)),
            (MigrationStatus::Cancelled, (false, true)),
        ];

        for (status, (active, terminal)) in cases {
            assert_eq!(status.is_active(), active, "{status:?}");
            assert_eq!(status.is_terminal(), terminal, "{status:?}");
        }
    }

    /// The target key is created. A planned migration may move to in
    /// progress.
    #[test]
    fn planned_to_in_progress() {
        assert!(
            MigrationStatus::Planned
                .try_transition(MigrationStatus::InProgress)
                .is_ok()
        );
    }

    /// The target key becomes the signer. A migration in progress may move
    /// to validating.
    #[test]
    fn in_progress_to_validating() {
        assert!(
            MigrationStatus::InProgress
                .try_transition(MigrationStatus::Validating)
                .is_ok()
        );
    }

    /// The new key will not verify, so the migration is stopped before
    /// promotion. A migration in progress may roll back.
    #[test]
    fn in_progress_to_rolled_back() {
        assert!(
            MigrationStatus::InProgress
                .try_transition(MigrationStatus::RolledBack)
                .is_ok()
        );
    }

    /// The source key is revoked after the grace period. A validating
    /// migration may complete.
    #[test]
    fn validating_to_completed() {
        assert!(
            MigrationStatus::Validating
                .try_transition(MigrationStatus::Completed)
                .is_ok()
        );
    }

    /// A validating migration cannot roll back. The source key was rotated
    /// out at promotion and cannot sign again, so a rollback then would claim
    /// a reversal the keys never made.
    #[test]
    fn a_promoted_migration_cannot_roll_back() {
        assert!(
            MigrationStatus::Validating
                .try_transition(MigrationStatus::RolledBack)
                .is_err()
        );
    }

    /// An admin drops a plan before any key is made. A planned migration may
    /// be cancelled.
    #[test]
    fn planned_to_cancelled() {
        assert!(
            MigrationStatus::Planned
                .try_transition(MigrationStatus::Cancelled)
                .is_ok()
        );
    }

    /// A completed migration moves to no status at all.
    #[test]
    fn completed_is_terminal() {
        for to in [
            MigrationStatus::Planned,
            MigrationStatus::InProgress,
            MigrationStatus::Validating,
            MigrationStatus::Completed,
            MigrationStatus::RolledBack,
            MigrationStatus::Cancelled,
        ] {
            assert!(MigrationStatus::Completed.try_transition(to).is_err());
        }
    }

    /// A rolled-back migration moves to no status at all. Trying again means
    /// planning a new one.
    #[test]
    fn rolled_back_is_terminal() {
        for to in [
            MigrationStatus::Planned,
            MigrationStatus::InProgress,
            MigrationStatus::Validating,
            MigrationStatus::Completed,
            MigrationStatus::RolledBack,
            MigrationStatus::Cancelled,
        ] {
            assert!(MigrationStatus::RolledBack.try_transition(to).is_err());
        }
    }

    /// A cancelled migration moves to no status at all.
    #[test]
    fn cancelled_is_terminal() {
        for to in [
            MigrationStatus::Planned,
            MigrationStatus::InProgress,
            MigrationStatus::Validating,
            MigrationStatus::Completed,
            MigrationStatus::RolledBack,
            MigrationStatus::Cancelled,
        ] {
            assert!(MigrationStatus::Cancelled.try_transition(to).is_err());
        }
    }

    /// A migration in progress already made a key, so it cannot be
    /// cancelled. It is rolled back instead.
    #[test]
    fn in_progress_cannot_cancel() {
        assert!(
            MigrationStatus::InProgress
                .try_transition(MigrationStatus::Cancelled)
                .is_err()
        );
    }

    /// A planned migration cannot jump to validating, because no target key
    /// exists yet to promote.
    #[test]
    fn planned_cannot_skip_to_validating() {
        assert!(
            MigrationStatus::Planned
                .try_transition(MigrationStatus::Validating)
                .is_err()
        );
    }

    /// A planned migration cannot jump straight to completed.
    #[test]
    fn planned_cannot_skip_to_completed() {
        assert!(
            MigrationStatus::Planned
                .try_transition(MigrationStatus::Completed)
                .is_err()
        );
    }

    /// A migration in progress cannot complete before its target key has
    /// been promoted and validated.
    #[test]
    fn in_progress_cannot_skip_to_completed() {
        assert!(
            MigrationStatus::InProgress
                .try_transition(MigrationStatus::Completed)
                .is_err()
        );
    }

    /// Planned, in progress and validating each refuse a move to themselves.
    #[test]
    fn no_self_transitions() {
        for s in [
            MigrationStatus::Planned,
            MigrationStatus::InProgress,
            MigrationStatus::Validating,
        ] {
            assert!(s.try_transition(s).is_err());
        }
    }

    /// Planned, in progress and validating count as active. The three
    /// finished statuses do not.
    #[test]
    fn only_unfinished_migrations_are_active() {
        assert!(MigrationStatus::Planned.is_active());
        assert!(MigrationStatus::InProgress.is_active());
        assert!(MigrationStatus::Validating.is_active());
        assert!(!MigrationStatus::Completed.is_active());
        assert!(!MigrationStatus::RolledBack.is_active());
        assert!(!MigrationStatus::Cancelled.is_active());
    }

    /// Completed, rolled back and cancelled are terminal. Planned is not.
    #[test]
    fn finished_migrations_are_terminal() {
        assert!(!MigrationStatus::Planned.is_terminal());
        assert!(MigrationStatus::Completed.is_terminal());
        assert!(MigrationStatus::RolledBack.is_terminal());
        assert!(MigrationStatus::Cancelled.is_terminal());
    }

    /// Each status is written as its variant name, such as `"InProgress"`,
    /// and read back from it. Renaming a variant fails here instead of
    /// breaking saved migrations.
    #[cfg(feature = "serde")]
    #[test]
    fn migration_status_is_stored_under_its_variant_name() {
        for (status, stored) in [
            (MigrationStatus::Planned, r#""Planned""#),
            (MigrationStatus::InProgress, r#""InProgress""#),
            (MigrationStatus::Validating, r#""Validating""#),
            (MigrationStatus::Completed, r#""Completed""#),
            (MigrationStatus::RolledBack, r#""RolledBack""#),
            (MigrationStatus::Cancelled, r#""Cancelled""#),
        ] {
            assert_eq!(serde_json::to_string(&status).unwrap(), stored);
            assert_eq!(
                serde_json::from_str::<MigrationStatus>(stored).unwrap(),
                status
            );
        }
    }
}

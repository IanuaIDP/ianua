//! Where an import of accounts stands.

use time::OffsetDateTime;

/// Where an import stands.
///
/// The allowed moves:
/// - `Pending` to `Running`, when the worker takes it up.
/// - `Running` to `Finished`, once every record is worked through.
/// - `Pending` or `Running` to `Failed`, when the worker gives up on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImportStatus {
    /// Kept, waiting for the worker.
    Pending,
    /// The worker is going through its records.
    Running,
    /// Every record is worked through.
    Finished,
    /// The worker gave up on it. The chunks it finished stay.
    Failed,
}

/// An import status change the rules refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move a user import from {from:?} to {to:?}")]
pub struct InvalidImportTransition {
    /// The current status.
    pub from: ImportStatus,
    /// The status asked for.
    pub to: ImportStatus,
}

impl ImportStatus {
    /// Moves to `to`.
    ///
    /// # Errors
    ///
    /// - [`InvalidImportTransition`] when the move is not one of the moves
    ///   listed on [`ImportStatus`].
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidImportTransition> {
        let allowed = matches!(
            (self, to),
            (Self::Pending, Self::Running)
                | (Self::Running, Self::Finished)
                | (Self::Pending | Self::Running, Self::Failed)
        );
        if !allowed {
            return Err(InvalidImportTransition { from: self, to });
        }
        Ok(to)
    }

    /// The status's name, stable across releases.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Finished => "finished",
            Self::Failed => "failed",
        }
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidImportTransition);

/// Where an import stands, with when it ended once it has.
///
/// One value, not a status beside an optional time, so an ended import
/// always has its end time and no other state has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportState {
    /// Kept, waiting for the worker.
    Pending,
    /// The worker is going through its records.
    Running,
    /// Every record is worked through.
    Finished {
        /// When the last chunk was kept.
        at: OffsetDateTime,
    },
    /// The worker gave up on it.
    Failed {
        /// When it gave up.
        at: OffsetDateTime,
    },
}

impl ImportState {
    /// Its status, without the time.
    #[must_use]
    pub fn status(self) -> ImportStatus {
        match self {
            Self::Pending => ImportStatus::Pending,
            Self::Running => ImportStatus::Running,
            Self::Finished { .. } => ImportStatus::Finished,
            Self::Failed { .. } => ImportStatus::Failed,
        }
    }

    /// When it ended, finished or given up on.
    #[must_use]
    pub fn ended_at(self) -> Option<OffsetDateTime> {
        match self {
            Self::Pending | Self::Running => None,
            Self::Finished { at } | Self::Failed { at } => Some(at),
        }
    }

    /// Whether it fits `done` of `total` records worked through: none done
    /// while pending, some left while running, all done once finished.
    #[must_use]
    pub fn fits_progress(self, done: usize, total: usize) -> bool {
        match self {
            Self::Pending => done == 0,
            Self::Running => done < total,
            Self::Finished { .. } => done == total,
            Self::Failed { .. } => done <= total,
        }
    }

    /// The state an import moves to when it is moved to `status` at `now`.
    pub(crate) fn moved_to(status: ImportStatus, now: OffsetDateTime) -> Self {
        match status {
            ImportStatus::Pending => Self::Pending,
            ImportStatus::Running => Self::Running,
            ImportStatus::Finished => Self::Finished { at: now },
            ImportStatus::Failed => Self::Failed { at: now },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A finished import cannot start running again, nor fail after the
    /// fact.
    #[test]
    fn a_finished_import_moves_nowhere() {
        assert!(
            ImportStatus::Finished
                .try_transition(ImportStatus::Running)
                .is_err()
        );
        assert!(
            ImportStatus::Finished
                .try_transition(ImportStatus::Failed)
                .is_err()
        );
    }

    /// An import never finishes without having run.
    #[test]
    fn a_pending_import_cannot_finish() {
        assert!(
            ImportStatus::Pending
                .try_transition(ImportStatus::Finished)
                .is_err()
        );
    }

    /// An import the worker never took up may still be given up on.
    #[test]
    fn a_pending_import_may_fail() {
        assert_eq!(
            ImportStatus::Pending.try_transition(ImportStatus::Failed),
            Ok(ImportStatus::Failed)
        );
    }

    /// A finished import says when it finished; a running one has no end.
    #[test]
    fn only_an_ended_import_has_an_end_time() {
        let now = crate::shared::clock::now();

        assert_eq!(ImportState::Finished { at: now }.ended_at(), Some(now));
        assert_eq!(ImportState::Running.ended_at(), None);
    }
}

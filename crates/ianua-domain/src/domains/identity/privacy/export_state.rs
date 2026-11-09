//! Where a request for a copy of a person's data stands.

use time::{Duration, OffsetDateTime};

use crate::shared::errors::DomainError;

/// Where an export request stands.
///
/// The allowed moves:
/// - `Requested` to `Ready`, once the file is gathered.
/// - `Ready` to `Expired`, once its download window is over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExportStatus {
    /// Asked for; the file is being gathered.
    Requested,
    /// The file may be downloaded until its window ends.
    Ready,
    /// The window ended and the file is gone.
    Expired,
}

/// An export status change the rules refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move a data export from {from:?} to {to:?}")]
pub struct InvalidExportTransition {
    /// The current status.
    pub from: ExportStatus,
    /// The status asked for.
    pub to: ExportStatus,
}

impl ExportStatus {
    /// Moves to `to`.
    ///
    /// # Errors
    ///
    /// - [`InvalidExportTransition`] when the move is not one of the moves
    ///   listed on [`ExportStatus`].
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidExportTransition> {
        let allowed = matches!(
            (self, to),
            (Self::Requested, Self::Ready) | (Self::Ready, Self::Expired)
        );
        if !allowed {
            return Err(InvalidExportTransition { from: self, to });
        }
        Ok(to)
    }

    /// The status's name, stable across releases.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Ready => "ready",
            Self::Expired => "expired",
        }
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidExportTransition);

/// Where an export request stands, with the times its status has.
///
/// One value, not a status beside optional times, so a ready export always
/// has the window it may be downloaded in, and no other state has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportState {
    /// Asked for; the file is being gathered.
    Requested,
    /// The file may be downloaded.
    Ready {
        /// When it was ready.
        at: OffsetDateTime,
        /// Until when it may be downloaded.
        available_until: OffsetDateTime,
    },
    /// The window ended and the file is gone.
    Expired,
}

impl ExportState {
    /// The [`ExportStatus`] for this state.
    #[must_use]
    pub fn status(self) -> ExportStatus {
        match self {
            Self::Requested => ExportStatus::Requested,
            Self::Ready { .. } => ExportStatus::Ready,
            Self::Expired => ExportStatus::Expired,
        }
    }

    /// Reads a state back from its stored status and times.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when a ready export lacks either
    ///   time, or another status has one.
    pub fn from_stored(
        status: ExportStatus,
        ready_at: Option<OffsetDateTime>,
        available_until: Option<OffsetDateTime>,
    ) -> Result<Self, DomainError> {
        match (status, ready_at, available_until) {
            (ExportStatus::Requested, None, None) => Ok(Self::Requested),
            (ExportStatus::Ready, Some(at), Some(available_until)) => Ok(Self::Ready {
                at,
                available_until,
            }),
            (ExportStatus::Expired, None, None) => Ok(Self::Expired),
            (status, _, _) => Err(DomainError::infra_msg(format!(
                "stored {} data export has times that contradict it",
                status.as_str()
            ))),
        }
    }

    /// When it was ready, while it is. Storage keeps it this way.
    #[must_use]
    pub fn ready_at(self) -> Option<OffsetDateTime> {
        match self {
            Self::Ready { at, .. } => Some(at),
            Self::Requested | Self::Expired => None,
        }
    }

    /// Until when it may be downloaded, while it is ready. Storage keeps it
    /// this way.
    #[must_use]
    pub fn available_until(self) -> Option<OffsetDateTime> {
        match self {
            Self::Ready {
                available_until, ..
            } => Some(available_until),
            Self::Requested | Self::Expired => None,
        }
    }

    /// Whether the file may be downloaded at `now`.
    #[must_use]
    pub fn downloadable_at(self, now: OffsetDateTime) -> bool {
        match self {
            Self::Ready {
                at,
                available_until,
            } => at <= now && now < available_until,
            Self::Requested | Self::Expired => false,
        }
    }

    /// Whether a ready export may be downloaded for exactly `window`. A
    /// state with no window keeps it trivially.
    #[must_use]
    pub fn keeps_the_download_window(self, window: Duration) -> bool {
        match self {
            Self::Ready {
                at,
                available_until,
            } => crate::shared::clock::between(at, available_until) == window,
            Self::Requested | Self::Expired => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request moves to ready and then to expired. It never skips ready,
    /// and an expired one never comes back.
    #[test]
    fn an_export_moves_from_requested_through_ready_to_expired() {
        assert!(
            ExportStatus::Requested
                .try_transition(ExportStatus::Ready)
                .is_ok()
        );
        assert!(
            ExportStatus::Ready
                .try_transition(ExportStatus::Expired)
                .is_ok()
        );
        assert!(
            ExportStatus::Requested
                .try_transition(ExportStatus::Expired)
                .is_err()
        );
        assert!(
            ExportStatus::Expired
                .try_transition(ExportStatus::Ready)
                .is_err()
        );
    }

    /// A stored ready export without its window, and a stored requested one
    /// with a ready time, are refused. A ready one with both reads back.
    #[test]
    fn a_stored_state_is_read_only_with_the_times_it_has() {
        let now = crate::shared::clock::now();

        assert!(ExportState::from_stored(ExportStatus::Ready, Some(now), None).is_err());
        assert!(ExportState::from_stored(ExportStatus::Requested, Some(now), None).is_err());
        assert_eq!(
            ExportState::from_stored(ExportStatus::Ready, Some(now), Some(now)).unwrap(),
            ExportState::Ready {
                at: now,
                available_until: now
            }
        );
    }

    /// A ready export may be downloaded from the moment it is ready until
    /// just before its window ends.
    #[test]
    fn a_ready_export_is_downloadable_inside_its_window() {
        let now = crate::shared::clock::now();
        let state = ExportState::Ready {
            at: now,
            available_until: now + Duration::days(7),
        };

        assert!(state.downloadable_at(now));
        assert!(state.downloadable_at(now + Duration::days(6)));
        assert!(!state.downloadable_at(now + Duration::days(7)));
        assert!(!ExportState::Requested.downloadable_at(now));
    }
}

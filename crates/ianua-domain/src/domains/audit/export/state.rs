//! Where an export of the audit log stands.

use time::{Duration, OffsetDateTime};

use crate::domains::audit::export::seal::FileDigest;

/// Where an export stands.
///
/// The allowed moves:
/// - `Pending` to `Ready`, once the file is written.
/// - `Pending` to `Failed`, once it was not written in time.
/// - `Ready` to `Expired`, once its download window is over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditExportStatus {
    /// Asked for; the worker is writing the file.
    Pending,
    /// The file may be downloaded until its window ends.
    Ready,
    /// The file was not written in time; nothing is kept.
    Failed,
    /// The window ended and the file is gone.
    Expired,
}

/// An export status change the rules refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move an audit log export from {from:?} to {to:?}")]
pub struct InvalidAuditExportTransition {
    /// The current status.
    pub from: AuditExportStatus,
    /// The status asked for.
    pub to: AuditExportStatus,
}

impl AuditExportStatus {
    /// Moves to `to`.
    ///
    /// # Errors
    ///
    /// - [`InvalidAuditExportTransition`] when the move is not one of the
    ///   moves listed on [`AuditExportStatus`].
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidAuditExportTransition> {
        let allowed = matches!(
            (self, to),
            (Self::Pending, Self::Ready | Self::Failed) | (Self::Ready, Self::Expired)
        );
        if !allowed {
            return Err(InvalidAuditExportTransition { from: self, to });
        }
        Ok(to)
    }

    /// The status's name, stable across releases.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidAuditExportTransition);

/// Where an export stands, with what its status has.
///
/// One value, not a status beside optional times, so a ready export always
/// has its window and its count, and no other state has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditExportState {
    /// Asked for; the worker is writing the file.
    Pending,
    /// The file may be downloaded.
    Ready {
        /// When it was written.
        at: OffsetDateTime,
        /// Until when it may be downloaded.
        available_until: OffsetDateTime,
        /// How many records it holds.
        rows: u64,
        /// The file's SHA-256, taken as it was written.
        digest: FileDigest,
    },
    /// The file was not written in time.
    Failed {
        /// When it was given up on.
        at: OffsetDateTime,
    },
    /// The window ended and the file is gone.
    Expired,
}

impl AuditExportState {
    /// The [`AuditExportStatus`] for this state.
    #[must_use]
    pub fn status(self) -> AuditExportStatus {
        match self {
            Self::Pending => AuditExportStatus::Pending,
            Self::Ready { .. } => AuditExportStatus::Ready,
            Self::Failed { .. } => AuditExportStatus::Failed,
            Self::Expired => AuditExportStatus::Expired,
        }
    }

    /// When the state began, for the states that keep it.
    #[must_use]
    pub fn since(self) -> Option<OffsetDateTime> {
        match self {
            Self::Ready { at, .. } | Self::Failed { at } => Some(at),
            Self::Pending | Self::Expired => None,
        }
    }

    /// Whether the file may be downloaded at `now`.
    #[must_use]
    pub fn downloadable_at(self, now: OffsetDateTime) -> bool {
        match self {
            Self::Ready {
                at,
                available_until,
                ..
            } => at <= now && now < available_until,
            Self::Pending | Self::Failed { .. } | Self::Expired => false,
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
                ..
            } => crate::shared::clock::between(at, available_until) == window,
            Self::Pending | Self::Failed { .. } | Self::Expired => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An export moves from pending to ready to expired, or from pending
    /// to failed. A failed one never becomes ready, and an expired one never
    /// comes back.
    #[test]
    fn an_export_moves_forward_only() {
        assert!(
            AuditExportStatus::Pending
                .try_transition(AuditExportStatus::Ready)
                .is_ok()
        );
        assert!(
            AuditExportStatus::Pending
                .try_transition(AuditExportStatus::Failed)
                .is_ok()
        );
        assert!(
            AuditExportStatus::Ready
                .try_transition(AuditExportStatus::Expired)
                .is_ok()
        );
        assert!(
            AuditExportStatus::Failed
                .try_transition(AuditExportStatus::Ready)
                .is_err()
        );
        assert!(
            AuditExportStatus::Expired
                .try_transition(AuditExportStatus::Ready)
                .is_err()
        );
    }

    /// A ready export may be downloaded from the moment it is written until
    /// just before its window ends; a pending one never.
    #[test]
    fn a_ready_export_is_downloadable_inside_its_window() {
        let now = crate::shared::clock::now();
        let state = AuditExportState::Ready {
            at: now,
            available_until: now + Duration::days(7),
            rows: 3,
            digest: FileDigest::from_bytes(&[0; 32]).unwrap(),
        };

        assert!(state.downloadable_at(now));
        assert!(!state.downloadable_at(now + Duration::days(7)));
        assert!(!AuditExportState::Pending.downloadable_at(now));
    }
}

//! Records organization metric snapshots that back the trend baselines.

use std::sync::Arc;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::metrics::MetricSnapshotWriter;
use crate::use_case::Command;

/// The ports [`CaptureSnapshotsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CaptureSnapshotsPorts {
    /// Where the snapshots are written.
    pub writer: Arc<dyn MetricSnapshotWriter>,
}

/// Captures a point-in-time snapshot of every organization's counts.
///
/// Run on a fixed interval by the background worker, so it takes no caller.
/// Each run appends one snapshot row per organization, and one per tenant
/// that is not deleted or archived; the metrics overviews later read the
/// snapshot nearest a window boundary to compute an exact baseline.
pub struct CaptureSnapshotsUseCase {
    ports: CaptureSnapshotsPorts,
}

impl CaptureSnapshotsUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: CaptureSnapshotsPorts) -> Self {
        Self { ports }
    }
}

impl Command for CaptureSnapshotsUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<u64, AppError>;

    /// Captures one snapshot per organization and per live tenant, returning
    /// how many organizations were snapshotted.
    ///
    /// Records nothing: a snapshot copies counts the metrics overview reads
    /// back, it changes nothing anyone set, and a record per interval would
    /// bury every real change in the audit log.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the snapshot write fails.
    async fn execute(&self, (): &(), _auditor: &RequestAuditor, (): ()) -> Result<u64, AppError> {
        self.ports.writer.capture_all().await.or_internal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeEventDispatcher, FakeSnapshotWriter, block_on, test_auditor};

    fn capture_with(writer: FakeSnapshotWriter) -> Result<u64, AppError> {
        let uc = CaptureSnapshotsUseCase::new(CaptureSnapshotsPorts {
            writer: Arc::new(writer),
        });
        block_on(uc.execute(&(), &test_auditor(Arc::new(FakeEventDispatcher::new())), ()))
    }

    /// The worker snapshots seven organizations and reports seven.
    #[test]
    fn returns_number_of_snapshots_captured() {
        let captured = capture_with(FakeSnapshotWriter::Capturing(7)).unwrap();

        assert_eq!(captured, 7);
    }

    /// The snapshot store cannot be written. The run fails as internal
    /// rather than reporting nothing captured.
    #[test]
    fn maps_writer_failure_to_internal_error() {
        let result = capture_with(FakeSnapshotWriter::Failing);

        assert!(matches!(result, Err(AppError::Internal(_))));
    }
}

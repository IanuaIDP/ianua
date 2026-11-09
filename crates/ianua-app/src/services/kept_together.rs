//! Keeping a change and the record of it together outside a request.
//!
//! Inside a request the API runs all of it as one unit of work. Work that runs
//! outside one, such as a sweep, a job or a reaction to an event, wraps each
//! change and its audit record in a unit of its own, so the two are kept or
//! dropped together without a transaction held open across the slow parts of
//! the work, such as a DNS lookup or a certificate order. Inside a request the
//! unit joins the request's own.
//!
//! [`kept_apart`] keeps its work in a unit of its own even inside a request,
//! for work a worker must see while the request still waits on it.

use std::future::Future;

use crate::error::{AppError, OrInternal};
use crate::ports::runtime::{Settlement, UnitOfWork, atomically, atomically_apart};

/// Runs `work` as one unit: kept if it succeeds, dropped if it fails.
///
/// # Errors
///
/// Returns the error `work` failed with, or `AppError::Internal` if what it
/// wrote cannot be committed, in which case none of it was kept.
pub async fn kept_together<T: Send>(
    unit: &dyn UnitOfWork,
    work: impl Future<Output = Result<T, AppError>> + Send,
) -> Result<T, AppError> {
    atomically(unit, work, settlement_for).await.or_internal()?
}

/// Runs `work` as a unit of its own, kept if it succeeds and dropped if it
/// fails, and settled when it ends even inside a request: others see what it
/// kept at once, whatever the request goes on to answer.
///
/// # Errors
///
/// Returns the error `work` failed with, or `AppError::Internal` if what it
/// wrote cannot be committed, in which case none of it was kept.
pub async fn kept_apart<T: Send>(
    unit: &dyn UnitOfWork,
    work: impl Future<Output = Result<T, AppError>> + Send,
) -> Result<T, AppError> {
    atomically_apart(unit, work, settlement_for)
        .await
        .or_internal()?
}

fn settlement_for<T>(outcome: &Result<T, AppError>) -> Settlement {
    match outcome {
        Ok(_) => Settlement::Commit,
        Err(_) => Settlement::Rollback,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{RecordingUnitOfWork, block_on};

    /// A sweep's change and its audit record both succeed, so both are kept
    /// and the work's result comes back.
    #[test]
    fn work_that_succeeds_is_kept() {
        let unit = RecordingUnitOfWork::default();

        let output = block_on(kept_together(&unit, async { Ok(7) })).unwrap();

        assert_eq!(output, 7);
        assert_eq!(unit.settlements(), [Settlement::Commit]);
    }

    /// A conflict rolls back the unit of work and returns the original error.
    #[test]
    fn work_that_fails_is_dropped_and_its_error_returned() {
        let unit = RecordingUnitOfWork::default();

        let result: Result<(), AppError> = block_on(kept_together(&unit, async {
            Err(AppError::Conflict("taken".to_owned().into()))
        }));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(unit.settlements(), [Settlement::Rollback]);
    }
}

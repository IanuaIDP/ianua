//! Trying work again at once on a fresh read when the record it saved over
//! moved on.
//!
//! Background work that saves a record only over the version it read, such
//! as a tenant's setup whose sibling steps finish at the same moment, is
//! refused with a conflict when another saved the record first. The unit it
//! ran in rolled back, so nothing it wrote is kept. It reads the record
//! again and tries at once, a few times, rather than waiting minutes on the
//! job queue's backoff for a refusal that only says it lost a race.

use std::future::Future;

use crate::error::AppError;

/// How many times work refused as stale is tried in all. A setup has at
/// most three steps running at once, so a step loses at most two races.
const TRIES: usize = 5;

/// What `attempt` answers, tried again at once while it is refused as a
/// conflict, at most [`TRIES`] times in all. Each try must read what it
/// saves afresh, or it is refused the same way again.
///
/// # Errors
///
/// The last try's error: `AppError::Conflict` when every try lost its
/// race, or whatever else a try failed with, at once.
pub(crate) async fn tried_on_fresh_reads<T, F, Fut>(mut attempt: F) -> Result<T, AppError>
where
    F: FnMut() -> Fut + Send,
    Fut: Future<Output = Result<T, AppError>> + Send,
{
    for _ in 1..TRIES {
        match attempt().await {
            Err(AppError::Conflict(_)) => continue,
            settled => return settled,
        }
    }
    attempt().await
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::test_support::block_on;

    /// Work that lost its race twice is tried again at once, and the third
    /// try's answer comes back.
    #[test]
    fn work_refused_as_stale_is_tried_again() {
        let tries = AtomicUsize::new(0);

        let answer = block_on(tried_on_fresh_reads(|| {
            let tried = tries.fetch_add(1, Ordering::SeqCst);
            async move {
                if tried < 2 {
                    return Err(AppError::Conflict("moved on".to_owned().into()));
                }
                Ok(tried)
            }
        }));

        assert_eq!(answer.unwrap(), 2);
        assert_eq!(tries.load(Ordering::SeqCst), 3);
    }

    /// An infrastructure failure is returned after the first attempt without
    /// being retried as a conflict.
    #[test]
    fn another_failure_comes_back_at_once() {
        let tries = AtomicUsize::new(0);

        let answer: Result<(), AppError> = block_on(tried_on_fresh_reads(|| {
            tries.fetch_add(1, Ordering::SeqCst);
            async { Err(AppError::internal_msg("the database is gone")) }
        }));

        assert!(matches!(answer, Err(AppError::Internal(_))));
        assert_eq!(tries.load(Ordering::SeqCst), 1);
    }

    /// Work that loses every race ends as a conflict after its last try,
    /// so the job behind it is tried again later.
    #[test]
    fn work_that_always_loses_ends_as_a_conflict() {
        let tries = AtomicUsize::new(0);

        let answer: Result<(), AppError> = block_on(tried_on_fresh_reads(|| {
            tries.fetch_add(1, Ordering::SeqCst);
            async { Err(AppError::Conflict("moved on".to_owned().into())) }
        }));

        assert!(matches!(answer, Err(AppError::Conflict(_))));
        assert_eq!(tries.load(Ordering::SeqCst), TRIES);
    }
}

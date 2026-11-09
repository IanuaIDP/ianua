//! Unit of work: the port that makes a stretch of work atomic.
//!
//! Every write the stores make while a unit runs, and every audit record
//! dispatched during it, is kept or dropped together. That is what stops a
//! change from being saved without the record of who made it, or a record
//! from describing a change that never happened.

use std::future::Future;
use std::pin::Pin;

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;

/// The work a unit runs, ending with what to do with its writes.
pub type UnitWork<'a> = Pin<Box<dyn Future<Output = Settlement> + Send + 'a>>;

/// What a unit of work does with its writes once its work has finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settlement {
    /// Keep every write, and the audit records that describe them.
    Commit,
    /// Drop every write, and the audit records with them.
    Rollback,
}

/// Dyn-safe port that runs work as one atomic unit.
#[async_trait]
pub trait UnitOfWork: Send + Sync {
    /// Runs `work` and settles its writes as it decides.
    ///
    /// A unit started while another is running joins it: the outer unit
    /// settles everything.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the writes cannot be
    /// committed. None of them were kept.
    async fn run<'a>(&'a self, work: UnitWork<'a>) -> Result<(), DomainError>;

    /// Runs `work` as a unit of its own, settled when it ends, even while
    /// another unit is running: others see what it kept at once, whatever
    /// the running unit later decides. For work another process must see
    /// while the request that started it still waits.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the writes cannot be
    /// committed. None of them were kept.
    async fn run_apart<'a>(&'a self, work: UnitWork<'a>) -> Result<(), DomainError>;
}

/// Whether a unit started while another runs joins it or stands apart.
#[derive(Clone, Copy)]
enum Standing {
    /// It joins the running unit, which settles everything.
    Joined,
    /// It settles on its own.
    Apart,
}

/// Runs `work` as one unit, settling its writes by what `settle` says about
/// its output, and returns that output.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` if the writes cannot be committed.
/// None of them were kept, and the output is dropped with them.
pub async fn atomically<T, W, S>(
    unit: &dyn UnitOfWork,
    work: W,
    settle: S,
) -> Result<T, DomainError>
where
    T: Send,
    W: Future<Output = T> + Send,
    S: FnOnce(&T) -> Settlement + Send,
{
    settled(unit, Standing::Joined, work, settle).await
}

/// Runs `work` as a unit of its own, as [`UnitOfWork::run_apart`] does,
/// settling its writes by what `settle` says about its output, and returns
/// that output.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` if the writes cannot be committed.
/// None of them were kept, and the output is dropped with them.
pub async fn atomically_apart<T, W, S>(
    unit: &dyn UnitOfWork,
    work: W,
    settle: S,
) -> Result<T, DomainError>
where
    T: Send,
    W: Future<Output = T> + Send,
    S: FnOnce(&T) -> Settlement + Send,
{
    settled(unit, Standing::Apart, work, settle).await
}

/// `work`'s output once `unit` ran it standing as `standing` and settled
/// it as `settle` says.
async fn settled<T, W, S>(
    unit: &dyn UnitOfWork,
    standing: Standing,
    work: W,
    settle: S,
) -> Result<T, DomainError>
where
    T: Send,
    W: Future<Output = T> + Send,
    S: FnOnce(&T) -> Settlement + Send,
{
    let mut output = None;
    let run: UnitWork<'_> = Box::pin(async {
        let finished = work.await;
        let settlement = settle(&finished);
        output = Some(finished);
        settlement
    });
    match standing {
        Standing::Joined => unit.run(run).await?,
        Standing::Apart => unit.run_apart(run).await?,
    }
    output.ok_or_else(|| DomainError::infra_msg("the unit of work never ran its work"))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::test_support::block_on;

    #[derive(Default)]
    struct RecordingUnit {
        settled: Mutex<Option<Settlement>>,
    }

    #[async_trait]
    impl UnitOfWork for RecordingUnit {
        async fn run<'a>(&'a self, work: UnitWork<'a>) -> Result<(), DomainError> {
            let settlement = work.await;
            *self.settled.lock().unwrap() = Some(settlement);
            Ok(())
        }

        async fn run_apart<'a>(&'a self, work: UnitWork<'a>) -> Result<(), DomainError> {
            self.run(work).await
        }
    }

    struct BrokenUnit;

    #[async_trait]
    impl UnitOfWork for BrokenUnit {
        async fn run<'a>(&'a self, work: UnitWork<'a>) -> Result<(), DomainError> {
            work.await;
            Err(DomainError::infra_msg("the commit failed"))
        }

        async fn run_apart<'a>(&'a self, work: UnitWork<'a>) -> Result<(), DomainError> {
            self.run(work).await
        }
    }

    /// Work run in one transaction hands back its result, and the transaction
    /// is committed as asked.
    #[test]
    fn the_output_comes_back_and_is_settled_as_asked() {
        let unit = RecordingUnit::default();

        let output = block_on(atomically(&unit, async { 7 }, |_| Settlement::Commit)).unwrap();

        assert_eq!(output, 7);
        assert_eq!(*unit.settled.lock().unwrap(), Some(Settlement::Commit));
    }

    /// The work ends with a 500. Looking at that result, the transaction is
    /// rolled back rather than committed.
    #[test]
    fn the_settlement_is_decided_from_the_output() {
        let unit = RecordingUnit::default();

        block_on(atomically(&unit, async { 500 }, |status| {
            if *status >= 500 {
                return Settlement::Rollback;
            }
            Settlement::Commit
        }))
        .unwrap();

        assert_eq!(*unit.settled.lock().unwrap(), Some(Settlement::Rollback));
    }

    /// The work finishes but the commit fails. The caller gets an error, not
    /// a result that was never saved.
    #[test]
    fn a_failed_commit_is_an_error_not_the_output() {
        let result = block_on(atomically(&BrokenUnit, async { 7 }, |_| Settlement::Commit));

        assert!(result.is_err());
    }
}

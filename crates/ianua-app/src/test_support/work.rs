//! Units of work and bulk revocations, as the fakes carry them out.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;

use crate::test_support::Fake;

/// Whether a fake store's bulk session revocation goes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Revocation {
    /// Revoking succeeds.
    #[default]
    Succeeds,
    /// Revoking fails as if the store were unreachable.
    Fails,
}

/// Unit of work that runs the work and keeps nothing apart: the fakes write
/// straight through, so there is nothing to commit or roll back.
pub struct PassThroughUnitOfWork;

#[async_trait]
impl crate::ports::runtime::UnitOfWork for PassThroughUnitOfWork {
    async fn run_apart<'a>(
        &'a self,
        work: crate::ports::runtime::UnitWork<'a>,
    ) -> Result<(), DomainError> {
        self.run(work).await
    }

    async fn run<'a>(
        &'a self,
        work: crate::ports::runtime::UnitWork<'a>,
    ) -> Result<(), DomainError> {
        work.await;
        Ok(())
    }
}

/// Unit of work that runs the work and remembers how each unit was settled,
/// so a test can see that work ran as one unit and how it ended.
#[derive(Default)]
pub struct RecordingUnitOfWork {
    settlements: Mutex<Vec<crate::ports::runtime::Settlement>>,
    apart: Mutex<Vec<crate::ports::runtime::Settlement>>,
}

impl RecordingUnitOfWork {
    /// How each unit run so far was settled, in order.
    pub fn settlements(&self) -> Vec<crate::ports::runtime::Settlement> {
        self.settlements.lock().unwrap().clone()
    }

    /// How each unit run apart so far was settled, in order.
    pub fn apart(&self) -> Vec<crate::ports::runtime::Settlement> {
        self.apart.lock().unwrap().clone()
    }
}

#[async_trait]
impl crate::ports::runtime::UnitOfWork for RecordingUnitOfWork {
    async fn run_apart<'a>(
        &'a self,
        work: crate::ports::runtime::UnitWork<'a>,
    ) -> Result<(), DomainError> {
        let settlement = work.await;
        self.apart.lock().unwrap().push(settlement);
        Ok(())
    }

    async fn run<'a>(
        &'a self,
        work: crate::ports::runtime::UnitWork<'a>,
    ) -> Result<(), DomainError> {
        let settlement = work.await;
        self.settlements.lock().unwrap().push(settlement);
        Ok(())
    }
}

/// A fake store a unit of work can put back as it was, so a unit the work
/// settles to roll back leaves nothing it wrote, as storage does.
pub trait Rewind: Send + Sync {
    /// What the store holds now, put back when the answer is called.
    fn mark(&self) -> Box<dyn FnOnce() + Send + Sync + '_>;
}

/// Unit of work that keeps the stores it is given all or nothing: a unit
/// settled to roll back, on any error its work returned, puts each of them
/// back as it was when the unit began. Nested units are kept the same way,
/// each on its own. Stores it is not given write straight through.
pub struct RewindingUnitOfWork {
    stores: Vec<Arc<dyn Rewind>>,
}

impl RewindingUnitOfWork {
    /// A unit of work over `stores`.
    #[must_use]
    pub fn over(stores: Vec<Arc<dyn Rewind>>) -> Self {
        Self { stores }
    }
}

#[async_trait]
impl crate::ports::runtime::UnitOfWork for RewindingUnitOfWork {
    async fn run_apart<'a>(
        &'a self,
        work: crate::ports::runtime::UnitWork<'a>,
    ) -> Result<(), DomainError> {
        self.run(work).await
    }

    async fn run<'a>(
        &'a self,
        work: crate::ports::runtime::UnitWork<'a>,
    ) -> Result<(), DomainError> {
        let marks: Vec<_> = self.stores.iter().map(|store| store.mark()).collect();
        if work.await == crate::ports::runtime::Settlement::Rollback {
            marks.into_iter().for_each(|put_back| put_back());
        }
        Ok(())
    }
}

impl Fake for Arc<dyn crate::ports::runtime::UnitOfWork> {
    fn fake() -> Self {
        Arc::new(PassThroughUnitOfWork)
    }
}

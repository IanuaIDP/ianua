//! Fakes for tenant clones: where they are kept and what copies their
//! parts.

use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::tenant::clone::{ClonePart, CloneState, TenantClone, TenantCloneRow};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{TenantCloneId, TenantId};

use crate::ports::tenant::{ClonePartCopier, TenantCloneStore};
use crate::test_support::Fake;
use crate::test_support::scheduling::FakeJobQueue;
use crate::use_cases::tenant::clones::CloneRuns;

/// In-memory clone store, keeping each clone as its row.
#[derive(Default)]
pub struct FakeTenantCloneStore {
    clones: Mutex<Vec<TenantCloneRow>>,
}

impl FakeTenantCloneStore {
    /// A store holding no clone.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// The clone `id` as last saved.
    ///
    /// # Panics
    ///
    /// If the saved row no longer reads back, which a fake never stores.
    #[must_use]
    pub fn stored(&self, id: &TenantCloneId) -> Option<TenantClone> {
        self.clones
            .lock()
            .unwrap()
            .iter()
            .find(|row| row.id == *id)
            .map(|row| TenantClone::reconstitute(copy_row(row)).expect("a saved clone reads back"))
    }

    /// How many clones are kept.
    #[must_use]
    pub fn count(&self) -> usize {
        self.clones.lock().unwrap().len()
    }
}

#[async_trait]
impl TenantCloneStore for FakeTenantCloneStore {
    async fn find_by_id(&self, id: &TenantCloneId) -> Result<Option<TenantClone>, DomainError> {
        let row = self
            .clones
            .lock()
            .unwrap()
            .iter()
            .find(|row| row.id == *id)
            .map(copy_row);
        row.map(TenantClone::reconstitute).transpose()
    }

    async fn copying_into(&self, target: &TenantId) -> Result<bool, DomainError> {
        Ok(self
            .clones
            .lock()
            .unwrap()
            .iter()
            .any(|row| row.target == *target && row.state == CloneState::Copying))
    }

    async fn save(&self, clone: &TenantClone) -> Result<(), DomainError> {
        let mut clones = self.clones.lock().unwrap();
        clones.retain(|row| row.id != *clone.id());
        clones.push(row_of(clone));
        Ok(())
    }
}

impl Fake for Arc<dyn TenantCloneStore> {
    fn fake() -> Self {
        Arc::new(FakeTenantCloneStore::empty())
    }
}

/// A clone as storage would write it.
fn row_of(clone: &TenantClone) -> TenantCloneRow {
    TenantCloneRow {
        id: *clone.id(),
        organization_id: *clone.organization_id(),
        source: *clone.source(),
        target: *clone.target(),
        parts: clone.parts().to_vec(),
        copied: clone.copied().to_vec(),
        state: clone.state(),
        started_at: clone.started_at(),
    }
}

/// A second copy of a stored row.
fn copy_row(row: &TenantCloneRow) -> TenantCloneRow {
    TenantCloneRow {
        id: row.id,
        organization_id: row.organization_id,
        source: row.source,
        target: row.target,
        parts: row.parts.clone(),
        copied: row.copied.clone(),
        state: row.state,
        started_at: row.started_at,
    }
}

/// Copies parts by noting them, failing the one a test names.
#[derive(Default)]
pub struct FakeClonePartCopier {
    copied: Mutex<Vec<ClonePart>>,
    failing: Option<ClonePart>,
}

impl FakeClonePartCopier {
    /// A copier that copies every part.
    #[must_use]
    pub fn copying() -> Self {
        Self::default()
    }

    /// A copier that fails to copy `part` and copies every other.
    #[must_use]
    pub fn failing_on(part: ClonePart) -> Self {
        Self {
            copied: Mutex::new(Vec::new()),
            failing: Some(part),
        }
    }

    /// The parts copied, in order.
    #[must_use]
    pub fn copied(&self) -> Vec<ClonePart> {
        self.copied.lock().unwrap().clone()
    }
}

#[async_trait]
impl ClonePartCopier for FakeClonePartCopier {
    async fn copy(&self, _: &TenantClone, part: ClonePart) -> Result<(), DomainError> {
        if self.failing == Some(part) {
            return Err(DomainError::infra_msg("the copy failed"));
        }
        self.copied.lock().unwrap().push(part);
        Ok(())
    }
}

impl Fake for Arc<dyn ClonePartCopier> {
    fn fake() -> Self {
        Arc::new(FakeClonePartCopier::copying())
    }
}

/// Clone jobs queued on `queue`, tried three times each.
#[must_use]
pub fn clone_runs(queue: Arc<FakeJobQueue>) -> CloneRuns {
    CloneRuns {
        queue,
        attempts: NonZeroU32::new(3).unwrap_or(NonZeroU32::MIN),
    }
}

impl Fake for CloneRuns {
    fn fake() -> Self {
        clone_runs(Arc::new(FakeJobQueue::new()))
    }
}

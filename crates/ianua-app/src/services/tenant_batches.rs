//! Walking every tenant a batch at a time, for the sweeps that look in
//! each one.
//!
//! A sweep never holds every tenant at once. It reads one batch, works
//! through it, and asks for the next from the last id it saw, so the walk
//! costs the same however many tenants there are, and a tenant made or
//! removed meanwhile neither repeats a tenant nor skips one.

use std::num::NonZeroU32;

use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::types::TenantId;

use crate::error::{AppError, OrInternal};
use crate::ports::tenant::TenantStore;

/// How many tenants one batch holds.
const BATCH: NonZeroU32 = NonZeroU32::MIN.saturating_add(499);

/// Where a walk over every tenant stands: the last tenant it handed out.
pub(crate) struct TenantBatches<'a> {
    /// Where the tenants are read from.
    store: &'a dyn TenantStore,
    /// How far the walk has come.
    progress: Progress,
}

/// How far a walk has come.
#[derive(Clone, Copy)]
enum Progress {
    /// Nothing read yet.
    Start,
    /// The last batch ended at this tenant.
    After(TenantId),
    /// The last batch came back short or empty: no tenant follows.
    Done,
}

impl<'a> TenantBatches<'a> {
    /// A walk over every tenant `store` holds, from the first.
    pub(crate) fn over(store: &'a dyn TenantStore) -> Self {
        Self {
            store,
            progress: Progress::Start,
        }
    }

    /// The next batch of tenants, in id order, or `None` once every tenant
    /// was handed out.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the tenants cannot be read.
    pub(crate) async fn next(&mut self) -> Result<Option<Vec<Tenant>>, AppError> {
        let after = match self.progress {
            Progress::Start => None,
            Progress::After(last) => Some(last),
            Progress::Done => return Ok(None),
        };
        let batch = self.store.batch_after(after, BATCH).await.or_internal()?;
        self.progress = progress_after(&batch);
        Ok(Some(batch).filter(|tenants| !tenants.is_empty()))
    }

    /// The ids in the next batch, or `None` once every tenant was handed
    /// out.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the tenants cannot be read.
    pub(crate) async fn next_ids(&mut self) -> Result<Option<Vec<TenantId>>, AppError> {
        let batch = self.next().await?;
        Ok(batch.map(|tenants| tenants.iter().map(|tenant| *tenant.id()).collect()))
    }
}

/// Where a walk stands once `batch` was read: done when it came back short,
/// since no tenant follows, otherwise after its last tenant.
fn progress_after(batch: &[Tenant]) -> Progress {
    let full = batch.len() >= BATCH.get() as usize;
    match batch.last() {
        Some(last) if full => Progress::After(*last.id()),
        Some(_) | None => Progress::Done,
    }
}

/// What one purge across every tenant did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgeReport {
    /// Rows removed across every tenant.
    pub removed: u64,
    /// Tenants that could not be purged this time.
    pub unpurged: u64,
}

impl PurgeReport {
    /// This report with one more purge counted: how many went, or that
    /// none could.
    #[must_use]
    pub(crate) fn counting(self, removed: Option<u64>) -> Self {
        let Some(removed) = removed else {
            return Self {
                unpurged: self.unpurged.saturating_add(1),
                ..self
            };
        };
        Self {
            removed: self.removed.saturating_add(removed),
            ..self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::block_on;
    use crate::test_support::tenant::{FakeTenantStore, test_tenant};

    /// Every tenant's id the walk hands out, batch by batch, in order.
    fn walked(store: &FakeTenantStore) -> Vec<Vec<TenantId>> {
        let mut walk = TenantBatches::over(store);
        let mut batches = Vec::new();
        while let Some(batch) = block_on(walk.next_ids()).unwrap() {
            batches.push(batch);
        }
        batches
    }

    /// Acme has more tenants than one batch holds. The walk hands each out
    /// once, in id order, a batch at a time, and never more than a batch.
    #[test]
    fn every_tenant_is_handed_out_once_a_batch_at_a_time() {
        let count = BATCH.get() as usize + 3;
        let tenants = (0..count)
            .map(|n| test_tenant(&format!("tenant-{n}"), &format!("tenant-{n}.example.test")));
        let store = FakeTenantStore::holding_all(tenants);

        let batches = walked(&store);

        let sizes: Vec<usize> = batches.iter().map(Vec::len).collect();
        assert_eq!(sizes, [BATCH.get() as usize, 3]);
        let ids: Vec<TenantId> = batches.concat();
        let in_order = ids
            .windows(2)
            .all(|pair| pair[0].as_uuid() < pair[1].as_uuid());
        assert!(in_order);
        assert_eq!(ids.len(), count);
    }

    /// A platform with no tenants yet. The walk ends at once.
    #[test]
    fn a_walk_over_no_tenants_hands_out_nothing() {
        let store = FakeTenantStore::empty();

        assert!(walked(&store).is_empty());
    }
}

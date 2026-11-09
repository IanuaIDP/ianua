//! Records the identity fakes keep, each filed under the tenant whose store
//! wrote it.

use std::sync::Mutex;

use ianua_domain::types::TenantId;

use crate::test_support::test_ctx;

/// The tenant a fake's seeding helpers file records under: the one
/// [`test_ctx`] carries, so the use case under test finds them.
pub(super) fn seeded_tenant() -> TenantId {
    test_ctx().tenant_id()
}

/// Records of one kind, each kept with the tenant it belongs to. Every read
/// and write names a tenant and sees only that tenant's records.
pub(super) struct TenantRows<T> {
    rows: Mutex<Vec<(TenantId, T)>>,
}

impl<T> Default for TenantRows<T> {
    fn default() -> Self {
        Self {
            rows: Mutex::new(Vec::new()),
        }
    }
}

impl<T> TenantRows<T> {
    /// Adds `row` to `tenant`'s records.
    pub(super) fn insert(&self, tenant: TenantId, row: T) {
        self.rows.lock().unwrap().push((tenant, row));
    }

    /// Replaces `tenant`'s record that `same` picks with `row`, or adds it.
    pub(super) fn upsert(&self, tenant: TenantId, same: impl Fn(&T) -> bool, row: T) {
        let mut rows = self.rows.lock().unwrap();
        let slot = rows
            .iter_mut()
            .find(|(owner, kept)| *owner == tenant && same(kept));
        match slot {
            Some((_, kept)) => *kept = row,
            None => rows.push((tenant, row)),
        }
    }

    /// `read` of `tenant`'s first record that `pick` matches.
    pub(super) fn find<R>(
        &self,
        tenant: &TenantId,
        pick: impl Fn(&T) -> bool,
        read: impl Fn(&T) -> R,
    ) -> Option<R> {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, row)| owner == tenant && pick(row))
            .map(|(_, row)| read(row))
    }

    /// `read` of each of `tenant`'s records that `keep` matches, in the
    /// order they were added.
    pub(super) fn collect<R>(
        &self,
        tenant: &TenantId,
        keep: impl Fn(&T) -> bool,
        read: impl Fn(&T) -> R,
    ) -> Vec<R> {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, row)| owner == tenant && keep(row))
            .map(|(_, row)| read(row))
            .collect()
    }

    /// Changes each of `tenant`'s records that `pick` matches.
    pub(super) fn update(
        &self,
        tenant: &TenantId,
        pick: impl Fn(&T) -> bool,
        mut change: impl FnMut(&mut T),
    ) {
        self.rows
            .lock()
            .unwrap()
            .iter_mut()
            .filter(|(owner, row)| owner == tenant && pick(row))
            .for_each(|(_, row)| change(row));
    }

    /// Removes each of `tenant`'s records that `pick` matches, and says how
    /// many it removed.
    pub(super) fn remove(&self, tenant: &TenantId, pick: impl Fn(&T) -> bool) -> usize {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|(owner, row)| owner != tenant || !pick(row));
        before - rows.len()
    }

    /// How many records are kept, across every tenant.
    pub(super) fn count(&self) -> usize {
        self.rows.lock().unwrap().len()
    }
}

//! The in-memory table every agent store fake keeps its records on: each
//! record beside the tenant it was saved for, so a lookup for one tenant
//! never sees another's.

use std::sync::Mutex;

use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use crate::tenancy::ScopedTenant;

/// Records kept per tenant, in the order they were first saved.
pub(super) struct Shelf<T> {
    items: Mutex<Vec<(TenantId, T)>>,
}

impl<T> Default for Shelf<T> {
    fn default() -> Self {
        Self {
            items: Mutex::new(Vec::new()),
        }
    }
}

impl<T: Clone + Send + Sync> Shelf<T> {
    /// What the shelf holds now, put back as it is when the answer is
    /// called, as a unit of work rolled back would leave it.
    pub(super) fn mark(&self) -> Box<dyn FnOnce() + Send + Sync + '_> {
        let held = self.items.lock().unwrap().clone();
        Box::new(move || *self.items.lock().unwrap() = held)
    }
}

impl<T: Clone> Shelf<T> {
    /// Saves `item` for `tenant`, in place of the record `same` picks out.
    pub(super) fn put(&self, tenant: &ScopedTenant, item: T, same: impl Fn(&T) -> bool) {
        let mut items = self.items.lock().unwrap();
        let held = items
            .iter()
            .position(|(owner, stored)| owner == &**tenant && same(stored));
        match held {
            Some(index) => items[index] = (**tenant, item),
            None => items.push((**tenant, item)),
        }
    }

    /// The first of `tenant`'s records `wanted` picks out.
    pub(super) fn find(&self, tenant: &ScopedTenant, wanted: impl Fn(&T) -> bool) -> Option<T> {
        self.items
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, stored)| owner == &**tenant && wanted(stored))
            .map(|(_, stored)| stored.clone())
    }

    /// Every one of `tenant`'s records `wanted` picks out, oldest first.
    pub(super) fn filter(&self, tenant: &ScopedTenant, wanted: impl Fn(&T) -> bool) -> Vec<T> {
        self.items
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, stored)| owner == &**tenant && wanted(stored))
            .map(|(_, stored)| stored.clone())
            .collect()
    }

    /// Replaces each of `tenant`'s records `wanted` picks out with what
    /// `change` makes of it, and returns the new records.
    pub(super) fn revise(
        &self,
        tenant: &ScopedTenant,
        wanted: impl Fn(&T) -> bool,
        change: impl Fn(&T) -> Result<T, DomainError>,
    ) -> Result<Vec<T>, DomainError> {
        let mut items = self.items.lock().unwrap();
        let mut revised = Vec::new();
        for (_, stored) in items
            .iter_mut()
            .filter(|(owner, stored)| owner == &**tenant && wanted(stored))
        {
            *stored = change(stored)?;
            revised.push(stored.clone());
        }
        Ok(revised)
    }

    /// Replaces the first of `tenant`'s records `wanted` picks out with what
    /// `change` makes of it, and returns the new record.
    pub(super) fn revise_first(
        &self,
        tenant: &ScopedTenant,
        wanted: impl Fn(&T) -> bool,
        change: impl Fn(&T) -> Result<T, DomainError>,
    ) -> Result<Option<T>, DomainError> {
        let mut items = self.items.lock().unwrap();
        let Some((_, stored)) = items
            .iter_mut()
            .find(|(owner, stored)| owner == &**tenant && wanted(stored))
        else {
            return Ok(None);
        };
        *stored = change(stored)?;
        Ok(Some(stored.clone()))
    }

    /// Removes every one of `tenant`'s records `wanted` picks out.
    pub(super) fn remove(&self, tenant: &ScopedTenant, wanted: impl Fn(&T) -> bool) {
        self.items
            .lock()
            .unwrap()
            .retain(|(owner, stored)| !(owner == &**tenant && wanted(stored)));
    }

    /// Every record kept, whatever its tenant, oldest first.
    pub(super) fn all(&self) -> Vec<T> {
        self.items
            .lock()
            .unwrap()
            .iter()
            .map(|(_, stored)| stored.clone())
            .collect()
    }

    /// How many records are kept, whatever their tenant.
    pub(super) fn count(&self) -> usize {
        self.items.lock().unwrap().len()
    }
}

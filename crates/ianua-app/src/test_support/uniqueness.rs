//! The uniqueness rule an in-memory store keeps, as its real store's unique
//! index does.

use ianua_domain::types::TenantId;

use crate::tenancy::ScopedTenant;

/// Whether `entry`, kept for a tenant, is another record of `tenant` than
/// `candidate` with the same unique key: one a store refuses to keep beside
/// it. `identify` gives a record's unique key and its id.
pub fn rivals<T, K: PartialEq, Id: PartialEq>(
    entry: &(TenantId, T),
    tenant: &ScopedTenant,
    candidate: &T,
    identify: impl Fn(&T) -> (K, Id),
) -> bool {
    let (entry_key, entry_id) = identify(&entry.1);
    let (key, id) = identify(candidate);
    entry.0 == **tenant && entry_key == key && entry_id != id
}

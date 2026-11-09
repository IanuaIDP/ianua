//! An organization's counts as one snapshot kept them. Its other figures
//! are its tenants', read with the tenant figures' own records in
//! `crate::postgres::metrics::tenant::record` and added up.

use crate::postgres::metrics::tenant::record::count;

/// A count an organization's snapshot keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OrgMetric {
    /// The people of all its tenants.
    People,
    /// Counts the isolated account spaces belonging to this organization.
    Tenants,
    /// The active sessions of all its tenants.
    Sessions,
}

/// An organization's counts as one snapshot kept them.
pub(super) struct OrgSnapshotRecord {
    pub(super) users_count: i64,
    pub(super) tenants_count: i64,
    pub(super) active_sessions_count: i64,
}

impl OrgSnapshotRecord {
    /// The count of `metric` the snapshot kept.
    pub(super) fn into_count(self, metric: OrgMetric) -> u64 {
        match metric {
            OrgMetric::People => count(self.users_count),
            OrgMetric::Tenants => count(self.tenants_count),
            OrgMetric::Sessions => count(self.active_sessions_count),
        }
    }
}

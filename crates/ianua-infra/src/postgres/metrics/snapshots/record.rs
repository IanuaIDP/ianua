//! A tenant's counts as they are read for a snapshot, and many of them as
//! one statement keeps them.

use uuid::Uuid;

use crate::postgres::metrics::tenant::record::count;

/// One tenant's counts, read in the database it lives in.
pub(super) struct CountsRecord {
    pub(super) users_count: i64,
    pub(super) active_sessions_count: i64,
}

/// The counts of many tenants, one list per column and one place per
/// tenant.
#[derive(Default)]
pub(super) struct CountsBatch {
    pub(super) tenant_ids: Vec<Uuid>,
    pub(super) users: Vec<i64>,
    pub(super) sessions: Vec<i64>,
}

impl CountsBatch {
    /// The batch `counted` makes, each tenant beside its counts.
    pub(super) fn into_batch(counted: Vec<(Uuid, CountsRecord)>) -> Self {
        let mut batch = Self::default();
        for (tenant, counts) in counted {
            batch.tenant_ids.push(tenant);
            batch.users.push(counts.users_count);
            batch.sessions.push(counts.active_sessions_count);
        }
        batch
    }
}

/// How many organizations one capture kept, as the domain counts them.
pub(super) fn into_captured(captured: i64) -> u64 {
    count(captured)
}

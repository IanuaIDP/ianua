//! A fake of records kept by when they happened, per tenant, removed as a
//! retention passes them: the audit trail, the gateway's request records
//! and its stream records alike.

use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::audit::AuditRetentionStore;
use crate::ports::proxy::RequestRecordRetention;
use crate::ports::routing::StreamRecordRetention;
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// Records of tenants, each with when it happened, removed oldest first.
#[derive(Default)]
pub struct FakeRetainedRecords {
    records: Mutex<Vec<(TenantId, OffsetDateTime)>>,
    failing: Option<TenantId>,
}

impl TenantScoped for FakeRetainedRecords {}

impl FakeRetainedRecords {
    /// Records holding, for `tenant`, one record at each of `times`.
    #[must_use]
    pub fn holding(tenant: TenantId, times: impl IntoIterator<Item = OffsetDateTime>) -> Self {
        let store = Self::default();
        store
            .records
            .lock()
            .unwrap()
            .extend(times.into_iter().map(|at| (tenant, at)));
        store
    }

    /// Records holding, for `tenant`, one record from each of `ages` ago.
    #[must_use]
    pub fn aged(tenant: TenantId, ages: impl IntoIterator<Item = time::Duration>) -> Self {
        let now = clock::now();
        Self::holding(tenant, ages.into_iter().map(|age| now - age))
    }

    /// The same records, failing every removal for `tenant`.
    #[must_use]
    pub fn failing_for(self, tenant: TenantId) -> Self {
        Self {
            failing: Some(tenant),
            ..self
        }
    }

    /// When each of `tenant`'s records left happened, oldest first.
    #[must_use]
    pub fn left(&self, tenant: TenantId) -> Vec<OffsetDateTime> {
        let mut left: Vec<OffsetDateTime> = self
            .records
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, _)| *owner == tenant)
            .map(|(_, at)| *at)
            .collect();
        left.sort();
        left
    }

    /// Removes at most `most` of `tenant`'s records from before `before`,
    /// oldest first, and says how many went.
    fn forget(
        &self,
        tenant: &ScopedTenant,
        before: OffsetDateTime,
        most: u64,
    ) -> Result<u64, DomainError> {
        if self.failing == Some(**tenant) {
            return Err(DomainError::infra_msg("the records are unreachable"));
        }
        let mut records = self.records.lock().unwrap();
        records.sort_by_key(|(_, at)| *at);
        let mut removed = 0_u64;
        records.retain(|(owner, at)| {
            let goes = owner == &**tenant && *at < before && removed < most;
            removed = removed.saturating_add(u64::from(goes));
            !goes
        });
        Ok(removed)
    }
}

#[async_trait]
impl AuditRetentionStore for FakeRetainedRecords {
    async fn purge_before(
        &self,
        tenant_id: &ScopedTenant,
        cutoff: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        self.forget(tenant_id, cutoff, u64::MAX)
    }
}

#[async_trait]
impl RequestRecordRetention for FakeRetainedRecords {
    async fn forget_before(
        &self,
        tenant_id: &ScopedTenant,
        before: OffsetDateTime,
        most: NonZeroU32,
    ) -> Result<u64, DomainError> {
        self.forget(tenant_id, before, u64::from(most.get()))
    }
}

#[async_trait]
impl StreamRecordRetention for FakeRetainedRecords {
    async fn forget_before(
        &self,
        tenant_id: &ScopedTenant,
        before: OffsetDateTime,
        most: NonZeroU32,
    ) -> Result<u64, DomainError> {
        self.forget(tenant_id, before, u64::from(most.get()))
    }
}

impl Fake for Arc<dyn AuditRetentionStore> {
    fn fake() -> Self {
        Arc::new(FakeRetainedRecords::default())
    }
}

impl Fake for Arc<dyn RequestRecordRetention> {
    fn fake() -> Self {
        Arc::new(FakeRetainedRecords::default())
    }
}

impl Fake for Arc<dyn StreamRecordRetention> {
    fn fake() -> Self {
        Arc::new(FakeRetainedRecords::default())
    }
}

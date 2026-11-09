//! In-memory stores for a user's consent records and erasure requests.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::identity::privacy::consent::{
    ConsentDecision, ConsentRecord, ConsentRecordRow, ConsentType,
};
use ianua_domain::domains::identity::privacy::erasure::{
    ErasureRequest, ErasureRequestRow, ErasureState, GracePeriod,
};
use ianua_domain::domains::identity::privacy::erasure_status::ErasureStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConsentId, Email, ErasureRequestId, Fact, Label, TokenHash, UserId};

use crate::ports::TenantScoped;
use crate::ports::identity::{ConsentStore, ErasureBatch, ErasureRequestStore};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::identity::held::{TenantRows, seeded_tenant};
use crate::test_support::identity::tokens::hash_of_link;
use crate::use_cases::identity::privacy::ErasurePolicy;

/// `user_id`'s decision on version `v1` of `consent_type`, recorded an hour
/// ago, as storage would hand it back.
///
/// # Panics
///
/// Never: the version is a constant valid label.
#[must_use]
pub fn stored_consent(
    user_id: UserId,
    consent_type: ConsentType,
    decision: ConsentDecision,
) -> ConsentRecord<ResolvedTenant> {
    ConsentRecord::reconstitute(ConsentRecordRow {
        id: ConsentId::new(),
        user_id,
        consent_type,
        granted: decision,
        version: Label::new("version", "v1").expect("a valid version"),
        ip_address: Fact::Unknown,
        recorded_at: clock::now() - time::Duration::hours(1),
    })
    .expect("a consent record is a consistent row")
}

/// A pending erasure of `user_id`, whose cancel link went to `sent_to`,
/// asked `days_ago` days ago with a grace period of `grace_days`, as storage
/// would hand it back. Its cancel link carries `cancel-{user_id}`.
///
/// # Panics
///
/// If `sent_to` is not a valid address, or `grace_days` is outside one to
/// 30. Tests pass values that are valid.
#[must_use]
pub fn stored_erasure(
    user_id: UserId,
    sent_to: &str,
    timing: (i64, i64),
) -> ErasureRequest<ResolvedTenant> {
    stored_erasure_at(user_id, sent_to, timing, ErasureState::Pending)
}

/// The same erasure as [`stored_erasure`], standing at `state`.
///
/// # Panics
///
/// As [`stored_erasure`], or when `state` completed before the grace period
/// was over.
#[must_use]
pub fn stored_erasure_at(
    user_id: UserId,
    sent_to: &str,
    (days_ago, grace_days): (i64, i64),
    state: ErasureState,
) -> ErasureRequest<ResolvedTenant> {
    let requested_at = clock::now() - time::Duration::days(days_ago);
    ErasureRequest::reconstitute(ErasureRequestRow {
        id: ErasureRequestId::new(),
        user_id,
        reason: None,
        state,
        requested_at,
        scheduled_at: requested_at + time::Duration::days(grace_days),
        cancel_token_hash: hash_of_link(&format!("cancel-{user_id}")),
        sent_to: Email::new(sent_to).expect("a valid address"),
    })
    .expect("an erasure inside its bounds is a consistent row")
}

/// In-memory consent records: every grant and withdrawal kept under its
/// tenant, the latest answering for a user.
#[derive(Default)]
pub struct FakeConsentStore {
    records: TenantRows<ConsentRecord<ResolvedTenant>>,
}

impl TenantScoped for FakeConsentStore {}

impl FakeConsentStore {
    /// Nothing held.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// How many records are held, across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.records.count()
    }
}

#[async_trait]
impl ConsentStore for FakeConsentStore {
    async fn find_latest(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        consent_type: ConsentType,
    ) -> Result<Option<ConsentRecord<ResolvedTenant>>, DomainError> {
        let theirs = |record: &ConsentRecord<ResolvedTenant>| {
            record.user_id() == user_id && record.consent_type() == consent_type
        };
        self.records
            .collect(tenant_id, theirs, copy_consent)
            .pop()
            .transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        record: &ConsentRecord<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.records.insert(**tenant_id, copy_consent(record)?);
        Ok(())
    }

    async fn history(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<ConsentRecord<ResolvedTenant>>, DomainError> {
        let theirs = |record: &ConsentRecord<ResolvedTenant>| record.user_id() == user_id;
        self.records
            .collect(tenant_id, theirs, copy_consent)
            .into_iter()
            .rev()
            .collect()
    }
}

impl Fake for Arc<dyn ConsentStore> {
    fn fake() -> Self {
        Arc::new(FakeConsentStore::empty())
    }
}

/// In-memory erasure requests, kept under their tenant.
#[derive(Default)]
pub struct FakeErasureStore {
    requests: TenantRows<ErasureRequest<ResolvedTenant>>,
    due_batches: Mutex<Vec<usize>>,
}

impl TenantScoped for FakeErasureStore {}

impl FakeErasureStore {
    /// The number of due requests materialized by each sweep read.
    #[must_use]
    pub fn due_batch_sizes(&self) -> Vec<usize> {
        self.due_batches.lock().unwrap().clone()
    }

    /// Nothing held.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `request` for the tenant [`test_ctx`] carries.
    ///
    /// [`test_ctx`]: crate::test_support::test_ctx
    #[must_use]
    pub fn holding(request: ErasureRequest<ResolvedTenant>) -> Self {
        let store = Self::empty();
        store.requests.insert(seeded_tenant(), request);
        store
    }

    /// How many requests are held, across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.requests.count()
    }

    /// The status of the seeded tenant's request `id`.
    #[must_use]
    pub fn status_of(&self, id: &ErasureRequestId) -> Option<ErasureStatus> {
        self.requests.find(
            &seeded_tenant(),
            |request| request.id() == id,
            ErasureRequest::status,
        )
    }
}

#[async_trait]
impl ErasureRequestStore for FakeErasureStore {
    async fn find_active_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<ErasureRequest<ResolvedTenant>>, DomainError> {
        let active = |request: &ErasureRequest<ResolvedTenant>| {
            request.user_id() == user_id && is_active(request.status())
        };
        self.requests
            .find(tenant_id, active, copy_request)
            .transpose()
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ErasureRequestId,
    ) -> Result<Option<ErasureRequest<ResolvedTenant>>, DomainError> {
        self.requests
            .find(tenant_id, |request| request.id() == id, copy_request)
            .transpose()
    }

    async fn find_by_cancel_token_hash(
        &self,
        tenant_id: &ScopedTenant,
        cancel_token_hash: &TokenHash,
    ) -> Result<Option<ErasureRequest<ResolvedTenant>>, DomainError> {
        let pick = |request: &ErasureRequest<ResolvedTenant>| {
            request.cancel_token_hash() == cancel_token_hash
        };
        self.requests
            .find(tenant_id, pick, copy_request)
            .transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        request: &ErasureRequest<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let kept = copy_request(request)?;
        self.requests
            .upsert(**tenant_id, |held| held.id() == request.id(), kept);
        Ok(())
    }

    async fn find_due(
        &self,
        tenant_id: &ScopedTenant,
        batch: ErasureBatch,
    ) -> Result<Vec<ErasureRequest<ResolvedTenant>>, DomainError> {
        let due = |request: &ErasureRequest<ResolvedTenant>| {
            awaits_deletion(request.status())
                && request.scheduled_at() <= batch.now
                && batch.after.is_none_or(|after| {
                    (request.scheduled_at(), request.id().as_uuid())
                        > (after.scheduled_at, after.id.as_uuid())
                })
        };
        let mut due: Vec<_> = self.requests.collect(tenant_id, due, |request| {
            (
                (request.scheduled_at(), *request.id().as_uuid()),
                copy_request(request),
            )
        });
        due.sort_by_key(|(position, _)| *position);
        due.truncate(ErasureBatch::LIMIT);
        self.due_batches.lock().unwrap().push(due.len());
        due.into_iter().map(|(_, request)| request).collect()
    }
}

impl Fake for Arc<dyn ErasureRequestStore> {
    fn fake() -> Self {
        Arc::new(FakeErasureStore::empty())
    }
}

/// Erasures wait the 14 days a tenant gives by default, with cancel links on
/// the test address.
impl Fake for ErasurePolicy {
    fn fake() -> Self {
        Self {
            grace_period: GracePeriod::days(14).expect("14 days is a valid grace period"),
            base_url: Fake::fake(),
        }
    }
}

/// Whether a request at `status` is still under way.
fn is_active(status: ErasureStatus) -> bool {
    matches!(status, ErasureStatus::Pending | ErasureStatus::Processing)
}

/// Whether a request at `status` still has to be carried out.
fn awaits_deletion(status: ErasureStatus) -> bool {
    matches!(status, ErasureStatus::Pending | ErasureStatus::Failed)
}

/// A copy of `record`, which does not implement `Clone`, read back as a real
/// store would.
fn copy_consent(
    record: &ConsentRecord<ResolvedTenant>,
) -> Result<ConsentRecord<ResolvedTenant>, DomainError> {
    ConsentRecord::reconstitute(ConsentRecordRow {
        id: *record.id(),
        user_id: *record.user_id(),
        consent_type: record.consent_type(),
        granted: ConsentDecision::from(record.granted()),
        version: record.version().clone(),
        ip_address: record.ip_address().cloned(),
        recorded_at: record.recorded_at(),
    })
}

/// A copy of `request`, which does not implement `Clone`, read back as a
/// real store would.
fn copy_request(
    request: &ErasureRequest<ResolvedTenant>,
) -> Result<ErasureRequest<ResolvedTenant>, DomainError> {
    ErasureRequest::reconstitute(ErasureRequestRow {
        id: *request.id(),
        user_id: *request.user_id(),
        reason: request.reason().cloned(),
        state: request.state(),
        requested_at: request.requested_at(),
        scheduled_at: request.scheduled_at(),
        cancel_token_hash: request.cancel_token_hash().clone(),
        sent_to: request.sent_to().clone(),
    })
}

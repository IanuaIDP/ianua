//! In-memory stores for members' erasure requests and consent records, and
//! the stored rows tests seed them with.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::identity::privacy::consent::{ConsentDecision, ConsentType};
use ianua_domain::domains::identity::privacy::erasure::ErasureState;
use ianua_domain::domains::identity::privacy::erasure_status::ErasureStatus;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::organization::members::privacy::consent::{
    OrgConsentRecord, OrgConsentRecordRow,
};
use ianua_domain::domains::organization::members::privacy::erasure::{
    OrgErasureRequest, OrgErasureRequestRow,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    ConsentId, ErasureRequestId, Fact, Label, OrgUserId, OrganizationId, TokenHash,
};

use crate::ports::identity::ErasureBatch;
use crate::ports::organization::{OrgConsentStore, OrgErasureRequestStore};
use crate::test_support::Fake;
use crate::test_support::identity::hash_of_link;
use crate::use_cases::identity::privacy::ErasurePolicy;
use crate::use_cases::organization::privacy::OrgErasurePolicy;

/// The raw token in the cancel link of an erasure [`stored_org_erasure`]
/// makes for `member`.
#[must_use]
pub fn org_cancel_link(member: &OrgUserId) -> String {
    format!("cancel-{member}")
}

/// An erasure of `member`, asked `days_ago` days ago with a grace period
/// of `grace_days`, standing at `state`, as storage would hand it back. Its
/// cancel link carries [`org_cancel_link`] and went to the member's
/// address.
///
/// # Panics
///
/// If `grace_days` is outside one to 30, or `state` completed before the
/// grace period was over. Tests pass values that hold.
#[must_use]
pub fn stored_org_erasure(
    member: &OrgUser,
    (days_ago, grace_days): (i64, i64),
    state: ErasureState,
) -> OrgErasureRequest {
    let requested_at = clock::now() - time::Duration::days(days_ago);
    OrgErasureRequest::reconstitute(OrgErasureRequestRow {
        id: ErasureRequestId::new(),
        organization_id: *member.organization_id(),
        org_user_id: *member.id(),
        reason: None,
        state,
        requested_at,
        scheduled_at: requested_at + time::Duration::days(grace_days),
        cancel_token_hash: hash_of_link(&org_cancel_link(member.id())),
        sent_to: member.email().clone(),
    })
    .expect("an erasure inside its bounds is a consistent row")
}

/// `member`'s decision on version `v1` of `consent_type`, recorded an hour
/// ago, as storage would hand it back.
///
/// # Panics
///
/// Never: the version is a constant valid label.
#[must_use]
pub fn stored_org_consent(
    member: &OrgUser,
    consent_type: ConsentType,
    decision: ConsentDecision,
) -> OrgConsentRecord {
    OrgConsentRecord::reconstitute(OrgConsentRecordRow {
        id: ConsentId::new(),
        organization_id: *member.organization_id(),
        org_user_id: *member.id(),
        consent_type,
        granted: decision,
        version: Label::new("version", "v1").expect("a valid version"),
        ip_address: Fact::Unknown,
        recorded_at: clock::now() - time::Duration::hours(1),
    })
    .expect("a consent record is a consistent row")
}

/// A second copy of `request`, as storage would read it back.
fn copy_erasure(request: &OrgErasureRequest) -> Result<OrgErasureRequest, DomainError> {
    OrgErasureRequest::reconstitute(OrgErasureRequestRow {
        id: *request.id(),
        organization_id: *request.organization_id(),
        org_user_id: *request.org_user_id(),
        reason: request.reason().cloned(),
        state: request.state(),
        requested_at: request.requested_at(),
        scheduled_at: request.scheduled_at(),
        cancel_token_hash: request.cancel_token_hash().clone(),
        sent_to: request.sent_to().clone(),
    })
}

/// A second copy of `record`, as storage would read it back.
fn copy_consent(record: &OrgConsentRecord) -> Result<OrgConsentRecord, DomainError> {
    OrgConsentRecord::reconstitute(OrgConsentRecordRow {
        id: *record.id(),
        organization_id: *record.organization_id(),
        org_user_id: *record.org_user_id(),
        consent_type: record.consent_type(),
        granted: record.decision(),
        version: record.version().clone(),
        ip_address: record.ip_address().cloned(),
        recorded_at: record.recorded_at(),
    })
}

/// Whether `request` is still under way: neither completed nor cancelled.
fn is_under_way(request: &OrgErasureRequest) -> bool {
    !matches!(
        request.status(),
        ErasureStatus::Completed | ErasureStatus::Cancelled
    )
}

/// In-memory erasure requests of every organization, keyed by their id.
#[derive(Default)]
pub struct FakeOrgErasureStore {
    requests: Mutex<Vec<OrgErasureRequest>>,
    due_batches: Mutex<Vec<usize>>,
}

impl FakeOrgErasureStore {
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

    /// A store holding `requests`.
    #[must_use]
    pub fn holding(requests: impl IntoIterator<Item = OrgErasureRequest>) -> Self {
        let store = Self::empty();
        store.requests.lock().unwrap().extend(requests);
        store
    }

    /// How many requests are held.
    #[must_use]
    pub fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    /// The status of request `id`, when held.
    #[must_use]
    pub fn status_of(&self, id: &ErasureRequestId) -> Option<ErasureStatus> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .find(|request| request.id() == id)
            .map(OrgErasureRequest::status)
    }

    /// The first held request matching `wanted`, copied.
    fn first(
        &self,
        wanted: impl Fn(&OrgErasureRequest) -> bool,
    ) -> Result<Option<OrgErasureRequest>, DomainError> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .find(|request| wanted(request))
            .map(copy_erasure)
            .transpose()
    }
}

#[async_trait]
impl OrgErasureRequestStore for FakeOrgErasureStore {
    async fn find_active_by_member(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
    ) -> Result<Option<OrgErasureRequest>, DomainError> {
        self.first(|request| {
            request.organization_id() == organization_id
                && request.org_user_id() == org_user_id
                && is_under_way(request)
        })
    }

    async fn find_by_id(
        &self,
        organization_id: &OrganizationId,
        id: &ErasureRequestId,
    ) -> Result<Option<OrgErasureRequest>, DomainError> {
        self.first(|request| request.organization_id() == organization_id && request.id() == id)
    }

    async fn find_by_cancel_token_hash(
        &self,
        cancel_token_hash: &TokenHash,
    ) -> Result<Option<OrgErasureRequest>, DomainError> {
        self.first(|request| request.cancel_token_hash() == cancel_token_hash)
    }

    async fn save(&self, request: &OrgErasureRequest) -> Result<(), DomainError> {
        let copy = copy_erasure(request)?;
        let mut requests = self.requests.lock().unwrap();
        let another_under_way = is_under_way(request)
            && requests.iter().any(|held| {
                held.id() != request.id()
                    && held.organization_id() == request.organization_id()
                    && held.org_user_id() == request.org_user_id()
                    && is_under_way(held)
            });
        if another_under_way {
            return Err(DomainError::conflict(
                "the member already has an erasure under way",
            ));
        }
        requests.retain(|held| held.id() != request.id());
        requests.push(copy);
        Ok(())
    }

    async fn find_due(&self, batch: ErasureBatch) -> Result<Vec<OrgErasureRequest>, DomainError> {
        let mut due: Vec<_> = self
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| {
                request.is_due(batch.now) || request.status() == ErasureStatus::Failed
            })
            .filter(|request| {
                batch.after.is_none_or(|after| {
                    (request.scheduled_at(), request.id().as_uuid())
                        > (after.scheduled_at, after.id.as_uuid())
                })
            })
            .map(copy_erasure)
            .collect::<Result<_, _>>()?;
        due.sort_by_key(|request| (request.scheduled_at(), *request.id().as_uuid()));
        due.truncate(ErasureBatch::LIMIT);
        self.due_batches.lock().unwrap().push(due.len());
        Ok(due)
    }
}

impl Fake for Arc<dyn OrgErasureRequestStore> {
    fn fake() -> Self {
        Arc::new(FakeOrgErasureStore::empty())
    }
}

/// In-memory consent records of every organization, in the order they were
/// made.
#[derive(Default)]
pub struct FakeOrgConsentStore {
    records: Mutex<Vec<OrgConsentRecord>>,
}

impl FakeOrgConsentStore {
    /// Nothing held.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `records`, oldest first.
    #[must_use]
    pub fn holding(records: impl IntoIterator<Item = OrgConsentRecord>) -> Self {
        let store = Self::empty();
        store.records.lock().unwrap().extend(records);
        store
    }

    /// How many records are held.
    #[must_use]
    pub fn count(&self) -> usize {
        self.records.lock().unwrap().len()
    }

    /// Copies of the records of `org_user_id` in `organization_id`, newest
    /// first.
    fn of_member(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
    ) -> Result<Vec<OrgConsentRecord>, DomainError> {
        self.records
            .lock()
            .unwrap()
            .iter()
            .rev()
            .filter(|record| {
                record.organization_id() == organization_id && record.org_user_id() == org_user_id
            })
            .map(copy_consent)
            .collect()
    }
}

#[async_trait]
impl OrgConsentStore for FakeOrgConsentStore {
    async fn find_latest(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
        consent_type: ConsentType,
    ) -> Result<Option<OrgConsentRecord>, DomainError> {
        Ok(self
            .of_member(organization_id, org_user_id)?
            .into_iter()
            .find(|record| record.consent_type() == consent_type))
    }

    async fn list_by_member(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
    ) -> Result<Vec<OrgConsentRecord>, DomainError> {
        self.of_member(organization_id, org_user_id)
    }

    async fn save(&self, record: &OrgConsentRecord) -> Result<(), DomainError> {
        let copy = copy_consent(record)?;
        self.records.lock().unwrap().push(copy);
        Ok(())
    }
}

/// Members' erasures wait as long as a tenant's do by default, with cancel
/// links on the same test address.
impl Fake for OrgErasurePolicy {
    fn fake() -> Self {
        let tenants = ErasurePolicy::fake();
        Self {
            grace_period: tenants.grace_period,
            base_url: tenants.base_url,
        }
    }
}

impl Fake for Arc<dyn OrgConsentStore> {
    fn fake() -> Self {
        Arc::new(FakeOrgConsentStore::empty())
    }
}

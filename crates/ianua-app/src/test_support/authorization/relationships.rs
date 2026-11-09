//! In-memory relationships on a tenant's app objects, and the records of
//! authorization decisions.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authorization::relationship::{
    ObjectRef, RelationLink, RelationSubject, Relationship,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{RelationshipId, TenantId};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::authorization::{
    DecisionBasis, DecisionFilter, DecisionRecord, DecisionRecordSortField, DecisionRecordStore,
    MatchedRule, RelationshipFilter, RelationshipSortField, RelationshipStore,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::authorization::copies::copy_relationship;
use crate::test_support::listing::page;

/// In-memory relationship store, tenant by tenant.
#[derive(Default)]
pub struct FakeRelationshipStore {
    relationships: Mutex<Vec<(TenantId, Relationship<ResolvedTenant>)>>,
    chain_reads: Mutex<Vec<ObjectRef>>,
    chain_batches: AtomicUsize,
}

impl TenantScoped for FakeRelationshipStore {}

impl FakeRelationshipStore {
    /// How many ancestry reads were issued, regardless of objects per read.
    #[must_use]
    pub fn chain_batches(&self) -> usize {
        self.chain_batches.load(Ordering::SeqCst)
    }

    /// The objects whose ancestry was requested, in read order.
    #[must_use]
    pub fn chain_reads(&self) -> Vec<ObjectRef> {
        self.chain_reads.lock().unwrap().clone()
    }

    /// A store holding no relationship.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store already holding `relationships` in `tenant_id`.
    #[must_use]
    pub fn holding(
        tenant_id: TenantId,
        relationships: impl IntoIterator<Item = Relationship<ResolvedTenant>>,
    ) -> Self {
        Self {
            relationships: Mutex::new(
                relationships
                    .into_iter()
                    .map(|relationship| (tenant_id, relationship))
                    .collect(),
            ),
            ..Self::default()
        }
    }

    /// How many relationships are held, across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.relationships.lock().unwrap().len()
    }

    fn matching(
        &self,
        tenant_id: TenantId,
        keep: impl Fn(&Relationship<ResolvedTenant>) -> bool,
    ) -> Result<Vec<Relationship<ResolvedTenant>>, DomainError> {
        self.relationships
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, relationship)| *tenant == tenant_id && keep(relationship))
            .map(|(_, relationship)| copy_relationship(relationship))
            .collect()
    }

    /// The objects `objects` sit under, one step up.
    fn parents_of(
        &self,
        tenant_id: TenantId,
        objects: &[ObjectRef],
    ) -> Result<Vec<ObjectRef>, DomainError> {
        Ok(self
            .matching(tenant_id, |held| objects.contains(held.object()))?
            .into_iter()
            .filter_map(|held| match held.link() {
                RelationLink::Under(parent) => Some(parent.clone()),
                RelationLink::Holds { .. } => None,
            })
            .collect())
    }
}

/// Whether `relationship` names `subject` as the holder of a relation.
fn held_by(relationship: &Relationship<ResolvedTenant>, subject: &RelationSubject) -> bool {
    matches!(relationship.link(), RelationLink::Holds { subject: held, .. } if held == subject)
}

#[async_trait]
impl RelationshipStore for FakeRelationshipStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &RelationshipId,
    ) -> Result<Option<Relationship<ResolvedTenant>>, DomainError> {
        Ok(self.matching(**tenant_id, |held| held.id() == id)?.pop())
    }

    async fn find_same(
        &self,
        tenant_id: &ScopedTenant,
        object: &ObjectRef,
        link: &RelationLink,
    ) -> Result<Option<Relationship<ResolvedTenant>>, DomainError> {
        Ok(self
            .matching(**tenant_id, |held| {
                held.object() == object && held.link() == link
            })?
            .pop())
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
        filter: &RelationshipFilter,
        request: &PageRequest,
    ) -> Result<Page<Relationship<ResolvedTenant>>, DomainError> {
        let kept = self.matching(**tenant_id, |held| match filter {
            RelationshipFilter::All => true,
            RelationshipFilter::OnObject(object) => held.object() == object,
            RelationshipFilter::HeldBy(subject) => held_by(held, subject),
        })?;
        page(
            kept,
            &SortOrder::<RelationshipSortField>::default(),
            request,
        )
    }

    async fn find_chain(
        &self,
        tenant_id: &ScopedTenant,
        object: &ObjectRef,
        depth: usize,
    ) -> Result<Vec<Relationship<ResolvedTenant>>, DomainError> {
        self.find_chains(tenant_id, std::slice::from_ref(object), depth)
            .await
    }

    async fn find_chains(
        &self,
        tenant_id: &ScopedTenant,
        objects: &[ObjectRef],
        depth: usize,
    ) -> Result<Vec<Relationship<ResolvedTenant>>, DomainError> {
        self.chain_reads.lock().unwrap().extend_from_slice(objects);
        self.chain_batches.fetch_add(1, Ordering::SeqCst);
        let mut reached = objects.to_vec();
        let mut frontier = objects.to_vec();
        for _ in 0..depth {
            frontier = self.parents_of(**tenant_id, &frontier)?;
            reached.extend(frontier.iter().cloned());
        }
        self.matching(**tenant_id, |held| reached.contains(held.object()))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        relationship: &Relationship<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let copy = copy_relationship(relationship)?;
        self.relationships.lock().unwrap().push((**tenant_id, copy));
        Ok(())
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &RelationshipId,
    ) -> Result<(), DomainError> {
        self.relationships
            .lock()
            .unwrap()
            .retain(|(tenant, held)| !(*tenant == **tenant_id && held.id() == id));
        Ok(())
    }
}

impl Fake for Arc<dyn RelationshipStore> {
    fn fake() -> Self {
        Arc::new(FakeRelationshipStore::empty())
    }
}

/// In-memory decision records, tenant by tenant, in the order made.
#[derive(Default)]
pub struct FakeDecisionRecordStore {
    records: Mutex<Vec<(TenantId, DecisionRecord)>>,
    writes: AtomicUsize,
}

impl TenantScoped for FakeDecisionRecordStore {}

impl FakeDecisionRecordStore {
    /// How many storage writes kept the decisions, independent of batch size.
    #[must_use]
    pub fn writes(&self) -> usize {
        self.writes.load(Ordering::SeqCst)
    }

    /// A store holding no record.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Every record kept for `tenant_id`, oldest first.
    #[must_use]
    pub fn recorded(&self, tenant_id: TenantId) -> Vec<DecisionRecord> {
        self.records
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, _)| *tenant == tenant_id)
            .map(|(_, record)| record.clone())
            .collect()
    }
}

/// Whether `filter` keeps `record`.
fn kept_by(filter: &DecisionFilter, record: &DecisionRecord) -> bool {
    let (version, rule) = match &record.basis {
        DecisionBasis::Policy {
            version, matched, ..
        } => (Some(*version), matched.clone()),
        DecisionBasis::AppCheck { .. } => (None, MatchedRule::Default),
    };
    filter
        .subject
        .is_none_or(|subject| subject == record.subject)
        && filter
            .verdict
            .is_none_or(|verdict| verdict == record.verdict())
        && filter
            .policy_version
            .is_none_or(|wanted| Some(wanted) == version)
        && filter
            .rule
            .as_ref()
            .is_none_or(|wanted| rule == MatchedRule::Rule(wanted.clone()))
        && filter.since.is_none_or(|since| record.decided_at >= since)
}

#[async_trait]
impl DecisionRecordStore for FakeDecisionRecordStore {
    async fn record_all(
        &self,
        tenant_id: &ScopedTenant,
        records: &[DecisionRecord],
    ) -> Result<(), DomainError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.records
            .lock()
            .unwrap()
            .extend(records.iter().cloned().map(|record| (**tenant_id, record)));
        Ok(())
    }

    async fn record(
        &self,
        tenant_id: &ScopedTenant,
        record: &DecisionRecord,
    ) -> Result<(), DomainError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.records
            .lock()
            .unwrap()
            .push((**tenant_id, record.clone()));
        Ok(())
    }

    async fn search(
        &self,
        tenant_id: &ScopedTenant,
        filter: &DecisionFilter,
        request: &PageRequest,
    ) -> Result<Page<DecisionRecord>, DomainError> {
        let kept: Vec<DecisionRecord> = self
            .recorded(**tenant_id)
            .into_iter()
            .filter(|record| kept_by(filter, record))
            .collect();
        page(
            kept,
            &SortOrder::<DecisionRecordSortField>::default(),
            request,
        )
    }
}

impl Fake for Arc<dyn DecisionRecordStore> {
    fn fake() -> Self {
        Arc::new(FakeDecisionRecordStore::empty())
    }
}

/// A store whose every write fails, to show a decision nobody can record
/// is not handed out.
pub struct FailingDecisionRecordStore;

impl TenantScoped for FailingDecisionRecordStore {}

#[async_trait]
impl DecisionRecordStore for FailingDecisionRecordStore {
    async fn record_all(
        &self,
        _tenant_id: &ScopedTenant,
        _records: &[DecisionRecord],
    ) -> Result<(), DomainError> {
        Err(DomainError::infra_msg("the decision log is unreachable"))
    }

    async fn record(
        &self,
        _tenant_id: &ScopedTenant,
        _record: &DecisionRecord,
    ) -> Result<(), DomainError> {
        Err(DomainError::infra_msg("the decision log is unreachable"))
    }

    async fn search(
        &self,
        _tenant_id: &ScopedTenant,
        _filter: &DecisionFilter,
        _request: &PageRequest,
    ) -> Result<Page<DecisionRecord>, DomainError> {
        Err(DomainError::infra_msg("the decision log is unreachable"))
    }
}

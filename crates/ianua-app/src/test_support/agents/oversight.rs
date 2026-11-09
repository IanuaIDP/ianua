//! The watch kept over agents, kept in memory: review assignments, what an
//! agent did, whether it may act, the most sensitive data it has touched
//! and the paths it touched.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::agents::execution::convergence::Touch;
use ianua_domain::domains::agents::identity::exposure_reset::ExposureReset;
use ianua_domain::domains::agents::identity::standing::AgentStanding;
use ianua_domain::domains::agents::oversight::review::{ReviewAssignment, ReviewAssignmentRow};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    AgentId, DelegationId, Ending, PrincipalRef, ReviewAssignmentId, TenantId,
};
use time::OffsetDateTime;

use crate::listing::{Listing, Page};
use crate::ports::TenantScoped;
use crate::ports::agents::{
    AgentActivityStore, AgentExposureGate, AgentStandingCheck, DelegationRevocationCheck,
    ReviewAssignmentStore, TouchEntry, TouchLedger,
};
use crate::ports::audit::{AuditLogFilter, AuditLogPage, AuditLogSortField};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::agents::shelf::Shelf;

/// A review assignment's stored columns.
#[derive(Clone)]
struct ReviewRecord {
    id: ReviewAssignmentId,
    reviewer: AgentId,
    reviewed: AgentId,
    assigned_by: PrincipalRef,
    assigned_at: OffsetDateTime,
    ended_at: Option<OffsetDateTime>,
}

impl ReviewRecord {
    /// `assignment` as storage keeps it.
    fn of(assignment: &ReviewAssignment<ResolvedTenant>) -> Self {
        Self {
            id: *assignment.id(),
            reviewer: *assignment.reviewer(),
            reviewed: *assignment.reviewed(),
            assigned_by: *assignment.assigned_by(),
            assigned_at: assignment.assigned_at(),
            ended_at: assignment.ended_at(),
        }
    }

    /// The assignment read back through the domain's checks.
    fn read(&self) -> Result<ReviewAssignment<ResolvedTenant>, DomainError> {
        ReviewAssignment::reconstitute(ReviewAssignmentRow {
            id: self.id,
            reviewer: self.reviewer,
            reviewed: self.reviewed,
            assigned_by: self.assigned_by,
            assigned_at: self.assigned_at,
            ending: Ending::from_stored(self.ended_at),
        })
    }
}

/// In-memory review assignment store: assignments are kept per tenant and
/// saved in place.
#[derive(Default)]
pub struct FakeReviewStore {
    records: Shelf<ReviewRecord>,
}

impl TenantScoped for FakeReviewStore {}

#[async_trait]
impl ReviewAssignmentStore for FakeReviewStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        assignment: &ReviewAssignment<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.records
            .put(tenant_id, ReviewRecord::of(assignment), |record| {
                record.id == *assignment.id()
            });
        Ok(())
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ReviewAssignmentId,
    ) -> Result<Option<ReviewAssignment<ResolvedTenant>>, DomainError> {
        self.records
            .find(tenant_id, |record| record.id == *id)
            .map(|record| record.read())
            .transpose()
    }

    async fn list_for_agent(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentId,
    ) -> Result<Vec<ReviewAssignment<ResolvedTenant>>, DomainError> {
        self.records
            .filter(tenant_id, |record| {
                record.reviewer == *agent || record.reviewed == *agent
            })
            .iter()
            .rev()
            .map(ReviewRecord::read)
            .collect()
    }
}

/// Agent activity store that lists no records, though it may count some.
pub struct FakeAgentActivityStore {
    total: u64,
}

impl TenantScoped for FakeAgentActivityStore {}

impl FakeAgentActivityStore {
    /// A store with no matching records.
    #[must_use]
    pub fn empty() -> Self {
        Self::with_total(0)
    }

    /// A store counting `total` matching records, listing none of them.
    #[must_use]
    pub fn with_total(total: u64) -> Self {
        Self { total }
    }
}

#[async_trait]
impl AgentActivityStore for FakeAgentActivityStore {
    async fn query(
        &self,
        _tenant_id: &ScopedTenant,
        _agent_id: &AgentId,
        listing: Listing<'_, &AuditLogFilter, AuditLogSortField>,
    ) -> Result<AuditLogPage, DomainError> {
        Ok(Page::last(Vec::new(), listing.page.limit()))
    }

    async fn count(
        &self,
        _tenant_id: &ScopedTenant,
        _agent_id: &AgentId,
        _filter: &AuditLogFilter,
    ) -> Result<u64, DomainError> {
        Ok(self.total)
    }
}

/// One agent in one tenant.
type AgentKey = (TenantId, AgentId);

/// Standing check where every agent is active unless a test says otherwise.
#[derive(Default)]
pub struct FakeAgentStandings {
    standings: Mutex<HashMap<AgentKey, AgentStanding>>,
}

impl TenantScoped for FakeAgentStandings {}

impl FakeAgentStandings {
    /// Puts the agent `agent_id` of `tenant_id` in `standing`.
    pub fn set(&self, tenant_id: &ScopedTenant, agent_id: AgentId, standing: AgentStanding) {
        self.standings
            .lock()
            .unwrap()
            .insert((**tenant_id, agent_id), standing);
    }
}

#[async_trait]
impl AgentStandingCheck for FakeAgentStandings {
    async fn standing(
        &self,
        tenant_id: &ScopedTenant,
        agent_id: &AgentId,
    ) -> Result<AgentStanding, DomainError> {
        Ok(self
            .standings
            .lock()
            .unwrap()
            .get(&(**tenant_id, *agent_id))
            .copied()
            .unwrap_or(AgentStanding::Active))
    }
}

/// Revocation check where every delegation stands unless a test revoked
/// it.
#[derive(Default)]
pub struct FakeDelegationRevocations {
    revoked: Mutex<HashSet<(TenantId, DelegationId)>>,
}

impl TenantScoped for FakeDelegationRevocations {}

impl FakeDelegationRevocations {
    /// Revokes the delegation `delegation_id` of `tenant_id`.
    pub fn revoke(&self, tenant_id: &ScopedTenant, delegation_id: DelegationId) {
        self.revoked
            .lock()
            .unwrap()
            .insert((**tenant_id, delegation_id));
    }
}

#[async_trait]
impl DelegationRevocationCheck for FakeDelegationRevocations {
    async fn is_revoked(
        &self,
        tenant_id: &ScopedTenant,
        delegation_id: &DelegationId,
    ) -> Result<bool, DomainError> {
        Ok(self
            .revoked
            .lock()
            .unwrap()
            .contains(&(**tenant_id, *delegation_id)))
    }
}

/// Exposure gate holding the most sensitive class each agent has touched. It
/// admits a class only when the agent has touched nothing more sensitive,
/// and lowers a mark only while the agent is still stopped.
#[derive(Default)]
pub struct FakeExposureGate {
    marks: Mutex<HashMap<AgentKey, DataClassLevel>>,
    resumed: Mutex<HashSet<AgentKey>>,
}

impl TenantScoped for FakeExposureGate {}

impl FakeExposureGate {
    /// The most sensitive class the agent `agent_id` of `tenant_id` has
    /// touched.
    #[must_use]
    pub fn of(&self, tenant_id: &ScopedTenant, agent_id: &AgentId) -> DataClassLevel {
        self.marks
            .lock()
            .unwrap()
            .get(&(**tenant_id, *agent_id))
            .copied()
            .unwrap_or(DataClassLevel::Public)
    }

    /// Records that the agent `agent_id` of `tenant_id` was resumed, as
    /// between a person's check of it and their reset of its mark.
    pub fn resume(&self, tenant_id: &ScopedTenant, agent_id: AgentId) {
        self.resumed.lock().unwrap().insert((**tenant_id, agent_id));
    }

    /// Marks the agent `agent_id` of `tenant_id` as having touched `level`.
    pub fn set(&self, tenant_id: &ScopedTenant, agent_id: AgentId, level: DataClassLevel) {
        self.marks
            .lock()
            .unwrap()
            .insert((**tenant_id, agent_id), level);
    }
}

#[async_trait]
impl AgentExposureGate for FakeExposureGate {
    async fn admit(
        &self,
        tenant_id: &ScopedTenant,
        agent_id: &AgentId,
        class: DataClassLevel,
    ) -> Result<bool, DomainError> {
        let mut marks = self.marks.lock().unwrap();
        let mark = marks
            .entry((**tenant_id, *agent_id))
            .or_insert(DataClassLevel::Public);
        if *mark > class {
            return Ok(false);
        }
        *mark = class;
        Ok(true)
    }

    async fn current(
        &self,
        tenant_id: &ScopedTenant,
        agent_id: &AgentId,
    ) -> Result<DataClassLevel, DomainError> {
        Ok(self.of(tenant_id, agent_id))
    }

    async fn reset(
        &self,
        tenant_id: &ScopedTenant,
        reset: &ExposureReset<ResolvedTenant>,
    ) -> Result<bool, DomainError> {
        let key = (**tenant_id, *reset.agent_id());
        if self.resumed.lock().unwrap().contains(&key) {
            return Ok(false);
        }
        let mut marks = self.marks.lock().unwrap();
        let mark = marks
            .entry((**tenant_id, *reset.agent_id()))
            .or_insert(DataClassLevel::Public);
        if *mark != reset.previous() {
            return Ok(false);
        }
        *mark = reset.lowered_to();
        Ok(true)
    }
}

/// One touch on one path in one tenant, and when it happened.
type TouchRecord = (TenantId, String, Touch, OffsetDateTime);

/// In-memory touch ledger. Recording a touch forgets the path's touches
/// from before the entry's `forget_before`.
#[derive(Default)]
pub struct FakeTouchLedger {
    touches: Mutex<Vec<TouchRecord>>,
}

impl TenantScoped for FakeTouchLedger {}

#[async_trait]
impl TouchLedger for FakeTouchLedger {
    async fn since(
        &self,
        tenant_id: &ScopedTenant,
        path: &str,
        since: OffsetDateTime,
    ) -> Result<Vec<Touch>, DomainError> {
        let mut touches = self
            .touches
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, on, _, at)| tenant == &**tenant_id && on == path && *at >= since)
            .map(|(_, _, touch, at)| (*at, *touch))
            .collect::<Vec<_>>();
        touches.sort_by_key(|(at, _)| *at);
        Ok(touches.into_iter().map(|(_, touch)| touch).collect())
    }

    async fn record(
        &self,
        tenant_id: &ScopedTenant,
        entry: &TouchEntry<'_>,
    ) -> Result<(), DomainError> {
        let mut touches = self.touches.lock().unwrap();
        touches.retain(|(tenant, on, _, at)| {
            !(tenant == &**tenant_id && on == entry.path && *at < entry.forget_before)
        });
        touches.push((**tenant_id, entry.path.to_owned(), *entry.touch, entry.at));
        Ok(())
    }
}

impl Fake for Arc<dyn AgentActivityStore> {
    fn fake() -> Self {
        Arc::new(FakeAgentActivityStore::empty())
    }
}

impl Fake for Arc<dyn AgentExposureGate> {
    fn fake() -> Self {
        Arc::new(FakeExposureGate::default())
    }
}

impl Fake for Arc<dyn AgentStandingCheck> {
    fn fake() -> Self {
        Arc::new(FakeAgentStandings::default())
    }
}

impl Fake for Arc<dyn DelegationRevocationCheck> {
    fn fake() -> Self {
        Arc::new(FakeDelegationRevocations::default())
    }
}

impl Fake for Arc<dyn ReviewAssignmentStore> {
    fn fake() -> Self {
        Arc::new(FakeReviewStore::default())
    }
}

impl Fake for Arc<dyn TouchLedger> {
    fn fake() -> Self {
        Arc::new(FakeTouchLedger::default())
    }
}

//! Workflow versions kept in memory, per tenant, read back the way storage
//! reads them.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::workflows::design::workflow::{
    Workflow, WorkflowOrigin, WorkflowRow, WorkflowStatus,
};
use ianua_domain::domains::workflows::triggers::Trigger;
use ianua_domain::domains::workflows::triggers::before::GuardedChange;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::types::{EventType, IntegrationAccountId, TenantId, WorkflowId};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::workflows::{NewestFirstField, WorkflowSortField, WorkflowStore};
use crate::tenancy::ScopedTenant;
use crate::test_support::listing::page;
use crate::test_support::{Fake, test_ctx};

/// `workflow` read back from its row, as storage reads it.
fn copy_of(workflow: &Workflow<ResolvedTenant>) -> Workflow<ResolvedTenant> {
    Workflow::reconstitute(WorkflowRow {
        id: *workflow.id(),
        version: workflow.version(),
        name: workflow.name().clone(),
        description: workflow.description().cloned(),
        graph: workflow.graph().clone(),
        layout: workflow.layout().clone(),
        trigger: workflow.trigger().clone(),
        run_limit: workflow.run_limit(),
        failure_alert: workflow.failure_alert(),
        status: workflow.status(),
        created_by: workflow.created_by().clone(),
        edited_by: workflow.edited_by().clone(),
        authors: workflow.authors().clone(),
        publication: workflow.publication().clone(),
        origin: workflow.origin().clone(),
        hold: workflow.hold().clone(),
        created_at: Aggregate::created_at(workflow),
        updated_at: Aggregate::updated_at(workflow),
    })
    .expect("a kept version reads back as itself")
}

/// In-memory version store: one row per workflow and version, at most one
/// published version per workflow, each kept under its tenant.
#[derive(Default)]
pub struct FakeWorkflowStore {
    versions: Mutex<Vec<(TenantId, Workflow<ResolvedTenant>)>>,
}

impl TenantScoped for FakeWorkflowStore {}

impl FakeWorkflowStore {
    /// A store holding no workflow.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `versions` in the test tenant.
    #[must_use]
    pub fn holding(versions: &[Workflow<ResolvedTenant>]) -> Self {
        let tenant = test_ctx().tenant_id();
        Self {
            versions: Mutex::new(versions.iter().map(|v| (tenant, copy_of(v))).collect()),
        }
    }

    /// Version `version` of `id`, as the test tenant keeps it now.
    #[must_use]
    pub fn stored(&self, id: &WorkflowId, version: u32) -> Option<Workflow<ResolvedTenant>> {
        self.matching(test_ctx().tenant_id(), |kept| {
            kept.id() == id && kept.version() == version
        })
        .into_iter()
        .next()
    }

    /// How many versions are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.versions.lock().unwrap().len()
    }

    fn matching(
        &self,
        tenant: TenantId,
        wanted: impl Fn(&Workflow<ResolvedTenant>) -> bool,
    ) -> Vec<Workflow<ResolvedTenant>> {
        self.versions
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, kept)| *owner == tenant && wanted(kept))
            .map(|(_, kept)| copy_of(kept))
            .collect()
    }

    fn latest_of_each(&self, tenant: TenantId) -> Vec<Workflow<ResolvedTenant>> {
        let all = self.matching(tenant, |_| true);
        all.iter()
            .filter(|candidate| {
                !all.iter().any(|other| {
                    other.id() == candidate.id() && other.version() > candidate.version()
                })
            })
            .map(copy_of)
            .collect()
    }
}

#[async_trait]
impl WorkflowStore for FakeWorkflowStore {
    async fn find_version(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowId,
        version: u32,
    ) -> Result<Option<Workflow<ResolvedTenant>>, DomainError> {
        Ok(self
            .matching(**tenant_id, |kept| {
                kept.id() == id && kept.version() == version
            })
            .into_iter()
            .next())
    }

    async fn find_latest(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowId,
    ) -> Result<Option<Workflow<ResolvedTenant>>, DomainError> {
        Ok(self
            .matching(**tenant_id, |kept| kept.id() == id)
            .into_iter()
            .max_by_key(Workflow::version))
    }

    async fn find_published(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowId,
    ) -> Result<Option<Workflow<ResolvedTenant>>, DomainError> {
        Ok(self
            .matching(**tenant_id, |kept| {
                kept.id() == id && kept.status() == WorkflowStatus::Published
            })
            .into_iter()
            .next())
    }

    async fn list_latest(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<WorkflowSortField>,
        request: &PageRequest,
    ) -> Result<Page<Workflow<ResolvedTenant>>, DomainError> {
        let mut latest = self.latest_of_each(**tenant_id);
        latest.retain(|kept| *kept.origin() == WorkflowOrigin::Designed);
        page(latest, sort, request)
    }

    async fn list_flows(
        &self,
        tenant_id: &ScopedTenant,
        request: &PageRequest,
    ) -> Result<Page<Workflow<ResolvedTenant>>, DomainError> {
        let flows = self.matching(**tenant_id, |kept| {
            matches!(kept.origin(), WorkflowOrigin::Flow(_))
        });
        page(flows, &SortOrder::<NewestFirstField>::default(), request)
    }

    async fn delete_flow(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowId,
    ) -> Result<(), DomainError> {
        self.versions
            .lock()
            .unwrap()
            .retain(|(owner, kept)| owner != &**tenant_id || kept.id() != id);
        Ok(())
    }

    async fn list_published_on(
        &self,
        tenant_id: &ScopedTenant,
        event: EventType,
    ) -> Result<Vec<Workflow<ResolvedTenant>>, DomainError> {
        Ok(self.matching(**tenant_id, |kept| {
            kept.status() == WorkflowStatus::Published
                && matches!(kept.trigger(), Trigger::Event(on) if on.event() == event)
        }))
    }

    async fn list_published_before(
        &self,
        tenant_id: &ScopedTenant,
        change: GuardedChange,
    ) -> Result<Vec<Workflow<ResolvedTenant>>, DomainError> {
        Ok(self.matching(**tenant_id, |kept| {
            kept.status() == WorkflowStatus::Published && *kept.trigger() == Trigger::Before(change)
        }))
    }

    async fn list_published_using(
        &self,
        tenant_id: &ScopedTenant,
        account: &IntegrationAccountId,
    ) -> Result<Vec<Workflow<ResolvedTenant>>, DomainError> {
        Ok(self.matching(**tenant_id, |kept| {
            kept.status() == WorkflowStatus::Published
                && kept
                    .accounts_used()
                    .iter()
                    .any(|used| used.account == *account)
        }))
    }

    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        workflow: &Workflow<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut versions = self.versions.lock().unwrap();
        let taken = versions.iter().any(|(owner, kept)| {
            owner == &**tenant_id
                && kept.id() == workflow.id()
                && kept.version() == workflow.version()
        });
        if taken {
            return Err(DomainError::conflict(
                "the workflow already has a version with this number",
            ));
        }
        versions.push((**tenant_id, copy_of(workflow)));
        Ok(())
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        workflow: &Workflow<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut versions = self.versions.lock().unwrap();
        let second_in_service = workflow.status() == WorkflowStatus::Published
            && versions.iter().any(|(owner, kept)| {
                owner == &**tenant_id
                    && kept.id() == workflow.id()
                    && kept.version() != workflow.version()
                    && kept.status() == WorkflowStatus::Published
            });
        if second_in_service {
            return Err(DomainError::conflict(
                "another version of the workflow is published",
            ));
        }
        let held = versions.iter().position(|(owner, kept)| {
            owner == &**tenant_id
                && kept.id() == workflow.id()
                && kept.version() == workflow.version()
        });
        let Some(index) = held else {
            return Err(DomainError::infra_msg("no such version is kept"));
        };
        versions[index] = (**tenant_id, copy_of(workflow));
        Ok(())
    }
}

impl Fake for Arc<dyn WorkflowStore> {
    fn fake() -> Self {
        Arc::new(FakeWorkflowStore::empty())
    }
}

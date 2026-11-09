//! What an agent may reach, as a test says it: the relationship graph and
//! its grants, the intent compiler, and the task templates people approve.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::agents::authority::capability::{
    CapabilitySet, Relation, ResourceCapability, ResourceRef,
};
use ianua_domain::domains::agents::authority::intent::{
    CompiledIntent, IntentDigest, IntentEnvelope, IntentStatement,
};
use ianua_domain::domains::agents::authority::task_template::{TaskTemplate, TaskTemplateRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PrincipalRef, TaskTemplateId, TenantId};

use crate::ports::TenantScoped;
use crate::ports::agents::{
    IntentCompiler, RelationshipResolver, ResourceGrantStore, TaskTemplateStore,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::agents::shelf::Shelf;

/// Relationship resolver that answers every question the same way.
#[derive(Debug, Clone, Copy)]
pub enum FakeRelationshipResolver {
    /// Nobody holds any relation on anything.
    HoldsNothing,
    /// Everybody holds every relation on everything.
    HoldsEverything,
}

impl TenantScoped for FakeRelationshipResolver {}

#[async_trait]
impl RelationshipResolver for FakeRelationshipResolver {
    async fn check(
        &self,
        _tenant_id: &ScopedTenant,
        _subject: &PrincipalRef,
        _relation: &Relation,
        _object: &ResourceRef,
    ) -> Result<bool, DomainError> {
        Ok(matches!(self, Self::HoldsEverything))
    }

    async fn held_subset(
        &self,
        _tenant_id: &ScopedTenant,
        _subject: &PrincipalRef,
        wanted: &[ResourceCapability],
    ) -> Result<Vec<ResourceCapability>, DomainError> {
        Ok(match self {
            Self::HoldsNothing => Vec::new(),
            Self::HoldsEverything => wanted.to_vec(),
        })
    }
}

/// One subject holding one capability, in one tenant.
type Edge = (TenantId, PrincipalRef, ResourceCapability);

/// In-memory relationship graph, both resolver and grant store, so a test
/// can seed what a caller holds and see what a grant writes.
#[derive(Default)]
pub struct FakeResourceGraph {
    edges: Mutex<Vec<Edge>>,
}

impl TenantScoped for FakeResourceGraph {}

impl FakeResourceGraph {
    /// A graph with no edges.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Seeds `subject` holding `capability` in `tenant_id`, with no check on
    /// who may grant it.
    pub fn insert(
        &self,
        tenant_id: &ScopedTenant,
        subject: PrincipalRef,
        capability: ResourceCapability,
    ) {
        let edge = (**tenant_id, subject, capability);
        let mut edges = self.edges.lock().unwrap();
        if !edges.contains(&edge) {
            edges.push(edge);
        }
    }

    /// How many edges the graph holds, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.edges.lock().unwrap().len()
    }

    /// Whether `subject` holds `relation` on `object` in `tenant_id`.
    fn holds(
        &self,
        tenant_id: &ScopedTenant,
        subject: &PrincipalRef,
        relation: &Relation,
        object: &ResourceRef,
    ) -> bool {
        self.edges
            .lock()
            .unwrap()
            .iter()
            .any(|(tenant, holder, held)| {
                tenant == &**tenant_id
                    && holder == subject
                    && held.relation() == relation
                    && held.resource_ref() == object
            })
    }
}

#[async_trait]
impl RelationshipResolver for FakeResourceGraph {
    async fn check(
        &self,
        tenant_id: &ScopedTenant,
        subject: &PrincipalRef,
        relation: &Relation,
        object: &ResourceRef,
    ) -> Result<bool, DomainError> {
        Ok(self.holds(tenant_id, subject, relation, object))
    }

    async fn held_subset(
        &self,
        tenant_id: &ScopedTenant,
        subject: &PrincipalRef,
        wanted: &[ResourceCapability],
    ) -> Result<Vec<ResourceCapability>, DomainError> {
        Ok(wanted
            .iter()
            .filter(|capability| {
                self.holds(
                    tenant_id,
                    subject,
                    capability.relation(),
                    capability.resource_ref(),
                )
            })
            .cloned()
            .collect())
    }
}

#[async_trait]
impl ResourceGrantStore for FakeResourceGraph {
    async fn grant(
        &self,
        tenant_id: &ScopedTenant,
        subject: &PrincipalRef,
        capability: &ResourceCapability,
        _granted_by: &PrincipalRef,
    ) -> Result<(), DomainError> {
        self.insert(tenant_id, *subject, capability.clone());
        Ok(())
    }

    async fn revoke(
        &self,
        tenant_id: &ScopedTenant,
        subject: &PrincipalRef,
        capability: &ResourceCapability,
    ) -> Result<(), DomainError> {
        self.edges.lock().unwrap().retain(|(tenant, holder, held)| {
            !(tenant == &**tenant_id && holder == subject && held == capability)
        });
        Ok(())
    }
}

/// Intent compiler that keeps the whole requested scope and allows no
/// action class of its own.
pub struct FakeIntentCompiler;

#[async_trait]
impl IntentCompiler for FakeIntentCompiler {
    async fn compile(
        &self,
        _intent: &IntentStatement,
        requested: &CapabilitySet,
    ) -> Result<CompiledIntent, DomainError> {
        Ok(CompiledIntent::new(
            requested.clone(),
            IntentDigest::new([0u8; 32]),
            IntentEnvelope::default(),
        ))
    }
}

/// Intent compiler gone wrong: it answers every intent with the requested
/// scope and `extra` on top, as a broken or tricked backend might.
pub struct WideningIntentCompiler {
    /// What it adds to every request.
    pub extra: CapabilitySet,
}

#[async_trait]
impl IntentCompiler for WideningIntentCompiler {
    async fn compile(
        &self,
        _intent: &IntentStatement,
        requested: &CapabilitySet,
    ) -> Result<CompiledIntent, DomainError> {
        Ok(CompiledIntent::new(
            requested.union(&self.extra),
            IntentDigest::new([1u8; 32]),
            IntentEnvelope::default(),
        ))
    }
}

/// In-memory task template store: templates are kept per tenant as storage
/// rows, saved in place and read back through the domain's checks.
#[derive(Default)]
pub struct FakeTaskTemplateStore {
    rows: Shelf<TaskTemplateRow>,
}

impl TenantScoped for FakeTaskTemplateStore {}

#[async_trait]
impl TaskTemplateStore for FakeTaskTemplateStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        template: &TaskTemplate<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.rows.put(tenant_id, template_row(template), |row| {
            row.id == *template.id()
        });
        Ok(())
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &TaskTemplateId,
    ) -> Result<Option<TaskTemplate<ResolvedTenant>>, DomainError> {
        self.rows
            .find(tenant_id, |row| row.id == *id)
            .map(TaskTemplate::reconstitute)
            .transpose()
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<TaskTemplate<ResolvedTenant>>, DomainError> {
        self.rows
            .filter(tenant_id, |_| true)
            .into_iter()
            .rev()
            .map(TaskTemplate::reconstitute)
            .collect()
    }
}

/// `template` as storage keeps it.
fn template_row(template: &TaskTemplate<ResolvedTenant>) -> TaskTemplateRow {
    TaskTemplateRow {
        id: *template.id(),
        name: template.name().clone(),
        purpose: template.purpose().clone(),
        digest: *template.digest(),
        ceiling: template.ceiling().clone(),
        classes: template.classes().clone(),
        limits: template.limits().clone(),
        proposed_by: template.proposed_by().clone(),
        proposed_at: template.proposed_at(),
        state: template.state().clone(),
    }
}

impl Fake for Arc<dyn IntentCompiler> {
    fn fake() -> Self {
        Arc::new(FakeIntentCompiler)
    }
}

impl Fake for Arc<dyn RelationshipResolver> {
    fn fake() -> Self {
        Arc::new(FakeRelationshipResolver::HoldsNothing)
    }
}

impl Fake for Arc<dyn ResourceGrantStore> {
    fn fake() -> Self {
        Arc::new(FakeResourceGraph::empty())
    }
}

impl Fake for Arc<dyn TaskTemplateStore> {
    fn fake() -> Self {
        Arc::new(FakeTaskTemplateStore::default())
    }
}

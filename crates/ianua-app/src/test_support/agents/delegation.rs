//! What an agent acts under, kept in memory: the delegation graph, the task
//! tokens minted from it and the budget it has used.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::agents::authority::capability::{
    CapabilitySet, DelegationConstraints, ResourceRef,
};
use ianua_domain::domains::agents::authority::delegation::{
    Delegation, DelegationRenewal, DelegationRow, DelegationStatus, Lineage,
};
use ianua_domain::domains::agents::authority::intent::IntentBinding;
use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::types::{
    AgentId, DelegationId, Issuer, Label, PrincipalRef, Seconds, TenantId, UserId,
};

use crate::ports::TenantScoped;
use crate::ports::agents::{
    BudgetUsageReader, DelegationStore, ResourceHolder, RevokedDelegation, TaskToken,
    TaskTokenIssuer,
};
use crate::services::authorization::grant_revocation::{GrantRevocation, OrgGrantRevocation};
use crate::tenancy::ScopedTenant;
use crate::test_support::agents::shelf::Shelf;
use crate::test_support::{Fake, Revocation};

/// How long a delegation [`grant_from_user`] makes lasts.
const GRANT_LIFETIME: Seconds = Seconds::new(600);

/// How deep a delegation [`grant_from_user`] makes may be passed on.
const GRANT_DEPTH: u8 = 2;

/// A delegation `user` granted a fresh agent, as storage would read it back:
/// view routes, for ten minutes, passed on at most two levels deep.
///
/// # Panics
///
/// - Never: the lifetime and depth are within bounds.
#[must_use]
pub fn grant_from_user(user: UserId) -> Delegation<ResolvedTenant> {
    let now = clock::now();
    let constraints = DelegationConstraints::new(GRANT_LIFETIME, GRANT_DEPTH)
        .expect("ten minutes and depth two are within bounds");
    Delegation::reconstitute(DelegationRow {
        id: DelegationId::new(),
        delegator: PrincipalRef::User(user),
        delegate: AgentId::new(),
        granted: CapabilitySet::new(vec![SystemPermission::Routing(RoutingAction::View)], vec![]),
        constraints,
        lineage: Lineage::Root,
        depth: 0,
        status: DelegationStatus::Active,
        issued_at: now,
        expires_at: now + GRANT_LIFETIME.duration(),
        renewed: DelegationRenewal::NotRenewed,
        updated_at: now,
        name: None,
    })
    .expect("a fresh root grant is a consistent row")
}

/// What a test says a stored delegation is.
pub struct StoredGrant {
    /// Who granted it: a person for a root, the parent's agent for a
    /// sub-delegation, the agent itself for a token it minted.
    pub delegator: PrincipalRef,
    /// The agent holding it.
    pub delegate: AgentId,
    /// What it grants.
    pub granted: CapabilitySet,
    /// Its limits.
    pub constraints: DelegationConstraints,
    /// Where it sits in its chain.
    pub lineage: Lineage,
    /// Whether it still grants anything.
    pub status: DelegationStatus,
}

/// The delegation `grant` describes, issued just now and living its whole
/// lifetime, one link deep when it sits under a parent, as storage would
/// read it back.
///
/// # Panics
///
/// - When `grant` breaks a rule a stored delegation keeps, such as a
///   sub-delegation not passed on by an agent.
#[must_use]
pub fn stored_delegation(grant: StoredGrant) -> Delegation<ResolvedTenant> {
    let now = clock::now();
    let depth = match grant.lineage {
        Lineage::Under(_) => 1,
        Lineage::Root | Lineage::Minted { .. } => 0,
    };
    let lifetime = grant.constraints.ttl_seconds().duration();
    Delegation::reconstitute(DelegationRow {
        id: DelegationId::new(),
        delegator: grant.delegator,
        delegate: grant.delegate,
        granted: grant.granted,
        constraints: grant.constraints,
        lineage: grant.lineage,
        depth,
        status: grant.status,
        issued_at: now,
        expires_at: now + lifetime,
        renewed: DelegationRenewal::NotRenewed,
        updated_at: now,
        name: None,
    })
    .expect("the test describes a consistent stored delegation")
}

/// A delegation a fresh person granted `agent`, as storage would read it
/// back: nothing but its limits, for ten minutes, tied to `intent` when
/// there is one and titled `name` when given.
///
/// # Panics
///
/// - Never: the lifetime and depth are within bounds.
#[must_use]
pub fn grant_to(
    agent: AgentId,
    intent: Option<IntentBinding>,
    name: Option<Label>,
) -> Delegation<ResolvedTenant> {
    let now = clock::now();
    let limits = DelegationConstraints::new(GRANT_LIFETIME, GRANT_DEPTH)
        .expect("ten minutes and depth two are within bounds");
    let constraints = match intent {
        Some(binding) => limits.with_intent(binding),
        None => limits,
    };
    Delegation::reconstitute(DelegationRow {
        id: DelegationId::new(),
        delegator: PrincipalRef::User(UserId::new()),
        delegate: agent,
        granted: CapabilitySet::empty(),
        constraints,
        lineage: Lineage::Root,
        depth: 0,
        status: DelegationStatus::Active,
        issued_at: now,
        expires_at: now + GRANT_LIFETIME.duration(),
        renewed: DelegationRenewal::NotRenewed,
        updated_at: now,
        name,
    })
    .expect("a fresh root grant is a consistent row")
}

/// How deep a chain [`root_delegation`] starts may grow.
const CHAIN_DEPTH: u8 = 3;

/// A delegation `delegator` granted `delegate`, giving `granted`, as
/// storage would read it back: for ten minutes, passed on at most three
/// levels deep.
///
/// # Panics
///
/// - When `delegator` is not a person: only a person starts a chain.
#[must_use]
pub fn root_delegation(
    delegator: PrincipalRef,
    delegate: AgentId,
    granted: CapabilitySet,
) -> Delegation<ResolvedTenant> {
    let now = clock::now();
    Delegation::reconstitute(DelegationRow {
        id: DelegationId::new(),
        delegator,
        delegate,
        granted,
        constraints: chain_limits(),
        lineage: Lineage::Root,
        depth: 0,
        status: DelegationStatus::Active,
        issued_at: now,
        expires_at: now + GRANT_LIFETIME.duration(),
        renewed: DelegationRenewal::NotRenewed,
        updated_at: now,
        name: None,
    })
    .expect("a fresh root grant from a person is a consistent row")
}

/// The part of `parent` its agent passed on to `delegate`, giving
/// `granted`, one level under it, as storage would read it back.
///
/// # Panics
///
/// - When `parent` already sits at the deepest level a chain allows.
#[must_use]
pub fn child_delegation(
    parent: &Delegation<ResolvedTenant>,
    delegate: AgentId,
    granted: CapabilitySet,
) -> Delegation<ResolvedTenant> {
    let now = clock::now();
    Delegation::reconstitute(DelegationRow {
        id: DelegationId::new(),
        delegator: PrincipalRef::Agent(*parent.delegate()),
        delegate,
        granted,
        constraints: chain_limits(),
        lineage: Lineage::Under(*parent.id()),
        depth: parent.depth() + 1,
        status: DelegationStatus::Active,
        issued_at: now,
        expires_at: now + GRANT_LIFETIME.duration(),
        renewed: DelegationRenewal::NotRenewed,
        updated_at: now,
        name: None,
    })
    .expect("a child one level under its parent is a consistent row")
}

/// Ten minutes, three levels deep.
fn chain_limits() -> DelegationConstraints {
    DelegationConstraints::new(GRANT_LIFETIME, CHAIN_DEPTH)
        .expect("ten minutes and depth three are within bounds")
}

/// One `derived` delegation's authority recorded as coming from `source`.
type Provenance = (TenantId, DelegationId, DelegationId);

/// In-memory delegation store: delegations are kept per tenant and saved in
/// place, and revoking one revokes everything cut or minted from it.
#[derive(Default)]
pub struct FakeDelegationStore {
    delegations: Shelf<Delegation<ResolvedTenant>>,
    provenance: Mutex<Vec<Provenance>>,
    revocation: Mutex<Revocation>,
    revoke_during_provenance: Mutex<Option<DelegationId>>,
    closure_reads: Mutex<Vec<Vec<DelegationId>>>,
    id_reads: Mutex<Vec<Vec<DelegationId>>>,
}

impl TenantScoped for FakeDelegationStore {}

impl FakeDelegationStore {
    /// The roots each closure read requested, to prove graph walks are batched.
    #[must_use]
    pub fn closure_reads(&self) -> Vec<Vec<DelegationId>> {
        self.closure_reads.lock().unwrap().clone()
    }

    /// The ids each hydration read requested, to expose repeated descendants.
    #[must_use]
    pub fn id_reads(&self) -> Vec<Vec<DelegationId>> {
        self.id_reads.lock().unwrap().clone()
    }

    /// A store holding no delegations.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Revokes `id` the moment the next provenance is recorded, as a revoke
    /// landing between a token exchange's reads and its writes would.
    pub fn revoke_while_recording_provenance(&self, id: DelegationId) {
        *self.revoke_during_provenance.lock().unwrap() = Some(id);
    }

    /// Makes every later subtree revocation fail, as an unreachable database
    /// would.
    pub fn fail_revocations(&self) {
        *self.revocation.lock().unwrap() = Revocation::Fails;
    }

    /// How many delegations are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.delegations.count()
    }

    /// Every delegation kept, in every tenant, oldest first.
    #[must_use]
    pub fn all(&self) -> Vec<Delegation<ResolvedTenant>> {
        self.delegations.all()
    }

    /// Every provenance edge recorded, as `(tenant, derived, source)`.
    #[must_use]
    pub fn provenance(&self) -> Vec<(TenantId, DelegationId, DelegationId)> {
        self.provenance.lock().unwrap().clone()
    }

    /// Records each of `edges` not already recorded.
    fn remember(&self, edges: impl Iterator<Item = Provenance>) {
        let mut provenance = self.provenance.lock().unwrap();
        for edge in edges {
            if !provenance.contains(&edge) {
                provenance.push(edge);
            }
        }
    }

    /// Revokes the delegation a racing revoke named, if one did.
    fn revoke_racing(&self, tenant_id: &ScopedTenant) -> Result<(), DomainError> {
        let Some(racing) = self.revoke_during_provenance.lock().unwrap().take() else {
            return Ok(());
        };
        self.delegations
            .revise(tenant_id, |stored| stored.id() == &racing, revoked)?;
        Ok(())
    }

    /// The delegations cut or minted straight from `source`.
    fn derived_from(&self, tenant_id: &ScopedTenant, source: DelegationId) -> Vec<DelegationId> {
        let recorded = self
            .provenance
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, _, from)| tenant == &**tenant_id && *from == source)
            .map(|(_, derived, _)| *derived)
            .collect::<Vec<_>>();
        self.delegations
            .filter(tenant_id, |stored| comes_from(stored, source))
            .iter()
            .map(|stored| *stored.id())
            .chain(recorded)
            .collect()
    }

    /// Walks every derivation edge once per reached id, excluding the root.
    fn closure_of(&self, tenant: &ScopedTenant, root: &DelegationId) -> Vec<DelegationId> {
        let mut closure: Vec<DelegationId> = Vec::new();
        let mut frontier = vec![*root];
        while let Some(current) = frontier.pop() {
            for id in self.derived_from(tenant, current) {
                if id != *root && !closure.contains(&id) {
                    closure.push(id);
                    frontier.push(id);
                }
            }
        }
        closure
    }
}

#[async_trait]
impl DelegationStore for FakeDelegationStore {
    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[DelegationId],
    ) -> Result<Vec<Delegation<ResolvedTenant>>, DomainError> {
        self.id_reads.lock().unwrap().push(ids.to_vec());
        Ok(self
            .delegations
            .filter(tenant_id, |stored| ids.contains(stored.id())))
    }

    async fn find_revocation_closures(
        &self,
        tenant_id: &ScopedTenant,
        roots: &[DelegationId],
    ) -> Result<HashMap<DelegationId, Vec<DelegationId>>, DomainError> {
        self.closure_reads.lock().unwrap().push(roots.to_vec());
        Ok(roots
            .iter()
            .map(|root| (*root, self.closure_of(tenant_id, root)))
            .collect())
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &DelegationId,
    ) -> Result<Option<Delegation<ResolvedTenant>>, DomainError> {
        self.id_reads.lock().unwrap().push(vec![*id]);
        Ok(self.delegations.find(tenant_id, |stored| stored.id() == id))
    }

    async fn list_for_agent(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentId,
    ) -> Result<Vec<Delegation<ResolvedTenant>>, DomainError> {
        Ok(self
            .delegations
            .filter(tenant_id, |stored| stored.delegate() == agent))
    }

    async fn find_by_delegator(
        &self,
        tenant_id: &ScopedTenant,
        delegator: &PrincipalRef,
    ) -> Result<Vec<Delegation<ResolvedTenant>>, DomainError> {
        Ok(self
            .delegations
            .filter(tenant_id, |stored| stored.delegator() == delegator))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        delegation: &Delegation<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let revoked_already = self
            .delegations
            .find(tenant_id, |stored| stored.id() == delegation.id())
            .is_some_and(|stored| stored.is_revoked());
        let kept = if revoked_already && !delegation.is_revoked() {
            revoked(delegation)?
        } else {
            delegation.clone()
        };
        self.delegations
            .put(tenant_id, kept, |stored| stored.id() == delegation.id());
        Ok(())
    }

    async fn record_provenance(
        &self,
        tenant_id: &ScopedTenant,
        delegation_id: &DelegationId,
        sources: &[DelegationId],
    ) -> Result<(), DomainError> {
        self.remember(
            sources
                .iter()
                .map(|source| (**tenant_id, *delegation_id, *source)),
        );
        self.revoke_racing(tenant_id)
    }

    async fn resource_holders(
        &self,
        tenant_id: &ScopedTenant,
        resource: &ResourceRef,
    ) -> Result<Vec<ResourceHolder>, DomainError> {
        let now = clock::now();
        Ok(self
            .delegations
            .filter(tenant_id, |stored| stored.is_valid(now))
            .iter()
            .flat_map(|stored| holders_of(stored, resource))
            .collect())
    }

    async fn revoke_subtree(
        &self,
        tenant_id: &ScopedTenant,
        root: &DelegationId,
    ) -> Result<Vec<RevokedDelegation>, DomainError> {
        if *self.revocation.lock().unwrap() == Revocation::Fails {
            return Err(DomainError::infra_msg("delegation store unreachable"));
        }
        let mut ids = self.find_revocation_closure(tenant_id, root).await?;
        ids.push(*root);
        let revised = self.delegations.revise(
            tenant_id,
            |stored| ids.contains(stored.id()) && !stored.is_revoked(),
            revoked,
        )?;
        Ok(revised
            .iter()
            .map(|stored| RevokedDelegation {
                id: *stored.id(),
                delegate: *stored.delegate(),
            })
            .collect())
    }

    async fn find_revocation_closure(
        &self,
        tenant_id: &ScopedTenant,
        root: &DelegationId,
    ) -> Result<Vec<DelegationId>, DomainError> {
        self.closure_reads.lock().unwrap().push(vec![*root]);
        Ok(self.closure_of(tenant_id, root))
    }
}

/// Token issuer that mints the same fixed token for every delegation.
pub struct FakeTaskTokenIssuer;

#[async_trait]
impl TaskTokenIssuer for FakeTaskTokenIssuer {
    async fn issue(
        &self,
        _tenant_id: &ScopedTenant,
        _issuer: &Issuer,
        _delegation: &Delegation<ResolvedTenant>,
    ) -> Result<TaskToken, DomainError> {
        Ok(TaskToken::new("test.task.token"))
    }
}

/// Token issuer that refuses every delegation as a conflict, the way a real
/// issuer answers a request it cannot meet, such as binding a token to a
/// credential that has no bindable key, rather than failing outright.
pub struct ConflictingTaskTokenIssuer;

#[async_trait]
impl TaskTokenIssuer for ConflictingTaskTokenIssuer {
    async fn issue(
        &self,
        _tenant_id: &ScopedTenant,
        _issuer: &Issuer,
        _delegation: &Delegation<ResolvedTenant>,
    ) -> Result<TaskToken, DomainError> {
        Err(DomainError::conflict("no bindable credential key"))
    }
}

/// A budget counter that has never seen a request.
pub struct NoBudgetUsage;

#[async_trait]
impl BudgetUsageReader for NoBudgetUsage {
    async fn current_usage(&self, _delegation_id: &DelegationId) -> Option<u32> {
        None
    }
}

/// `delegation`, revoked now, as the store's one-statement revoke writes it.
fn revoked(
    delegation: &Delegation<ResolvedTenant>,
) -> Result<Delegation<ResolvedTenant>, DomainError> {
    Delegation::reconstitute(DelegationRow {
        id: *delegation.id(),
        delegator: *delegation.delegator(),
        delegate: *delegation.delegate(),
        granted: delegation.granted().clone(),
        constraints: delegation.constraints().clone(),
        lineage: delegation.lineage().clone(),
        depth: delegation.depth(),
        status: DelegationStatus::Revoked,
        issued_at: delegation.created_at(),
        expires_at: delegation.expires_at(),
        renewed: delegation.renewed(),
        updated_at: clock::now().max(delegation.updated_at()),
        name: delegation.name().cloned(),
    })
}

/// Whether `delegation` was cut or minted straight from `source`.
fn comes_from(delegation: &Delegation<ResolvedTenant>, source: DelegationId) -> bool {
    match delegation.lineage() {
        Lineage::Root => false,
        Lineage::Under(parent) => *parent == source,
        Lineage::Minted { from, .. } => from.contains(&source),
    }
}

/// The agent `delegation` goes to, once for each relation it grants on
/// `resource`.
fn holders_of(
    delegation: &Delegation<ResolvedTenant>,
    resource: &ResourceRef,
) -> Vec<ResourceHolder> {
    delegation
        .granted()
        .resources()
        .iter()
        .filter(|capability| capability.resource_ref() == resource)
        .map(|capability| ResourceHolder {
            agent: *delegation.delegate(),
            relation: capability.relation().clone(),
        })
        .collect()
}

impl Fake for Arc<dyn BudgetUsageReader> {
    fn fake() -> Self {
        Arc::new(NoBudgetUsage)
    }
}

impl Fake for Arc<dyn DelegationStore> {
    fn fake() -> Self {
        Arc::new(FakeDelegationStore::empty())
    }
}

impl Fake for Arc<dyn TaskTokenIssuer> {
    fn fake() -> Self {
        Arc::new(FakeTaskTokenIssuer)
    }
}

impl Fake for GrantRevocation {
    fn fake() -> Self {
        Self::new(Fake::fake())
    }
}

impl Fake for OrgGrantRevocation {
    fn fake() -> Self {
        Self::new(Fake::fake(), Fake::fake())
    }
}

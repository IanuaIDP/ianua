//! A delegation a member granted in one of their organization's tenants,
//! for tests showing that taking a member's standing away revokes what
//! they granted.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::capability::{CapabilitySet, DelegationConstraints};
use ianua_domain::domains::agents::authority::delegation::{DelegationStatus, Lineage};
use ianua_domain::types::{
    AgentId, DelegationId, OrgUserId, OrganizationId, PrincipalRef, Seconds, TenantId,
};

use crate::ports::agents::DelegationStore;
use crate::services::authorization::grant_revocation::{GrantRevocation, OrgGrantRevocation};
use crate::tenancy::ScopedTenant;
use crate::test_support::agents::{FakeDelegationStore, StoredGrant, stored_delegation};
use crate::test_support::block_on;
use crate::test_support::tenant::{FakeTenantStore, test_tenant_in};

/// One tenant of an organization holding one delegation a member granted,
/// and the revocation that reads them.
pub struct DelegatedGrant {
    revocation: OrgGrantRevocation,
    delegations: Arc<FakeDelegationStore>,
    tenant_id: TenantId,
    grant: DelegationId,
}

impl DelegatedGrant {
    /// The revocation over the tenant and its delegations.
    #[must_use]
    pub fn revocation(&self) -> OrgGrantRevocation {
        self.revocation.clone()
    }

    /// Whether the delegation was revoked.
    ///
    /// # Panics
    ///
    /// Panics if the delegation is no longer stored.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        let tenant = ScopedTenant::for_test(self.tenant_id);
        block_on(self.delegations.find_by_id(&tenant, &self.grant))
            .expect("the store reads")
            .expect("the delegation is stored")
            .is_revoked()
    }
}

/// One tenant of `organization_id` holding an active delegation `member`
/// granted a fresh agent.
///
/// # Panics
///
/// Never in practice: the delegation's limits are within bounds.
#[must_use]
pub fn delegation_granted_by(organization_id: OrganizationId, member: OrgUserId) -> DelegatedGrant {
    let tenant = test_tenant_in(organization_id, "acme", "acme.test");
    let tenant_id = *tenant.id();
    let delegation = stored_delegation(StoredGrant {
        delegator: PrincipalRef::OrgUser(member),
        delegate: AgentId::new(),
        granted: CapabilitySet::new(Vec::new(), Vec::new()),
        constraints: DelegationConstraints::new(Seconds::new(600), 1)
            .expect("ten minutes and depth one are within bounds"),
        lineage: Lineage::Root,
        status: DelegationStatus::Active,
    });
    let grant = *delegation.id();
    let delegations = Arc::new(FakeDelegationStore::empty());
    block_on(delegations.save(&ScopedTenant::for_test(tenant_id), &delegation))
        .expect("the store saves");
    DelegatedGrant {
        revocation: OrgGrantRevocation::new(
            Arc::new(FakeTenantStore::holding(tenant)),
            GrantRevocation::new(delegations.clone()),
        ),
        delegations,
        tenant_id,
        grant,
    }
}

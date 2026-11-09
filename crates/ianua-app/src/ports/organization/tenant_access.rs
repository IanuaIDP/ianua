//! Which organization a tenant belongs to, and the access it grants members.

use async_trait::async_trait;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::organization::members::reach::MemberReach;
use ianua_domain::domains::organization::members::tenant_grant::OrgTenantGrant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrgUserId, OrganizationId, TenantId};

use crate::tenancy::ScopedTenant;

/// The organization's members who may hold rights in one of its tenants,
/// with the grants they hold there, as the domain weighs them.
#[derive(Debug, Default)]
pub struct MembersInTenant {
    /// Every member whose role reaches every tenant (its owners and
    /// admins), and every plain member with a grant in the tenant,
    /// whatever their status: the domain decides who may act.
    pub members: Vec<OrgUser>,
    /// Those members' grants in the tenant.
    pub grants: Vec<OrgTenantGrant>,
}

/// Dyn-safe port for who in an organization might hold rights in one of
/// its tenants, read in one query.
///
/// Answers questions such as who else could approve a policy without
/// reading every member's grants one member at a time.
#[async_trait]
pub trait TenantMemberRoster: Send + Sync {
    /// The members of `organization_id` who might hold rights in
    /// `tenant_id`: every owner and admin, whose role reaches every tenant,
    /// and every plain member with at least one grant there, with those
    /// grants.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure, or when a
    /// stored member breaks a rule it keeps.
    async fn members_in(
        &self,
        organization_id: &OrganizationId,
        tenant_id: &TenantId,
    ) -> Result<MembersInTenant, DomainError>;
}

/// Dyn-safe port for the tenant roles an org user holds.
///
/// Grants are org-plane state keyed by `org_user_id`, not tenant-plane
/// `role_assignments` (whose `user_id` names a tenant user), so they live
/// behind their own port.
#[async_trait]
pub trait OrgTenantGrantStore: Send + Sync {
    /// Lists every grant an org user holds across the organization.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_by_user(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Vec<OrgTenantGrant>, DomainError>;

    /// Lists an org user's grants in one tenant.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_by_user_in_tenant(
        &self,
        org_user_id: &OrgUserId,
        tenant_id: &TenantId,
    ) -> Result<Vec<OrgTenantGrant>, DomainError>;

    /// Every tenant the org user has been let into, in grant order.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_tenant_ids(&self, org_user_id: &OrgUserId) -> Result<Vec<TenantId>, DomainError>;

    /// Replaces the org user's roles in one tenant with exactly `grants`.
    ///
    /// An empty slice withdraws access to that tenant. Replacing rather than
    /// adding keeps the stored set equal to what the caller asked for, so a
    /// narrowing is a narrowing and not a no-op.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn replace_in_tenant(
        &self,
        org_user_id: &OrgUserId,
        tenant_id: &TenantId,
        grants: &[OrgTenantGrant],
    ) -> Result<(), DomainError>;
}

/// An organization member as a tenant reads them while they are signed
/// out: what their reach reads of them, their organization, and their
/// grants in the tenant.
#[derive(Debug, Clone)]
pub struct MemberStanding {
    /// Who they are, whose member, in what role and status.
    pub member: MemberReach,
    /// The owning organization whose status constrains this member.
    pub organization: Organization,
    /// Their grants in the tenant.
    pub grants: Vec<OrgTenantGrant>,
}

/// Reads an organization member as a tenant judges work done for them
/// while they are signed out, such as an agent's request under their
/// delegation at the gateway.
///
/// It reads nothing of how a member signs in, so the gateway's own role may
/// answer it.
#[async_trait]
pub trait MemberStandings: Send + Sync {
    /// `member` as `tenant` reads them now. `None` when the member or their
    /// organization is gone.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the records cannot be
    /// read, or name a role or status the domain does not know.
    async fn member_in(
        &self,
        tenant: &ScopedTenant,
        member: &OrgUserId,
    ) -> Result<Option<MemberStanding>, DomainError>;
}

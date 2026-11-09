//! Where the authentication fakes keep a record: in one tenant, or on the
//! organization plane, the way the real stores keep them in different
//! databases.

use ianua_domain::types::{OrgUserId, OrganizationId, PrincipalId, TenantId, UserId};

use crate::context::CallerIdentity;
use crate::services::authentication::sign_in_steps::SeedHolder;
use crate::tenancy::ScopedTenant;
use crate::test_support::test_ctx;

/// The tenant user [`test_ctx`] signs in as.
///
/// # Panics
///
/// Never: the test caller is a tenant user.
#[must_use]
pub fn test_caller_id() -> UserId {
    let caller = test_ctx();
    let CallerIdentity::TenantUser(user) = caller.identity() else {
        unreachable!("the test caller is a tenant user");
    };
    *user
}

/// Where a record lives: in one tenant, or on the organization plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Plane {
    /// In this tenant, found only through a store opened for it.
    Tenant(TenantId),
    /// On the organization plane, outside every tenant.
    Organization,
}

impl Plane {
    /// The plane of the tenant a store call names.
    #[must_use]
    pub fn of(tenant: &ScopedTenant) -> Self {
        Self::Tenant(**tenant)
    }

    /// The plane of the tenant every test caller belongs to.
    #[must_use]
    pub fn test_tenant() -> Self {
        Self::Tenant(test_ctx().tenant_id())
    }
}

/// Whose record a seeding helper makes, and where it is kept: a tenant
/// user's in the test tenant, an organization member's on the organization
/// plane, as a member of the test organization unless named otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Holder {
    plane: Plane,
    subject: PrincipalId,
    seeds: SeedHolder,
}

impl Holder {
    /// `user_id`, kept in `tenant_id` rather than the test tenant.
    #[must_use]
    pub fn in_tenant(tenant_id: TenantId, user_id: UserId) -> Self {
        Self {
            plane: Plane::Tenant(tenant_id),
            subject: user_id.into(),
            seeds: SeedHolder::TenantUser(tenant_id),
        }
    }

    /// `org_user_id`, a member of `organization_id` rather than the test
    /// organization.
    #[must_use]
    pub fn member_of(organization_id: OrganizationId, org_user_id: OrgUserId) -> Self {
        Self {
            plane: Plane::Organization,
            subject: org_user_id.into(),
            seeds: SeedHolder::Member(organization_id),
        }
    }

    /// Where the record is kept.
    #[must_use]
    pub fn plane(&self) -> Plane {
        self.plane
    }

    /// Whose record it is.
    #[must_use]
    pub fn subject(&self) -> PrincipalId {
        self.subject
    }

    /// Who keeps the holder's authenticator seed, which its sealed form is
    /// bound to.
    pub(crate) fn seeds(&self) -> SeedHolder {
        self.seeds
    }
}

impl From<UserId> for Holder {
    fn from(user_id: UserId) -> Self {
        Self::in_tenant(test_ctx().tenant_id(), user_id)
    }
}

impl From<OrgUserId> for Holder {
    fn from(org_user_id: OrgUserId) -> Self {
        Self::member_of(test_ctx().organization_id(), org_user_id)
    }
}

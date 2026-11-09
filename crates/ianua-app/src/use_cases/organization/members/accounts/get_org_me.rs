//! The signed-in member's own account and what it reaches: the answer the
//! dashboard reads on almost every page.
//!
//! Every member reads their own account, whatever their role. Reading
//! another member's account needs the right to view members, through
//! [`crate::use_cases::organization::members::rights::get_org_user_access`].

use std::sync::Arc;

use ianua_domain::domains::organization::members::org_user::OrgUser;

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::AppError;
use crate::ports::authorization::RoleStore;
use crate::ports::organization::{OrgTenantGrantStore, OrgUserStore};
use crate::ports::tenant::TenantStore;
use crate::use_case::Query;
use crate::use_cases::organization::lookup::existing_member;
use crate::use_cases::organization::members::rights::access::{AccessSources, OrgUserAccess};

/// The caller's own account and what it reaches.
pub struct OrgMe {
    /// The member's account as it stands now.
    pub member: OrgUser,
    /// The tenants they reach, with their permissions in each.
    pub access: OrgUserAccess,
}

/// The ports [`GetOrgMeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetOrgMePorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// The organization's members.
    pub org_users: Arc<dyn OrgUserStore>,
    /// The organization's tenants.
    pub tenants: Arc<dyn TenantStore>,
    /// Each tenant's roles, to name and expand granted roles.
    pub roles: Arc<dyn RoleStore>,
    /// The tenants and roles members were granted.
    pub grants: Arc<dyn OrgTenantGrantStore>,
}

/// Reads the caller's own account.
pub struct GetOrgMeUseCase {
    ports: GetOrgMePorts,
}

impl GetOrgMeUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetOrgMePorts) -> Self {
        Self { ports }
    }

    /// Where a member's reach is read from.
    fn sources(&self) -> AccessSources<'_> {
        AccessSources {
            tenants: self.ports.tenants.as_ref(),
            roles: self.ports.roles.as_ref(),
            grants: self.ports.grants.as_ref(),
        }
    }
}

impl Query for GetOrgMeUseCase {
    type Caller = OrgCaller;
    type Input = ();
    type Output = Result<OrgMe, AppError>;

    /// The caller's own account and what it reaches now.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the organization turns the caller away.
    /// - `AppError::NotFound` when the member's account is gone.
    /// - `AppError::Internal` when a store fails.
    async fn execute(&self, caller: &OrgCaller, (): ()) -> Result<OrgMe, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        actor.control()?;
        let users = self.ports.org_users.as_ref();
        let member = existing_member(users, organization.id(), actor.member().id()).await?;
        let access = self.sources().reach_of(&member).await?;
        Ok(OrgMe { member, access })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{org_user_store_with, stored_caller};
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_in};
    use crate::test_support::{block_on, test_org_caller};

    /// A use case where the caller acts as `actors` say, with their own
    /// account stored as `stored` says, in an organization with one tenant.
    fn use_case(actors: FakeOrgActors, stored: Stored) -> GetOrgMeUseCase {
        let caller = test_org_caller();
        let org_id = caller.organization_id();
        let tenant = test_tenant_in(org_id, "production", "production.test");
        let users = match stored {
            Stored::Kept => org_user_store_with([stored_caller(OrgRole::Billing, "irrelevant")]),
            Stored::Gone => org_user_store_with([]),
        };
        GetOrgMeUseCase::new(GetOrgMePorts {
            org_actors: Arc::new(actors),
            org_users: Arc::new(users),
            tenants: Arc::new(FakeTenantStore::holding_all([tenant])),
            ..GetOrgMePorts::fakes()
        })
    }

    /// Whether the caller's account is in the store.
    #[derive(Clone, Copy)]
    enum Stored {
        /// The test store still contains the caller's account.
        Kept,
        /// It was removed.
        Gone,
    }

    /// Reads the caller's own account through `use_case`.
    fn me(use_case: &GetOrgMeUseCase) -> Result<OrgMe, AppError> {
        block_on(use_case.execute(&test_org_caller(), ()))
    }

    /// Bea handles Acme's invoices and may not view other members. She
    /// still reads her own account, which reaches no tenant.
    #[test]
    fn a_billing_contact_reads_their_own_account() {
        let use_case = use_case(FakeOrgActors::in_role(OrgRole::Billing), Stored::Kept);

        let me = me(&use_case).unwrap();

        assert_eq!(me.member.id(), test_org_caller().member());
        assert_eq!(me.access.org_role, OrgRole::Billing);
        assert!(me.access.tenants.is_empty());
    }

    /// A signed-out caller cannot read the account, even while it remains stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = use_case(FakeOrgActors::refusing(Refusal::SignedOut), Stored::Kept);

        assert!(matches!(me(&use_case), Err(AppError::Unauthenticated)));
    }

    /// Bea's account was removed while her page was open. It is not
    /// found.
    #[test]
    fn a_removed_account_is_not_found() {
        let use_case = use_case(FakeOrgActors::in_role(OrgRole::Billing), Stored::Gone);

        assert!(matches!(me(&use_case), Err(AppError::NotFound(_))));
    }
}

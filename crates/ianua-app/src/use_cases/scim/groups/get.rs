//! Get SCIM group: one group the directory keeps, with its users.

use std::sync::Arc;

use ianua_domain::types::GroupId;

use crate::acting::ScimAuthorities;
use crate::context::ScimCaller;
use crate::error::AppError;
use crate::ports::authorization::{GroupMembershipStore, GroupStore};
use crate::use_case::Query;
use crate::use_cases::scim::groups::fields::ScimGroup;
use crate::use_cases::scim::groups::roster::{directory_group, with_members};

/// The ports [`GetScimUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetScimPorts {
    /// Signs the directory in with its token.
    pub scim_authorities: Arc<dyn ScimAuthorities>,
    /// Reads the tenant's groups.
    pub group_store: Arc<dyn GroupStore>,
    /// Reads who is in them.
    pub membership_store: Arc<dyn GroupMembershipStore>,
}

/// Reads one group a tenant's directory keeps.
pub struct GetScimUseCase {
    ports: GetScimPorts,
}

impl GetScimUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetScimPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetScimUseCase {
    type Caller = ScimCaller;
    type Input = GroupId;
    type Output = Result<ScimGroup, AppError>;

    /// The group with `group_id`, with its users.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the directory's token is missing,
    ///   not the tenant's current one, or SCIM is switched off.
    /// - `AppError::NotFound` when the tenant has no such group, or a person
    ///   keeps it in the dashboard.
    /// - `AppError::Internal` on lookup failure.
    async fn execute(&self, caller: &ScimCaller, group_id: GroupId) -> Result<ScimGroup, AppError> {
        self.ports.scim_authorities.endpoint(caller).await?;
        let tenant = caller.tenant();
        let group = directory_group(self.ports.group_store.as_ref(), tenant, &group_id).await?;
        with_members(self.ports.membership_store.as_ref(), tenant, group).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::group::{Group, GroupOrigin};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{Expiry, PrincipalRef, TenantId, UserId};
    use time::Duration;

    use super::*;
    use crate::test_support::authorization::{
        FakeGroupMembershipStore, FakeGroupStore, stored_membership, stored_membership_until,
    };
    use crate::test_support::scim::{
        SignInRefusal, kept_group, refused_sign_in, scim_caller, signed_in,
    };
    use crate::test_support::{block_on, test_ctx};

    fn use_case(
        scim_authorities: Arc<dyn ScimAuthorities>,
        groups: FakeGroupStore,
        memberships: FakeGroupMembershipStore,
    ) -> GetScimUseCase {
        GetScimUseCase::new(GetScimPorts {
            scim_authorities,
            group_store: Arc::new(groups),
            membership_store: Arc::new(memberships),
        })
    }

    fn holding(group: Group<ResolvedTenant>) -> FakeGroupStore {
        FakeGroupStore::holding(test_ctx().tenant_id(), [group])
    }

    /// Okta reads Engineering. It gets the group, with Ada in it.
    #[test]
    fn a_group_is_read_with_its_users() {
        let ada = UserId::new();
        let engineering = kept_group("Engineering", GroupOrigin::Directory);
        let id = *engineering.id();
        let memberships = FakeGroupMembershipStore::holding(
            test_ctx().tenant_id(),
            [stored_membership(PrincipalRef::User(ada), id)],
        );
        let use_case = use_case(signed_in(), holding(engineering), memberships);

        let group = block_on(use_case.execute(&scim_caller(), id)).unwrap();

        assert_eq!(group.group.name().as_str(), "Engineering");
        assert_eq!(group.members, [ada]);
    }

    /// Reading a group excludes a stored membership that expired yesterday
    /// and returns only the member whose place remains in force.
    #[test]
    fn a_place_that_ran_out_is_not_shown() {
        let (ada, grace) = (UserId::new(), UserId::new());
        let engineering = kept_group("Engineering", GroupOrigin::Directory);
        let id = *engineering.id();
        let ran_out = Expiry::At(clock::now() - Duration::days(1));
        let memberships = FakeGroupMembershipStore::holding(
            test_ctx().tenant_id(),
            [
                stored_membership(PrincipalRef::User(ada), id),
                stored_membership_until(PrincipalRef::User(grace), id, ran_out),
            ],
        );
        let use_case = use_case(signed_in(), holding(engineering), memberships);

        let group = block_on(use_case.execute(&scim_caller(), id)).unwrap();

        assert_eq!(group.members, [ada]);
    }

    /// Reading a group maintained through the dashboard returns not found
    /// to the directory.
    #[test]
    fn a_group_the_directory_does_not_keep_is_not_found() {
        let admins = kept_group("Admins", GroupOrigin::Dashboard);
        let id = *admins.id();
        let use_case = use_case(
            signed_in(),
            holding(admins),
            FakeGroupMembershipStore::empty(),
        );

        let result = block_on(use_case.execute(&scim_caller(), id));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A directory reading another tenant's group receives not found.
    #[test]
    fn a_group_of_another_tenant_is_not_found() {
        let globex = kept_group("Engineering", GroupOrigin::Directory);
        let id = *globex.id();
        let groups = FakeGroupStore::holding(TenantId::new(), [globex]);
        let use_case = use_case(signed_in(), groups, FakeGroupMembershipStore::empty());

        let result = block_on(use_case.execute(&scim_caller(), id));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Reading a group with a missing, invalid or rotated token, or with
    /// SCIM disabled, returns an unauthenticated error.
    #[test]
    fn a_directory_that_is_not_signed_in_is_refused() {
        for refusal in SignInRefusal::ALL {
            let engineering = kept_group("Engineering", GroupOrigin::Directory);
            let id = *engineering.id();
            let (scim_authorities, caller) = refused_sign_in(refusal);
            let use_case = use_case(
                scim_authorities,
                holding(engineering),
                FakeGroupMembershipStore::empty(),
            );

            let result = block_on(use_case.execute(&caller, id));

            assert!(
                matches!(result, Err(AppError::Unauthenticated)),
                "{refusal:?}"
            );
        }
    }
}

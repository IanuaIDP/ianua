//! List SCIM groups: the groups the directory keeps, each with its users,
//! as the directory pages through them or looks one up by name.

use std::sync::Arc;

use ianua_domain::domains::authorization::group::{Group, GroupMembership};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::GroupId;

use crate::acting::ScimAuthorities;
use crate::context::ScimCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::GroupMembershipStore;
use crate::ports::federation::{
    ScimGroupAttribute, ScimGroupQueries, ScimPage, ScimQuery, ScimWindow,
};
use crate::use_case::Query;
use crate::use_cases::scim::groups::fields::ScimGroup;
use crate::use_cases::scim::groups::roster::{in_force, user_members};

/// Which groups to list, and which page of them.
pub struct ListScimRequest {
    /// Picks the groups returned: `displayName` compared with `eq`, `co`
    /// or `sw`, joined by `and` and `or`.
    pub filter: ScimQuery<ScimGroupAttribute>,
    /// The page to return.
    pub page: ScimWindow,
}

/// The ports [`ListScimUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListScimPorts {
    /// Signs the directory in with its token.
    pub scim_authorities: Arc<dyn ScimAuthorities>,
    /// Finds the page of groups the filter picks.
    pub group_queries: Arc<dyn ScimGroupQueries>,
    /// Reads who is in the groups on the page.
    pub memberships: Arc<dyn GroupMembershipStore>,
}

/// Lists the groups a tenant's directory keeps.
pub struct ListScimUseCase {
    ports: ListScimPorts,
}

impl ListScimUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListScimPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListScimUseCase {
    type Caller = ScimCaller;
    type Input = ListScimRequest;
    type Output = Result<ScimPage<ScimGroup>, AppError>;

    /// One page of the groups the directory keeps, oldest first, each with
    /// its users. Groups a person keeps in the dashboard are left out. Only
    /// the page's groups and their members are read.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the directory's token is missing,
    ///   not the tenant's current one, or SCIM is switched off.
    /// - `AppError::Internal` on lookup failure.
    async fn execute(
        &self,
        caller: &ScimCaller,
        request: ListScimRequest,
    ) -> Result<ScimPage<ScimGroup>, AppError> {
        let ListScimRequest { filter, page } = request;
        self.ports.scim_authorities.endpoint(caller).await?;
        let tenant = caller.tenant();
        let groups = self
            .ports
            .group_queries
            .find(tenant, &filter, page)
            .await
            .or_internal()?;
        let ids: Vec<GroupId> = groups.items.iter().map(|group| *group.id()).collect();
        let memberships = self
            .ports
            .memberships
            .find_by_groups(tenant, &ids)
            .await
            .or_internal()?;
        let memberships = in_force(memberships);
        Ok(groups.map(|group| scim_group(group, &memberships)))
    }
}

/// `group` with its users among `memberships`, the places in force now.
fn scim_group(
    group: Group<ResolvedTenant>,
    memberships: &[GroupMembership<ResolvedTenant>],
) -> ScimGroup {
    let own = memberships
        .iter()
        .filter(|held| held.group_id() == group.id());
    ScimGroup {
        members: user_members(own),
        group,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::group::GroupOrigin;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{Expiry, PrincipalRef, UserId};
    use time::Duration;

    use super::*;
    use crate::ports::federation::{ScimFilterValue, ScimOperator};
    use crate::test_support::authorization::{
        FakeGroupMembershipStore, FakeGroupStore, stored_membership, stored_membership_until,
    };
    use crate::test_support::scim::{
        SignInRefusal, kept_group, refused_sign_in, scim_caller, signed_in,
    };
    use crate::test_support::{block_on, test_ctx};

    struct Acme {
        groups: Arc<FakeGroupStore>,
        memberships: Arc<FakeGroupMembershipStore>,
        ada: UserId,
    }

    fn acme() -> Acme {
        let ada = UserId::new();
        let engineering = kept_group("Engineering", GroupOrigin::Directory);
        let ada_in = stored_membership(PrincipalRef::User(ada), *engineering.id());
        let groups = [
            engineering,
            kept_group("Sales", GroupOrigin::Directory),
            kept_group("Admins", GroupOrigin::Dashboard),
        ];
        let tenant = test_ctx().tenant_id();
        Acme {
            groups: Arc::new(FakeGroupStore::holding(tenant, groups)),
            memberships: Arc::new(FakeGroupMembershipStore::holding(tenant, [ada_in])),
            ada,
        }
    }

    impl Acme {
        fn list_window(
            &self,
            scim_authorities: Arc<dyn ScimAuthorities>,
            caller: &ScimCaller,
            request: ListScimRequest,
        ) -> Result<ScimPage<ScimGroup>, AppError> {
            let use_case = ListScimUseCase::new(ListScimPorts {
                scim_authorities,
                group_queries: self.groups.clone(),
                memberships: self.memberships.clone(),
            });
            block_on(use_case.execute(caller, request))
        }

        fn list(
            &self,
            scim_authorities: Arc<dyn ScimAuthorities>,
            caller: &ScimCaller,
            filter: ScimQuery<ScimGroupAttribute>,
        ) -> Result<ScimPage<ScimGroup>, AppError> {
            let request = ListScimRequest {
                filter,
                page: ScimWindow::new(1, 100),
            };
            self.list_window(scim_authorities, caller, request)
        }
    }

    fn named(operator: ScimOperator, name: &str) -> ScimQuery<ScimGroupAttribute> {
        ScimQuery::Compare {
            attribute: ScimGroupAttribute::DisplayName,
            operator,
            value: ScimFilterValue::new(name).unwrap(),
        }
    }

    /// Entra looks for groups whose name starts with `eng`, in any case.
    /// It finds Engineering.
    #[test]
    fn a_group_is_found_by_the_start_of_its_name() {
        let acme = acme();

        let page = acme
            .list(
                signed_in(),
                &scim_caller(),
                named(ScimOperator::StartsWith, "ENG"),
            )
            .unwrap();

        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].group.name().as_str(), "Engineering");
    }

    /// Okta pages through Acme's groups. It sees the two it keeps, each with
    /// its users, and not the dashboard's Admins group.
    #[test]
    fn only_the_groups_the_directory_keeps_are_listed() {
        let acme = acme();

        let page = acme
            .list(signed_in(), &scim_caller(), ScimQuery::All)
            .unwrap();

        let names: Vec<_> = page
            .items
            .iter()
            .map(|item| item.group.name().as_str())
            .collect();
        assert_eq!(page.total, 2);
        assert!(names.contains(&"Engineering") && names.contains(&"Sales"));
    }

    /// Listing a group excludes a stored membership that expired yesterday
    /// and returns only the member whose place remains in force.
    #[test]
    fn a_place_that_ran_out_is_not_listed() {
        let acme = acme();
        let tenant = test_ctx().tenant();
        let adas = block_on(
            acme.memberships
                .find_by_principal(&tenant, &PrincipalRef::User(acme.ada)),
        )
        .unwrap();
        let ran_out = stored_membership_until(
            PrincipalRef::User(UserId::new()),
            *adas[0].group_id(),
            Expiry::At(clock::now() - Duration::days(1)),
        );
        block_on(acme.memberships.save(&tenant, &ran_out)).unwrap();

        let page = acme
            .list(
                signed_in(),
                &scim_caller(),
                named(ScimOperator::Equals, "Engineering"),
            )
            .unwrap();

        assert_eq!(page.items[0].members, [acme.ada]);
    }

    /// Okta reads Acme's groups one at a time. The second page holds one
    /// group, and the total still counts both the directory keeps.
    #[test]
    fn groups_are_read_one_window_at_a_time() {
        let acme = acme();
        let request = ListScimRequest {
            filter: ScimQuery::All,
            page: ScimWindow::new(2, 1),
        };

        let page = acme
            .list_window(signed_in(), &scim_caller(), request)
            .unwrap();

        assert_eq!((page.items.len(), page.total), (1, 2));
    }

    /// Okta looks Engineering up by name. It finds it, with Ada in it.
    #[test]
    fn a_group_is_looked_up_by_name() {
        let acme = acme();

        let page = acme
            .list(
                signed_in(),
                &scim_caller(),
                named(ScimOperator::Equals, "Engineering"),
            )
            .unwrap();

        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].members, [acme.ada]);
    }

    /// Searching for a group maintained through the dashboard returns no
    /// matching groups to the directory.
    #[test]
    fn a_group_the_directory_does_not_keep_is_not_found() {
        let acme = acme();

        let page = acme
            .list(
                signed_in(),
                &scim_caller(),
                named(ScimOperator::Equals, "Admins"),
            )
            .unwrap();

        assert_eq!(page.total, 0);
    }

    /// Listing groups with a missing, invalid or rotated token, or with
    /// SCIM disabled, returns an unauthenticated error.
    #[test]
    fn a_directory_that_is_not_signed_in_is_refused() {
        let acme = acme();
        for refusal in SignInRefusal::ALL {
            let (scim_authorities, caller) = refused_sign_in(refusal);

            let result = acme.list(scim_authorities, &caller, ScimQuery::All);

            assert!(
                matches!(result, Err(AppError::Unauthenticated)),
                "{refusal:?}"
            );
        }
    }
}

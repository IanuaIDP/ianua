//! List group members: who holds a group's roles through belonging to it,
//! a page at a time.
//!
//! A membership confers the group's roles, so it is a grant like any other,
//! and a grant nobody can list cannot be reviewed or taken back. People,
//! agents and consumers are listed alike: a consumer in a partner tier
//! holds the tier's permissions at the proxy just as a person would.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::authorization::group::GroupMembership;
use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{EventLabel, GroupId, OrgUserId, PrincipalRef};
use time::OffsetDateTime;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::listing::{Page, PageRequest};
use crate::ports::authorization::{GroupMembershipStore, GroupStore};
use crate::ports::shared::{AuditLabelResolver, ControlPlaneLabelResolver};
use crate::use_case::Query;
use crate::use_cases::authorization::lookup::existing_group;

/// One member of a group, named as well as identified.
pub struct MemberView {
    /// The member.
    pub principal: PrincipalRef,
    /// The member's display name, or `None` when the row is gone.
    pub display_name: Option<String>,
    /// When the member joined.
    pub joined_at: OffsetDateTime,
}

/// Which group's members to list, and which page of them.
pub struct ListMembersRequest {
    /// The membership container whose direct members are requested.
    pub group_id: GroupId,
    /// Which page of its members, oldest membership first.
    pub page: PageRequest,
}

/// The ports [`ListMembersUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListMembersPorts {
    /// Confirms the group exists.
    pub group_store: Arc<dyn GroupStore>,
    /// Loads the memberships.
    pub membership_store: Arc<dyn GroupMembershipStore>,
    /// Names the page's members, together.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
    /// Names the page's members who are organization members, together.
    pub control_plane_label_resolver: Arc<dyn ControlPlaneLabelResolver>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the members of a group of the caller's tenant.
pub struct ListMembersUseCase {
    ports: ListMembersPorts,
}

impl ListMembersUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListMembersPorts) -> Self {
        Self { ports }
    }

    /// The name of each of `principals` that has one, read in one go per
    /// resolver: the tenant's records, and the organization's for its
    /// members.
    async fn names(
        &self,
        ctx: &CallerContext,
        principals: &[PrincipalRef],
    ) -> Result<HashMap<PrincipalRef, EventLabel>, AppError> {
        if principals.is_empty() {
            return Ok(HashMap::new());
        }
        let mut names = self
            .ports
            .audit_label_resolver
            .principals(&ctx.tenant(), principals)
            .await
            .or_internal()?;
        let org_users = org_users_among(principals);
        if org_users.is_empty() {
            return Ok(names);
        }
        let found = self
            .ports
            .control_plane_label_resolver
            .org_users(&ctx.organization_id(), &org_users)
            .await
            .or_internal()?;
        names.extend(
            found
                .into_iter()
                .map(|(id, label)| (PrincipalRef::OrgUser(id), label)),
        );
        Ok(names)
    }
}

impl Query for ListMembersUseCase {
    type Caller = CallerContext;
    type Input = ListMembersRequest;
    type Output = Result<Page<MemberView>, AppError>;

    /// One page of the members of `request.group_id`, whatever kind of
    /// principal they are, each named.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view roles, which
    ///   covers groups.
    /// - `AppError::NotFound` when the tenant has no such group.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: ListMembersRequest,
    ) -> Result<Page<MemberView>, AppError> {
        let ListMembersRequest { group_id, page } = request;
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Roles(RoleAction::View))
            .map_err(AppError::from_domain)?;
        existing_group(self.ports.group_store.as_ref(), &ctx.tenant(), &group_id).await?;
        let memberships = self
            .ports
            .membership_store
            .list_by_group(&ctx.tenant(), &group_id, &page)
            .await
            .map_err(AppError::from_domain)?;
        let principals: Vec<PrincipalRef> =
            memberships.items.iter().map(|m| *m.principal()).collect();
        let names = self.names(ctx, &principals).await?;
        Ok(memberships.map(|membership| member_view(&membership, &names)))
    }
}

/// The organization members among `principals`.
fn org_users_among(principals: &[PrincipalRef]) -> Vec<OrgUserId> {
    principals
        .iter()
        .filter_map(|principal| match principal {
            PrincipalRef::OrgUser(id) => Some(*id),
            PrincipalRef::User(_) | PrincipalRef::Agent(_) | PrincipalRef::Consumer(_) => None,
        })
        .collect()
}

/// `membership` as listed, named from `names` when its member has one.
fn member_view(
    membership: &GroupMembership<ResolvedTenant>,
    names: &HashMap<PrincipalRef, EventLabel>,
) -> MemberView {
    let principal = *membership.principal();
    MemberView {
        principal,
        display_name: names.get(&principal).cloned().map(String::from),
        joined_at: membership.joined_at(),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::group::GroupPlace;
    use ianua_domain::types::{ConsumerId, UserId};

    use super::*;
    use crate::listing::Limit;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        FakeGroupMembershipStore, FakeGroupStore, stored_group, stored_membership,
    };
    use crate::test_support::{FakeAuditLabelResolver, block_on, test_ctx};

    /// The group "Partners", with members in it and in other groups.
    struct Partners {
        id: GroupId,
        ports: ListMembersPorts,
    }

    impl Partners {
        fn with(members: &[PrincipalRef], elsewhere: &[PrincipalRef]) -> Self {
            let tenant = test_ctx().tenant_id();
            let group = stored_group("Partners", GroupPlace::TopLevel, Vec::new());
            let id = *group.id();
            let joined = members
                .iter()
                .map(|member| stored_membership(*member, id))
                .chain(
                    elsewhere
                        .iter()
                        .map(|member| stored_membership(*member, GroupId::new())),
                );
            Self {
                id,
                ports: ListMembersPorts {
                    group_store: Arc::new(FakeGroupStore::holding(tenant, [group])),
                    membership_store: Arc::new(FakeGroupMembershipStore::holding(tenant, joined)),
                    ..ListMembersPorts::fakes()
                },
            }
        }

        fn list_page(self, page: PageRequest) -> Result<Page<MemberView>, AppError> {
            let request = ListMembersRequest {
                group_id: self.id,
                page,
            };
            block_on(ListMembersUseCase::new(self.ports).execute(&test_ctx(), request))
        }

        fn list(self) -> Result<Page<MemberView>, AppError> {
            self.list_page(PageRequest::default())
        }

        /// Every member, read `limit` at a time from the first page to the
        /// last, and how many pages that took.
        fn walk(self, limit: u32) -> (Vec<PrincipalRef>, usize) {
            let uc = ListMembersUseCase::new(self.ports);
            let mut page = Some(PageRequest::first(Limit::new(limit).unwrap()));
            let (mut seen, mut pages) = (Vec::new(), 0);
            while let Some(request) = page.take() {
                let ask = ListMembersRequest {
                    group_id: self.id,
                    page: request.clone(),
                };
                let answer = block_on(uc.execute(&test_ctx(), ask)).unwrap();
                page = request.following(&answer);
                seen.extend(answer.items.iter().map(|member| member.principal));
                pages += 1;
            }
            (seen, pages)
        }
    }

    fn users(count: usize) -> Vec<PrincipalRef> {
        (0..count)
            .map(|_| PrincipalRef::User(UserId::new()))
            .collect()
    }

    /// Nobody has joined "Partners". Nobody is listed.
    #[test]
    fn a_group_nobody_has_joined_lists_nobody() {
        let members = Partners::with(&[], &[]).list().unwrap();

        assert!(members.is_empty() && !members.has_next());
    }

    /// Ann lists the members of a group the tenant does not have. It is not
    /// found, rather than empty.
    #[test]
    fn an_unknown_group_is_not_found() {
        let uc = ListMembersUseCase::new(ListMembersPorts::fakes());
        let request = ListMembersRequest {
            group_id: GroupId::new(),
            page: PageRequest::default(),
        };

        let result = block_on(uc.execute(&test_ctx(), request));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Bob and the partner app Acme Sync are in "Partners". Both are listed,
    /// the app beside the person, so nothing holds the tier's permissions
    /// without showing here.
    #[test]
    fn a_machine_member_is_listed_beside_the_people() {
        let app = PrincipalRef::Consumer(ConsumerId::new());

        let members = Partners::with(&[PrincipalRef::User(UserId::new()), app], &[])
            .list()
            .unwrap();

        assert_eq!(members.items.len(), 2);
        assert!(members.items.iter().any(|member| member.principal == app));
    }

    /// Bob is in another group only. "Partners" does not list him.
    #[test]
    fn members_of_another_group_are_not_listed() {
        let members = Partners::with(&[], &[PrincipalRef::User(UserId::new())])
            .list()
            .unwrap();

        assert!(members.is_empty());
    }

    /// Bob is in "Partners". He is listed by name.
    #[test]
    fn a_member_is_listed_by_name() {
        let members = Partners::with(&[PrincipalRef::User(UserId::new())], &[])
            .list()
            .unwrap();

        assert_eq!(members.items[0].display_name.as_deref(), Some("test user"));
    }

    /// Bob's account was deleted, but his membership of "Partners" is still
    /// on the record. He is listed without a name rather than left out.
    #[test]
    fn a_member_whose_record_is_gone_is_listed_without_a_name() {
        let mut partners = Partners::with(&users(1), &[]);
        partners.ports.audit_label_resolver = Arc::new(FakeAuditLabelResolver::missing());

        let members = partners.list().unwrap();

        assert_eq!(members.items.len(), 1);
        assert!(members.items[0].display_name.is_none());
    }

    /// "Partners" has five members and Ann reads them two at a time. Three
    /// pages hold every member exactly once.
    #[test]
    fn members_are_listed_a_page_at_a_time() {
        let all = users(5);

        let (mut seen, pages) = Partners::with(&all, &[]).walk(2);

        seen.sort_by_key(PrincipalRef::id);
        let mut expected = all.clone();
        expected.sort_by_key(PrincipalRef::id);
        assert_eq!((seen, pages), (expected, 3));
    }

    /// Listing Partners' members is forbidden without role view permission.
    #[test]
    fn a_caller_who_may_not_view_roles_is_refused() {
        let mut partners = Partners::with(&users(1), &[]);
        partners.ports.tenant_authorities = Arc::new(FakeTenantAuthorities::holding(&[]));

        let result = partners.list();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list group members.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let mut partners = Partners::with(&[], &[]);
        partners.ports.tenant_authorities =
            Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = partners.list();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

//! List users: a page of the tenant's users, filtered and ordered, for
//! someone who may view them.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
use ianua_domain::domains::authorization::role::Role;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::account::user_status::UserStatus;
use ianua_domain::domains::identity::attribute::SchemaControlCheck;
use ianua_domain::domains::identity::invitations::invitation::Invitation;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::types::{PrincipalRef, RoleId, UserId};
use time::OffsetDateTime;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::listing::{Page, PageRequest};
use crate::ports::authorization::RoleStore;
use crate::ports::identity::{
    InvitationFilter, InvitationState, InvitationStore, UserAttributeStore, UserFilter,
    UserOrdering, UserStore,
};
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::identity::users::records::query::{
    ListOrder, UserCriteria, UserQuery, resolved_query,
};

/// One user in a listing.
pub struct ListedUser {
    /// The stored account accompanied by its grants and invitation state.
    pub user: User<ResolvedTenant>,
    /// The roles assigned to the user directly.
    pub roles: Vec<Role<ResolvedTenant>>,
    /// The open invitation of a user who has not accepted yet.
    pub invitation: Option<OpenInvitation>,
}

/// An invitation that has been sent and not yet used.
pub struct OpenInvitation {
    /// Whether its link still works.
    pub state: InvitationState,
    /// The role accepting it grants, or `None` when that role was since
    /// deleted and accepting would grant nothing.
    pub role: Option<Role<ResolvedTenant>>,
}

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Queries users.
    pub user_store: Arc<dyn UserStore>,
    /// Which users have an open invitation, and whether it has expired.
    pub invitation_store: Arc<dyn InvitationStore>,
    /// The roles users hold and invitations grant.
    pub role_store: Arc<dyn RoleStore>,
    /// The tenant's declared attributes, which filters and orders are
    /// checked against.
    pub attribute_store: Arc<dyn UserAttributeStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which users a listing returns, in what order, and which page of them.
pub struct ListRequest {
    /// Narrows the users returned.
    pub criteria: UserCriteria,
    /// Keeps only users whose invitation is in this state.
    pub invitation: Option<InvitationState>,
    /// The order to return them in.
    pub order: ListOrder,
    /// The page to return.
    pub page: PageRequest,
}

/// Lists the users of the caller's tenant.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }

    /// The filter and order for `query`, for a caller who may view users,
    /// with the clearance they hold.
    async fn viewed_query(
        &self,
        ctx: &CallerContext,
        query: UserQuery,
    ) -> Result<(UserFilter, UserOrdering), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Users(UserAction::View))
            .map_err(AppError::from_domain)?;
        let clearance = SchemaControlCheck::clearance(&authority);
        resolved_query(
            self.ports.attribute_store.as_ref(),
            &ctx.tenant(),
            query,
            clearance,
        )
        .await
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = ListRequest;
    type Output = Result<Page<ListedUser>, AppError>;

    /// The page of users `request` asks for.
    ///
    /// Custom attributes are filtered and ordered only as far as the caller's
    /// own clearance reaches, worked out from what they hold. `invitation`
    /// narrows the selection before paging, evaluated at the same instant
    /// as the invitation details returned for that page.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view users, or names
    ///   a sensitive attribute they may not see.
    /// - `AppError::Domain` when a named attribute cannot be filtered or
    ///   ordered by as asked.
    /// - `AppError::Domain` when the page's cursor was made for another
    ///   order.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: ListRequest,
    ) -> Result<Page<ListedUser>, AppError> {
        let ListRequest {
            criteria,
            invitation,
            order,
            page,
        } = request;
        let tenant = ctx.tenant();
        let query = UserQuery { criteria, order };
        let (filter, ordering) = self.viewed_query(ctx, query).await?;
        let now = clock::now();
        let filter = UserFilter {
            invitation: invitation.map(|state| InvitationFilter { state, at: now }),
            ..filter
        };
        let Page { items, next, limit } = self
            .ports
            .user_store
            .list(&tenant, &filter, &ordering, &page)
            .await
            .map_err(AppError::from_domain)?;
        let items = described(&self.ports, &tenant, items, now).await?;
        Ok(Page { items, next, limit })
    }
}

/// Each user with their roles and, for an invited user, their invitation.
async fn described(
    ports: &ListPorts,
    tenant: &ScopedTenant,
    users: Vec<User<ResolvedTenant>>,
    now: OffsetDateTime,
) -> Result<Vec<ListedUser>, AppError> {
    if users.is_empty() {
        return Ok(Vec::new());
    }
    let pending = pending_for_page(ports.invitation_store.as_ref(), tenant, &users).await?;
    let granted = granted_roles(ports.role_store.as_ref(), tenant, &pending).await?;
    let mut direct = direct_roles(ports.role_store.as_ref(), tenant, &users).await?;
    let by_user: HashMap<UserId, &Invitation<ResolvedTenant>> =
        pending.iter().map(|inv| (*inv.user_id(), inv)).collect();

    let mut listed = Vec::with_capacity(users.len());
    for user in users {
        let roles = direct
            .remove(&PrincipalRef::User(*user.id()))
            .unwrap_or_default();
        let invitation = open_invitation(&user, by_user.get(user.id()).copied(), &granted, now);
        listed.push(ListedUser {
            user,
            roles,
            invitation,
        });
    }
    Ok(listed)
}

/// The current page's direct assignments, resolved in one store read.
async fn direct_roles(
    store: &dyn RoleStore,
    tenant: &ScopedTenant,
    users: &[User<ResolvedTenant>],
) -> Result<HashMap<PrincipalRef, Vec<Role<ResolvedTenant>>>, AppError> {
    let principals: Vec<_> = users
        .iter()
        .map(|user| PrincipalRef::User(*user.id()))
        .collect();
    store
        .find_by_principals(tenant, &principals)
        .await
        .or_internal()
}

/// An invited user's current link state and the role accepting it grants.
/// Users who already joined or whose stored offer closed have no open link.
fn open_invitation(
    user: &User<ResolvedTenant>,
    invitation: Option<&Invitation<ResolvedTenant>>,
    granted: &HashMap<RoleId, Role<ResolvedTenant>>,
    now: OffsetDateTime,
) -> Option<OpenInvitation> {
    if user.status() != UserStatus::Invited {
        return None;
    }
    let invitation = invitation?;
    Some(OpenInvitation {
        state: InvitationState::of(invitation.state(now))?,
        role: granted.get(invitation.role_id()).cloned(),
    })
}

/// The roles the pending invitations grant, read in one query.
async fn granted_roles(
    store: &dyn RoleStore,
    tenant: &ScopedTenant,
    pending: &[Invitation<ResolvedTenant>],
) -> Result<HashMap<RoleId, Role<ResolvedTenant>>, AppError> {
    let ids: Vec<RoleId> = pending.iter().map(|inv| *inv.role_id()).collect();
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let roles = store.find_by_ids(tenant, &ids).await.or_internal()?;
    Ok(roles.into_iter().map(|role| (*role.id(), role)).collect())
}

/// Only the current page's invited users need invitation details.
async fn pending_for_page(
    store: &dyn InvitationStore,
    tenant: &ScopedTenant,
    users: &[User<ResolvedTenant>],
) -> Result<Vec<Invitation<ResolvedTenant>>, AppError> {
    let ids: Vec<_> = users
        .iter()
        .filter(|user| user.status() == UserStatus::Invited)
        .map(|user| *user.id())
        .collect();
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    store
        .latest_pending_for_users(tenant, &ids)
        .await
        .or_internal()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::attribute::{
        AttributeKey, AttributeNamespace, AttributeOperator,
    };
    use ianua_domain::domains::identity::invitations::offer::OfferState;

    use super::*;
    use crate::listing::{Limit, Sort, SortOrder};
    use crate::ports::authorization::RoleAssignmentStore as _;
    use crate::ports::identity::{TimeSpan, UserSortField};
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        FakeRoleAssignmentStore, FakeRoleStore, RoleHolders, stored_assignment, stored_role,
    };
    use crate::test_support::identity::{
        FakeInvitationStore, FakeUserStore, InvitationSeed, stored_user, user_named,
    };
    use crate::test_support::{block_on, test_ctx};
    use crate::use_cases::identity::users::AttributeCondition;

    fn everyone() -> ListRequest {
        ListRequest {
            criteria: UserCriteria::default(),
            invitation: None,
            order: ListOrder::default(),
            page: PageRequest::first(Limit::new(100).unwrap()),
        }
    }

    fn by_email() -> ListOrder {
        ListOrder::Column(SortOrder::single(Sort::ascending(UserSortField::Email)))
    }

    fn users_at(emails: &[&str]) -> Arc<FakeUserStore> {
        let users = Arc::new(FakeUserStore::empty());
        for email in emails {
            users.add(stored_user(UserId::new(), email, UserStatus::Active));
        }
        users
    }

    fn listing(users: Arc<FakeUserStore>) -> ListUseCase {
        ListUseCase::new(ListPorts {
            user_store: users,
            ..ListPorts::fakes()
        })
    }

    fn emails_of(page: &Page<ListedUser>) -> Vec<&str> {
        page.items.iter().map(|u| u.user.email().as_str()).collect()
    }

    /// Ann lists the tenant's two users and sees both.
    #[test]
    fn every_user_is_listed() {
        let use_case = listing(users_at(&["alice@acme.com", "bob@acme.com"]));

        let page = block_on(use_case.execute(&test_ctx(), everyone())).unwrap();

        assert_eq!(page.items.len(), 2);
        assert!(!page.has_next());
    }

    /// Ann lists only active users. The one still invited is left out.
    #[test]
    fn a_listing_narrows_by_status() {
        let users = users_at(&["active@acme.com"]);
        users.add(stored_user(
            UserId::new(),
            "invited@acme.com",
            UserStatus::Invited,
        ));
        let request = ListRequest {
            criteria: UserCriteria {
                status: Some(UserStatus::Active),
                ..UserCriteria::default()
            },
            ..everyone()
        };

        let page = block_on(listing(users).execute(&test_ctx(), request)).unwrap();

        assert_eq!(emails_of(&page), ["active@acme.com"]);
    }

    /// Ann lists the users whose address contains "acme". Bob at Globex is
    /// left out.
    #[test]
    fn a_listing_narrows_by_address() {
        let users = users_at(&["alice@acme.com", "bob@globex.com"]);
        let request = ListRequest {
            criteria: UserCriteria {
                email_contains: Some("acme".to_owned()),
                ..UserCriteria::default()
            },
            ..everyone()
        };

        let page = block_on(listing(users).execute(&test_ctx(), request)).unwrap();

        assert_eq!(emails_of(&page), ["alice@acme.com"]);
    }

    /// Ann looks for "chen", whatever its case. Wei Chen is listed, and Bob
    /// is left out.
    #[test]
    fn a_listing_narrows_by_name() {
        let users = Arc::new(FakeUserStore::empty());
        users.add(user_named(UserId::new(), "wei@acme.com", "Wei Chen"));
        users.add(user_named(UserId::new(), "bob@acme.com", "Bob Stone"));
        let request = ListRequest {
            criteria: UserCriteria {
                name_contains: Some("CHEN".to_owned()),
                ..UserCriteria::default()
            },
            ..everyone()
        };

        let page = block_on(listing(users).execute(&test_ctx(), request)).unwrap();

        assert_eq!(emails_of(&page), ["wei@acme.com"]);
    }

    /// Ann lists the users created since an hour ago, and then those
    /// created from tomorrow. Alice, created just now, is in the first and
    /// not the second.
    #[test]
    fn a_listing_narrows_by_when_users_were_created() {
        let now = ianua_domain::shared::clock::now();
        let created_in = |span: TimeSpan| ListRequest {
            criteria: UserCriteria {
                created: span,
                ..UserCriteria::default()
            },
            ..everyone()
        };
        let since_an_hour_ago = TimeSpan {
            from: Some(now - time::Duration::hours(1)),
            until: None,
        };
        let from_tomorrow = TimeSpan {
            from: Some(now + time::Duration::days(1)),
            until: None,
        };
        let use_case = listing(users_at(&["alice@acme.com"]));

        let recent = block_on(use_case.execute(&test_ctx(), created_in(since_an_hour_ago)));
        let later = block_on(use_case.execute(&test_ctx(), created_in(from_tomorrow)));

        assert_eq!(emails_of(&recent.unwrap()), ["alice@acme.com"]);
        assert!(later.unwrap().items.is_empty());
    }

    /// Ann lists who signed in during the last week. Alice never signed in,
    /// so she falls in no span and is left out.
    #[test]
    fn a_listing_by_last_sign_in_leaves_out_who_never_signed_in() {
        let now = ianua_domain::shared::clock::now();
        let request = ListRequest {
            criteria: UserCriteria {
                last_login: TimeSpan {
                    from: Some(now - time::Duration::days(7)),
                    until: None,
                },
                ..UserCriteria::default()
            },
            ..everyone()
        };

        let use_case = listing(users_at(&["alice@acme.com"]));

        let page = block_on(use_case.execute(&test_ctx(), request)).unwrap();

        assert!(page.items.is_empty());
    }

    /// Ann reads five users two at a time by address. The second page holds
    /// the third and fourth, and points on to the fifth.
    #[test]
    fn a_listing_is_paged() {
        let use_case = listing(users_at(&[
            "a@acme.com",
            "b@acme.com",
            "c@acme.com",
            "d@acme.com",
            "e@acme.com",
        ]));
        let two = PageRequest::first(Limit::new(2).unwrap());
        let ask = |page: PageRequest| ListRequest {
            order: by_email(),
            page,
            ..everyone()
        };
        let first = block_on(use_case.execute(&test_ctx(), ask(two.clone()))).unwrap();

        let next = two.following(&first).unwrap();
        let second = block_on(use_case.execute(&test_ctx(), ask(next))).unwrap();

        assert_eq!(emails_of(&second), ["c@acme.com", "d@acme.com"]);
        assert!(second.has_next());
    }

    /// A tenant with no users lists nothing.
    #[test]
    fn an_empty_tenant_lists_nothing() {
        let page = block_on(listing(users_at(&[])).execute(&test_ctx(), everyone())).unwrap();

        assert!(page.items.is_empty() && !page.has_next());
    }

    /// Ann orders the list by address. It comes back alphabetical.
    #[test]
    fn a_listing_is_ordered_by_address() {
        let users = users_at(&["carol@acme.com", "alice@acme.com", "bob@acme.com"]);
        let request = ListRequest {
            order: by_email(),
            ..everyone()
        };

        let page = block_on(listing(users).execute(&test_ctx(), request)).unwrap();

        assert_eq!(
            emails_of(&page),
            ["alice@acme.com", "bob@acme.com", "carol@acme.com"]
        );
    }

    /// Two invitees, one whose link still works and one whose link runs out
    /// at the moment the list is read, and a user nobody invited.
    struct Invitees {
        use_case: ListUseCase,
        closes_at: OffsetDateTime,
    }

    fn invitees() -> Invitees {
        let closes_at = clock::now();
        let invitations = Arc::new(FakeInvitationStore::empty());
        let users = Arc::new(FakeUserStore::empty().reading_invitations(invitations.clone()));
        let open = UserId::new();
        let closing = UserId::new();
        add_invitees(&users, open, closing);
        let tenant = test_ctx().tenant();
        for (user_id, email, expires_at) in [
            (open, "open@acme.com", closes_at + time::Duration::hours(1)),
            (closing, "closing@acme.com", closes_at),
        ] {
            let seed = InvitationSeed::for_user(user_id, email, RoleId::new(), email)
                .expiring_at(expires_at);
            block_on(invitations.save(&tenant, &seed.stored())).unwrap();
        }
        Invitees {
            use_case: ListUseCase::new(ListPorts {
                user_store: users,
                invitation_store: invitations,
                ..ListPorts::fakes()
            }),
            closes_at,
        }
    }

    /// Adds two invited accounts and an active user with no invitation.
    fn add_invitees(users: &FakeUserStore, open: UserId, closing: UserId) {
        users.add(stored_user(open, "open@acme.com", UserStatus::Invited));
        users.add(stored_user(
            closing,
            "closing@acme.com",
            UserStatus::Invited,
        ));
        users.add(stored_user(
            UserId::new(),
            "uninvited@acme.com",
            UserStatus::Active,
        ));
    }

    fn emails_in(invitees: &Invitees, state: InvitationState) -> Vec<String> {
        let _clock = clock::freeze(invitees.closes_at);
        let request = ListRequest {
            invitation: Some(state),
            order: by_email(),
            ..everyone()
        };
        let page = block_on(invitees.use_case.execute(&test_ctx(), request)).unwrap();
        page.items
            .iter()
            .map(|u| u.user.email().as_str().to_owned())
            .collect()
    }

    /// Ann lists pending invitations. Only the invitee whose link still works
    /// is in it.
    #[test]
    fn pending_lists_only_invitees_whose_window_is_still_open() {
        let invitees = invitees();

        assert_eq!(
            emails_in(&invitees, InvitationState::Pending),
            ["open@acme.com"]
        );
    }

    /// An invitation whose link runs out now no longer works, so it is
    /// listed as expired rather than pending.
    #[test]
    fn expired_lists_invitees_whose_window_closed_at_or_before_now() {
        let invitees = invitees();

        assert_eq!(
            emails_in(&invitees, InvitationState::Expired),
            ["closing@acme.com"]
        );
    }

    /// Ana was invited as a member and has not accepted. She holds no role
    /// yet, so the listing says which role accepting gives her.
    #[test]
    fn an_invited_user_carries_the_role_their_invitation_grants() {
        let ana = UserId::new();
        let member = stored_role("Member", Vec::new(), Vec::new());
        let users = Arc::new(FakeUserStore::empty());
        users.add(stored_user(ana, "ana@acme.com", UserStatus::Invited));
        let invitation =
            InvitationSeed::for_user(ana, "ana@acme.com", *member.id(), "ana").stored();
        let use_case = ListUseCase::new(ListPorts {
            user_store: users,
            invitation_store: Arc::new(FakeInvitationStore::holding(invitation)),
            role_store: Arc::new(FakeRoleStore::holding(test_ctx().tenant_id(), [member])),
            ..ListPorts::fakes()
        });

        let page = block_on(use_case.execute(&test_ctx(), everyone())).unwrap();

        let open = page.items[0].invitation.as_ref().unwrap();
        assert_eq!(open.state, InvitationState::Pending);
        assert_eq!(
            open.role.as_ref().map(|r| r.name().as_str()),
            Some("Member")
        );
    }

    /// A page reads only its invitees' pending invitations, even when the tenant
    /// has more invitees than fit on the page, preserving the requested order.
    #[test]
    fn invitation_enrichment_reads_only_the_current_page() {
        let users = Arc::new(FakeUserStore::empty());
        let invitations = Arc::new(FakeInvitationStore::empty());
        let tenant = test_ctx().tenant();
        for email in ["a@acme.com", "b@acme.com", "c@acme.com"] {
            let id = UserId::new();
            users.add(stored_user(id, email, UserStatus::Invited));
            let invitation = InvitationSeed::for_user(id, email, RoleId::new(), email).stored();
            block_on(invitations.save(&tenant, &invitation)).unwrap();
        }
        let uc = ListUseCase::new(ListPorts {
            user_store: users,
            invitation_store: invitations.clone(),
            ..ListPorts::fakes()
        });

        let result = block_on(uc.execute(
            &test_ctx(),
            ListRequest {
                order: by_email(),
                page: PageRequest::first(Limit::new(2).unwrap()),
                ..everyone()
            },
        ))
        .unwrap();

        assert_eq!(emails_of(&result), ["a@acme.com", "b@acme.com"]);
        assert!(result.has_next());
        assert!(result.items.iter().all(|item| item.invitation.is_some()));
        let ids = result.items.iter().map(|item| *item.user.id()).collect();
        assert_eq!(invitations.pending_reads(), vec![Some(ids)]);
    }

    /// All users on one page have their direct roles resolved together rather
    /// than one read per user, including users who hold no role.
    #[test]
    fn direct_role_enrichment_uses_one_read_per_page() {
        let roles = Arc::new(FakeRoleStore::empty());
        let uc = ListUseCase::new(ListPorts {
            user_store: users_at(&["a@acme.com", "b@acme.com", "c@acme.com"]),
            role_store: roles.clone(),
            ..ListPorts::fakes()
        });

        let result = block_on(uc.execute(&test_ctx(), everyone())).unwrap();

        assert_eq!(result.items.len(), 3);
        assert!(result.items.iter().all(|item| item.roles.is_empty()));
        assert_eq!(roles.principal_reads(), 1);
    }

    /// An invitation already marked expired is closed for listing purposes,
    /// while an unanswered pending invitation past its expiry still matches.
    #[test]
    fn an_expired_filter_excludes_invitations_already_closed_by_the_sweep() {
        let uc = expired_invitees();

        let page = block_on(uc.execute(
            &test_ctx(),
            ListRequest {
                invitation: Some(InvitationState::Expired),
                ..everyone()
            },
        ))
        .unwrap();

        assert_eq!(emails_of(&page), ["open@acme.com"]);
    }

    /// One expired invitation is already closed while another still awaits the sweep.
    fn expired_invitees() -> ListUseCase {
        let invitations = Arc::new(FakeInvitationStore::empty());
        let users = Arc::new(FakeUserStore::empty().reading_invitations(invitations.clone()));
        for (email, state, status) in [
            (
                "closed@acme.com",
                OfferState::Expired,
                UserStatus::Deactivated,
            ),
            ("open@acme.com", OfferState::Pending, UserStatus::Invited),
        ] {
            let id = UserId::new();
            users.add(stored_user(id, email, status));
            let invite = InvitationSeed::for_user(id, email, RoleId::new(), email)
                .expiring_at(clock::now() - time::Duration::hours(1))
                .stored_as(state);
            block_on(invitations.save(&test_ctx().tenant(), &invite)).unwrap();
        }
        ListUseCase::new(ListPorts {
            user_store: users,
            invitation_store: invitations,
            ..ListPorts::fakes()
        })
    }

    /// Filtering invitation state happens before paging, so an expired invitee
    /// at the start of the address order neither empties nor shortens a pending page.
    #[test]
    fn invitation_filtering_precedes_page_boundaries() {
        let now = clock::now();
        let uc = paged_invitees(now);
        let _clock = clock::freeze(now);
        let request = |page| ListRequest {
            invitation: Some(InvitationState::Pending),
            order: by_email(),
            page,
            ..everyone()
        };
        let one = PageRequest::first(Limit::new(1).unwrap());

        let first = block_on(uc.execute(&test_ctx(), request(one.clone()))).unwrap();
        let second =
            block_on(uc.execute(&test_ctx(), request(one.following(&first).unwrap()))).unwrap();

        assert_eq!(emails_of(&first), ["b@acme.com"]);
        assert_eq!(emails_of(&second), ["c@acme.com"]);
        assert!(!second.has_next());
    }

    /// The first address has expired while the next two invitations remain usable.
    fn paged_invitees(now: OffsetDateTime) -> ListUseCase {
        let invitations = Arc::new(FakeInvitationStore::empty());
        let users = Arc::new(FakeUserStore::empty().reading_invitations(invitations.clone()));
        for (email, expires) in [
            ("a@acme.com", now),
            ("b@acme.com", now + time::Duration::hours(1)),
            ("c@acme.com", now + time::Duration::hours(1)),
        ] {
            let id = UserId::new();
            users.add(stored_user(id, email, UserStatus::Invited));
            let invite = InvitationSeed::for_user(id, email, RoleId::new(), email)
                .expiring_at(expires)
                .stored();
            block_on(invitations.save(&test_ctx().tenant(), &invite)).unwrap();
        }
        ListUseCase::new(ListPorts {
            user_store: users,
            invitation_store: invitations,
            ..ListPorts::fakes()
        })
    }

    /// A second listing reflects a revoked direct role without mixing the roles
    /// held by another user, and both page sizes resolve their roles in one read.
    #[test]
    fn batched_roles_follow_each_users_current_assignments() {
        let users = users_at(&[]);
        let alice = UserId::new();
        let bob = UserId::new();
        users.add_active_user(alice, "alice@acme.com");
        users.add_active_user(bob, "bob@acme.com");
        let held = held_roles(alice, bob);
        let uc = ListUseCase::new(ListPorts {
            user_store: users,
            role_store: held.roles.clone(),
            ..ListPorts::fakes()
        });
        let request = |limit| ListRequest {
            order: by_email(),
            page: PageRequest::first(Limit::new(limit).unwrap()),
            ..everyone()
        };

        let first = block_on(uc.execute(&test_ctx(), request(2))).unwrap();
        block_on(held.assignments.delete(
            &test_ctx().tenant(),
            &PrincipalRef::User(alice),
            &held.editor,
        ))
        .unwrap();
        let second = block_on(uc.execute(&test_ctx(), request(1))).unwrap();

        assert_eq!(first.items[0].roles[0].id(), &held.editor);
        assert_eq!(first.items[1].roles[0].id(), &held.viewer);
        assert!(second.items[0].roles.is_empty());
        assert_eq!(held.roles.principal_reads(), 2);
    }

    /// The role reader follows the same assignment store that the test later revokes from.
    struct HeldRoles {
        roles: Arc<FakeRoleStore>,
        assignments: Arc<FakeRoleAssignmentStore>,
        editor: RoleId,
        viewer: RoleId,
    }

    /// Alice holds Editor and Bob holds Viewer through distinct direct assignments.
    fn held_roles(alice: UserId, bob: UserId) -> HeldRoles {
        let editor = stored_role("Editor", Vec::new(), Vec::new());
        let viewer = stored_role("Viewer", Vec::new(), Vec::new());
        let editor_id = *editor.id();
        let viewer_id = *viewer.id();
        let assignments = Arc::new(FakeRoleAssignmentStore::holding(
            test_ctx().tenant_id(),
            [
                stored_assignment(PrincipalRef::User(alice), editor_id),
                stored_assignment(PrincipalRef::User(bob), viewer_id),
            ],
        ));
        let roles = Arc::new(
            FakeRoleStore::holding(test_ctx().tenant_id(), [editor, viewer]).reading(RoleHolders {
                assignments: assignments.clone(),
                ..RoleHolders::default()
            }),
        );
        HeldRoles {
            roles,
            assignments,
            editor: editor_id,
            viewer: viewer_id,
        }
    }

    /// A user listing cannot filter by a salary attribute the tenant has
    /// not declared.
    #[test]
    fn a_filter_on_an_undeclared_attribute_is_refused() {
        let request = ListRequest {
            criteria: UserCriteria {
                attributes: vec![AttributeCondition {
                    namespace: AttributeNamespace::User,
                    key: AttributeKey::new("salary").unwrap(),
                    operator: AttributeOperator::Is,
                    values: vec!["100000".to_owned()],
                }],
                ..UserCriteria::default()
            },
            ..everyone()
        };

        let result = block_on(listing(users_at(&["alice@acme.com"])).execute(&test_ctx(), request));

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// A caller without user-viewing rights cannot list tenant accounts.
    #[test]
    fn a_caller_who_may_not_view_users_is_refused() {
        let use_case = ListUseCase::new(ListPorts {
            user_store: users_at(&["alice@acme.com"]),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ListPorts::fakes()
        });

        let result = block_on(use_case.execute(&test_ctx(), everyone()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller cannot list tenant accounts.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = ListUseCase::new(ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ListPorts::fakes()
        });

        let result = block_on(use_case.execute(&test_ctx(), everyone()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

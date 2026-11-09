//! Listing the organization's members, filtered, ordered and paged.

use std::sync::Arc;

use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::organization::members::permission::{MemberAction, OrgPermission};
use ianua_domain::shared::clock;
use ianua_domain::types::{OrgUserId, OrganizationId};

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::identity::InvitationState;
use crate::ports::organization::{
    OrgInvitationStore, OrgUserFilter, OrgUserSortField, OrgUserStore,
};
use crate::use_case::Query;

/// Which members a listing returns, in what order, and which page of them.
pub struct ListOrgUsersRequest {
    /// Narrows the members returned.
    pub filter: OrgUserFilter,
    /// Keeps only members whose invitation is in this state.
    pub invitation: Option<InvitationState>,
    /// The order to return them in.
    pub sort: SortOrder<OrgUserSortField>,
    /// Which page of the ordered members to return.
    pub page: PageRequest,
}

/// The ports [`ListOrgUsersUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListOrgUsersPorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// The organization's members.
    pub org_users: Arc<dyn OrgUserStore>,
    /// The organization's pending invitations.
    pub org_invitations: Arc<dyn OrgInvitationStore>,
}

/// Lists the members of the caller's organization.
pub struct ListOrgUsersUseCase {
    ports: ListOrgUsersPorts,
}

impl ListOrgUsersUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListOrgUsersPorts) -> Self {
        Self { ports }
    }

    /// The members whose open invitation is in `state`.
    async fn invited_in(
        &self,
        organization_id: &OrganizationId,
        state: InvitationState,
    ) -> Result<Vec<OrgUserId>, AppError> {
        let now = clock::now();
        Ok(self
            .ports
            .org_invitations
            .list_pending(organization_id)
            .await
            .or_internal()?
            .into_iter()
            .filter(|invitation| InvitationState::of(invitation.state(now)) == Some(state))
            .map(|invitation| *invitation.org_user_id())
            .collect())
    }

    /// `filter`, narrowed to the members whose invitation is in `state`
    /// when one is asked for.
    async fn narrowed(
        &self,
        organization_id: &OrganizationId,
        filter: OrgUserFilter,
        invitation: Option<InvitationState>,
    ) -> Result<OrgUserFilter, AppError> {
        let Some(state) = invitation else {
            return Ok(filter);
        };
        let invited = self.invited_in(organization_id, state).await?;
        Ok(OrgUserFilter {
            ids: Some(intersection(filter.ids, invited)),
            ..filter
        })
    }
}

impl Query for ListOrgUsersUseCase {
    type Caller = OrgCaller;
    type Input = ListOrgUsersRequest;
    type Output = Result<Page<OrgUser>, AppError>;

    /// One page of the caller's organization's members.
    ///
    /// `invitation` narrows the page to members whose open invitation is in
    /// that state. That state is the invitation's expiry compared with now,
    /// which no member row records, so it becomes a restriction on ids,
    /// kept inside any ids the caller named. The page and its total stay
    /// consistent.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view members.
    /// - `AppError::Internal` when a store fails.
    async fn execute(
        &self,
        caller: &OrgCaller,
        request: ListOrgUsersRequest,
    ) -> Result<Page<OrgUser>, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        actor
            .control()?
            .ensure_may(
                organization.id(),
                OrgPermission::Members(MemberAction::View),
            )
            .map_err(AppError::from_domain)?;
        let filter = self
            .narrowed(organization.id(), request.filter, request.invitation)
            .await?;
        self.ports
            .org_users
            .list_by_org(organization.id(), &filter, &request.sort, &request.page)
            .await
            .map_err(AppError::from_domain)
    }
}

/// The `invited` members, kept to those in `named` when the caller named
/// any.
fn intersection(named: Option<Vec<OrgUserId>>, invited: Vec<OrgUserId>) -> Vec<OrgUserId> {
    let Some(named) = named else {
        return invited;
    };
    invited
        .into_iter()
        .filter(|id| named.contains(id))
        .collect()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
    use ianua_domain::types::TokenHash;

    use super::*;
    use crate::listing::Sort;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        FakeOrgInvitationStore, expired_org_invitation, org_user_store_with,
        pending_org_invitation, test_org_member_at, test_org_user,
    };
    use crate::test_support::{block_on, test_org_caller};

    fn acme() -> OrganizationId {
        test_org_caller().organization_id()
    }

    fn listing(
        actors: FakeOrgActors,
        members: Vec<OrgUser>,
        invitations: FakeOrgInvitationStore,
    ) -> ListOrgUsersUseCase {
        ListOrgUsersUseCase::new(ListOrgUsersPorts {
            org_actors: Arc::new(actors),
            org_users: Arc::new(org_user_store_with(members)),
            org_invitations: Arc::new(invitations),
        })
    }

    fn request(filter: OrgUserFilter, invitation: Option<InvitationState>) -> ListOrgUsersRequest {
        ListOrgUsersRequest {
            filter,
            invitation,
            sort: SortOrder::single(Sort::ascending(OrgUserSortField::Email)),
            page: PageRequest::default(),
        }
    }

    fn emails(page: &Page<OrgUser>) -> Vec<String> {
        page.items
            .iter()
            .map(|member| member.email().as_str().to_owned())
            .collect()
    }

    /// Sam, a plain member, lists Acme's members. Both come back on one
    /// page, and nobody from another organization.
    #[test]
    fn a_member_lists_the_organizations_members() {
        let uc = listing(
            FakeOrgActors::in_role(OrgRole::Member),
            vec![
                test_org_user(acme(), "a@acme.test", OrgRole::Member),
                test_org_user(acme(), "b@acme.test", OrgRole::Owner),
                test_org_user(OrganizationId::new(), "c@other.test", OrgRole::Member),
            ],
            FakeOrgInvitationStore::empty(),
        );

        let page =
            block_on(uc.execute(&test_org_caller(), request(OrgUserFilter::all(), None))).unwrap();

        assert_eq!(page.items.len(), 2);
        assert_eq!(emails(&page), ["a@acme.test", "b@acme.test"]);
    }

    /// A listing filtered to locked members holds only the locked one.
    #[test]
    fn filters_by_status() {
        let uc = listing(
            FakeOrgActors::in_role(OrgRole::Owner),
            vec![
                test_org_member_at(acme(), "active@acme.test", OrgUserStatus::Active),
                test_org_member_at(acme(), "locked@acme.test", OrgUserStatus::Locked),
            ],
            FakeOrgInvitationStore::empty(),
        );
        let filter = OrgUserFilter {
            status: Some(OrgUserStatus::Locked),
            ..OrgUserFilter::all()
        };

        let page = block_on(uc.execute(&test_org_caller(), request(filter, None))).unwrap();

        assert_eq!(emails(&page), ["locked@acme.test"]);
    }

    /// A listing ordered by address comes back in that order.
    #[test]
    fn sorts_by_email_ascending() {
        let uc = listing(
            FakeOrgActors::in_role(OrgRole::Owner),
            vec![
                test_org_user(acme(), "charlie@acme.test", OrgRole::Member),
                test_org_user(acme(), "alice@acme.test", OrgRole::Member),
                test_org_user(acme(), "bob@acme.test", OrgRole::Member),
            ],
            FakeOrgInvitationStore::empty(),
        );

        let page =
            block_on(uc.execute(&test_org_caller(), request(OrgUserFilter::all(), None))).unwrap();

        assert_eq!(
            emails(&page),
            ["alice@acme.test", "bob@acme.test", "charlie@acme.test"]
        );
    }

    /// Three members: one whose invitation is still open, one whose link
    /// ran out, and one never invited.
    fn invitees() -> (Vec<OrgUser>, FakeOrgInvitationStore) {
        let open = test_org_user(acme(), "open@acme.test", OrgRole::Member);
        let lapsed = test_org_user(acme(), "lapsed@acme.test", OrgRole::Member);
        let uninvited = test_org_user(acme(), "uninvited@acme.test", OrgRole::Member);
        let invitations = FakeOrgInvitationStore::holding([
            pending_org_invitation(
                acme(),
                *open.id(),
                "open@acme.test",
                TokenHash::from_stored("open".to_owned()),
            ),
            expired_org_invitation(
                acme(),
                *lapsed.id(),
                "lapsed@acme.test",
                TokenHash::from_stored("lapsed".to_owned()),
            ),
        ]);
        (vec![open, lapsed, uninvited], invitations)
    }

    fn invited_emails(state: InvitationState, filter: OrgUserFilter) -> Vec<String> {
        let (members, invitations) = invitees();
        let uc = listing(FakeOrgActors::in_role(OrgRole::Owner), members, invitations);
        let page = block_on(uc.execute(&test_org_caller(), request(filter, Some(state)))).unwrap();
        emails(&page)
    }

    /// Asking for pending invitations lists only the invitee whose link
    /// still works.
    #[test]
    fn pending_lists_only_invitees_whose_window_is_still_open() {
        assert_eq!(
            invited_emails(InvitationState::Pending, OrgUserFilter::all()),
            ["open@acme.test"]
        );
    }

    /// Asking for expired invitations lists only the invitee whose link
    /// ran out.
    #[test]
    fn expired_lists_invitees_whose_window_closed() {
        assert_eq!(
            invited_emails(InvitationState::Expired, OrgUserFilter::all()),
            ["lapsed@acme.test"]
        );
    }

    /// A caller who named the members to list and asks for pending
    /// invitations gets only those named. The invitation filter narrows
    /// their choice rather than replacing it.
    #[test]
    fn the_invitation_filter_keeps_inside_the_ids_named() {
        let filter = OrgUserFilter {
            ids: Some(vec![OrgUserId::new()]),
            ..OrgUserFilter::all()
        };

        assert!(invited_emails(InvitationState::Pending, filter).is_empty());
    }

    /// A signed-out caller must authenticate even when the member list is empty.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let uc = listing(
            FakeOrgActors::refusing(Refusal::SignedOut),
            Vec::new(),
            FakeOrgInvitationStore::empty(),
        );

        let result = block_on(uc.execute(&test_org_caller(), request(OrgUserFilter::all(), None)));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents listing members.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let uc = listing(
            FakeOrgActors::refusing(Refusal::Forbidden),
            Vec::new(),
            FakeOrgInvitationStore::empty(),
        );

        let result = block_on(uc.execute(&test_org_caller(), request(OrgUserFilter::all(), None)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An owner's key without the member-view scope cannot list members.
    #[test]
    fn a_key_without_the_view_scope_is_refused() {
        let uc = listing(
            FakeOrgActors::through_key(OrgRole::Owner, Vec::new()),
            Vec::new(),
            FakeOrgInvitationStore::empty(),
        );

        let result = block_on(uc.execute(&test_org_caller(), request(OrgUserFilter::all(), None)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}

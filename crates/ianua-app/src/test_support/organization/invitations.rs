//! Organization invitations as tests need them, and the in-memory
//! invitation store.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::identity::account::address::AddressStanding;
use ianua_domain::domains::identity::account::vouching::Vouching;
use ianua_domain::domains::identity::invitations::offer::OfferState;
use ianua_domain::domains::identity::invitations::status::InvitationStatus;
use ianua_domain::domains::organization::members::invitation::{OrgInvitation, OrgInvitationRow};
use ianua_domain::domains::organization::members::membership::OrgRole;
use ianua_domain::domains::organization::members::org_user::{OrgPassword, OrgUser, OrgUserRow};
use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
use ianua_domain::shared::clock;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    CredentialChange, DisplayName, Email, Joining, OrgInvitationId, OrgUserId, OrganizationId,
    Preference, TokenHash,
};
use time::{Duration, OffsetDateTime};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::organization::{OrgInvitationStore, OrgInvitationSweepSortField};
use crate::test_support::Fake;

/// A pending invitation for the member `org_user_id` at `email`, sent a
/// moment ago and good for a week.
#[must_use]
pub fn pending_org_invitation(
    organization_id: OrganizationId,
    org_user_id: OrgUserId,
    email: &str,
    token_hash: TokenHash,
) -> OrgInvitation {
    let now = clock::now();
    let invited = Invited {
        organization_id,
        org_user_id,
        email,
        invited_by: OrgUserId::new(),
        token_hash,
    };
    invitation_between(invited, now, now + Duration::days(7))
}

/// A pending invitation like [`pending_org_invitation`], sent a week ago,
/// whose link ran out a second ago.
#[must_use]
pub fn expired_org_invitation(
    organization_id: OrganizationId,
    org_user_id: OrgUserId,
    email: &str,
    token_hash: TokenHash,
) -> OrgInvitation {
    let now = clock::now();
    let invited = Invited {
        organization_id,
        org_user_id,
        email,
        invited_by: OrgUserId::new(),
        token_hash,
    };
    invitation_between(invited, now - Duration::days(7), now - Duration::seconds(1))
}

/// A pending invitation `inviter` sent `invitee` a moment ago, good for a
/// week, whose link carries `token_hash`.
#[must_use]
pub fn org_invitation_from(
    inviter: &OrgUser,
    invitee: &OrgUser,
    token_hash: TokenHash,
) -> OrgInvitation {
    let now = clock::now();
    let invited = Invited {
        organization_id: *invitee.organization_id(),
        org_user_id: *invitee.id(),
        email: invitee.email().as_str(),
        invited_by: *inviter.id(),
        token_hash,
    };
    invitation_between(invited, now, now + Duration::days(7))
}

/// A member of `organization_id` at `email` in `role` whom an owner invited
/// and who has not accepted yet: no password, address unverified.
#[must_use]
pub fn invited_org_user(organization_id: OrganizationId, email: &str, role: OrgRole) -> OrgUser {
    waiting_member(organization_id, email, role, OrgUserStatus::Invited)
}

/// A member of `organization_id` at `email` who signed up and has not yet
/// confirmed their address.
#[must_use]
pub fn unconfirmed_org_user(organization_id: OrganizationId, email: &str) -> OrgUser {
    waiting_member(
        organization_id,
        email,
        OrgRole::Member,
        OrgUserStatus::PendingVerification,
    )
}

fn waiting_member(
    organization_id: OrganizationId,
    email: &str,
    role: OrgRole,
    status: OrgUserStatus,
) -> OrgUser {
    let now = clock::now();
    OrgUser::reconstitute(OrgUserRow {
        id: OrgUserId::new(),
        organization_id,
        email: Email::new(email).expect("a valid address"),
        display_name: DisplayName::new("Invited", &DomainLimits::default().display_name)
            .expect("a valid name"),
        password_hash: OrgPassword::NotSet,
        status,
        role,
        email_standing: AddressStanding::Unverified,
        locale: Preference::Inherited,
        timezone: Preference::Inherited,
        created_at: now,
        updated_at: now,
        joining: Joining::NotYet,
        credentials_changed_at: CredentialChange::Never,
        vouching: Vouching::Absent,
    })
    .expect("a member still waiting to join is a consistent row")
}

/// Who a test invitation goes to, who sent it, and the hash its link
/// carries.
struct Invited<'a> {
    organization_id: OrganizationId,
    org_user_id: OrgUserId,
    email: &'a str,
    invited_by: OrgUserId,
    token_hash: TokenHash,
}

fn invitation_between(
    invited: Invited<'_>,
    sent_at: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> OrgInvitation {
    OrgInvitation::reconstitute(OrgInvitationRow {
        id: OrgInvitationId::new(),
        organization_id: invited.organization_id,
        org_user_id: invited.org_user_id,
        email: Email::new(invited.email).expect("a valid address"),
        invited_by: invited.invited_by,
        token_hash: invited.token_hash,
        state: OfferState::Pending,
        message: None,
        expires_at,
        created_at: sent_at,
    })
    .expect("a pending invitation is a consistent row")
}

/// The stored fields of `invitation`.
fn invitation_row(invitation: &OrgInvitation) -> Result<OrgInvitationRow, DomainError> {
    Ok(OrgInvitationRow {
        id: *invitation.id(),
        organization_id: *invitation.organization_id(),
        org_user_id: *invitation.org_user_id(),
        email: invitation.email().clone(),
        invited_by: *invitation.invited_by(),
        token_hash: invitation.token_hash().clone(),
        state: OfferState::from_stored(invitation.status(), invitation.accepted_at())?,
        message: invitation.message().cloned(),
        expires_at: invitation.expires_at(),
        created_at: invitation.created_at(),
    })
}

/// A copy of `invitation`, read back the way storage reads it.
fn copy_invitation(invitation: &OrgInvitation) -> Result<OrgInvitation, DomainError> {
    OrgInvitation::reconstitute(invitation_row(invitation)?)
}

/// In-memory invitation store that keeps every invitation it is handed.
#[derive(Default)]
pub struct FakeOrgInvitationStore {
    invitations: Mutex<Vec<OrgInvitation>>,
    lapsed_reads: Mutex<Vec<usize>>,
    refused_saves: Mutex<Vec<OrgInvitationId>>,
}

impl FakeOrgInvitationStore {
    /// Makes writes to this invitation fail without changing the held row.
    pub fn refuse_save(&self, id: OrgInvitationId) {
        self.refused_saves.lock().unwrap().push(id);
    }

    /// The number of invitations returned by each expiry-sweep read.
    #[must_use]
    pub fn lapsed_reads(&self) -> Vec<usize> {
        self.lapsed_reads.lock().unwrap().clone()
    }

    /// A store holding no invitation.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store already holding `invitations`.
    #[must_use]
    pub fn holding(invitations: impl IntoIterator<Item = OrgInvitation>) -> Self {
        let store = Self::default();
        store.invitations.lock().unwrap().extend(invitations);
        store
    }

    /// How many invitations are held.
    #[must_use]
    pub fn count(&self) -> usize {
        self.invitations.lock().unwrap().len()
    }

    fn matching(
        &self,
        organization_id: &OrganizationId,
        keep: impl Fn(&OrgInvitation) -> bool,
    ) -> Result<Vec<OrgInvitation>, DomainError> {
        self.invitations
            .lock()
            .unwrap()
            .iter()
            .filter(|held| held.organization_id() == organization_id && keep(held))
            .map(copy_invitation)
            .collect()
    }

    fn first(
        &self,
        organization_id: &OrganizationId,
        matches: impl Fn(&OrgInvitation) -> bool,
    ) -> Result<Option<OrgInvitation>, DomainError> {
        Ok(self.matching(organization_id, matches)?.into_iter().next())
    }
}

/// Whether `invitation` still reads as pending in storage. Status alone, as
/// the SQL behind the store reads it: one that ran out of time keeps
/// `Pending` until something lapses it, which is what lets a resend reach it.
fn stored_as_pending(invitation: &OrgInvitation) -> bool {
    invitation.status() == InvitationStatus::Pending
}

#[async_trait]
impl OrgInvitationStore for FakeOrgInvitationStore {
    async fn find_by_token_hash(
        &self,
        organization_id: &OrganizationId,
        hash: &TokenHash,
    ) -> Result<Option<OrgInvitation>, DomainError> {
        self.first(organization_id, |held| held.token_hash() == hash)
    }

    async fn find_pending_by_email(
        &self,
        organization_id: &OrganizationId,
        email: &Email,
    ) -> Result<Option<OrgInvitation>, DomainError> {
        let now = clock::now();
        self.first(organization_id, |held| {
            held.email() == email && held.is_pending(now)
        })
    }

    async fn find_pending_by_org_user(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
    ) -> Result<Option<OrgInvitation>, DomainError> {
        self.first(organization_id, |held| {
            held.org_user_id() == org_user_id && stored_as_pending(held)
        })
    }

    async fn list_pending(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Vec<OrgInvitation>, DomainError> {
        self.matching(organization_id, stored_as_pending)
    }

    async fn list_lapsed(
        &self,
        now: OffsetDateTime,
        request: &PageRequest,
    ) -> Result<Page<OrgInvitation>, DomainError> {
        let lapsed: Vec<_> = self
            .invitations
            .lock()
            .unwrap()
            .iter()
            .filter(|held| stored_as_pending(held) && held.expires_at() <= now)
            .map(copy_invitation)
            .collect::<Result<_, _>>()?;
        let sort = SortOrder::<OrgInvitationSweepSortField>::default();
        let page = request.keyset(&sort)?.cut(lapsed);
        self.lapsed_reads.lock().unwrap().push(page.items.len());
        Ok(page)
    }

    async fn save(&self, invitation: &OrgInvitation) -> Result<(), DomainError> {
        if self.refused_saves.lock().unwrap().contains(invitation.id()) {
            return Err(DomainError::infra_msg("invitation writes unavailable"));
        }
        let copy = copy_invitation(invitation)?;
        let mut invitations = self.invitations.lock().unwrap();
        match invitations
            .iter_mut()
            .find(|held| held.id() == invitation.id())
        {
            Some(held) => *held = copy,
            None => invitations.push(copy),
        }
        Ok(())
    }
}

impl Fake for Arc<dyn OrgInvitationStore> {
    fn fake() -> Self {
        Arc::new(FakeOrgInvitationStore::empty())
    }
}

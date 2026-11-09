//! An in-memory invitation store.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::identity::invitations::invitation::{Invitation, InvitationRow};
use ianua_domain::domains::identity::invitations::offer::OfferState;
use ianua_domain::domains::identity::invitations::status::InvitationStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ActorRef, Email, InvitationId, RoleId, TenantId, TokenHash, UserId};
use time::OffsetDateTime;

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::identity::{
    InvitationFilter, InvitationState, InvitationStore, InvitationSweepSortField,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::identity::held::{TenantRows, seeded_tenant};
use crate::test_support::identity::tokens::hash_of_link;

/// In-memory invitation store: keeps every invitation saved under its
/// tenant and finds them by link, address and invitee in that tenant only.
#[derive(Default)]
pub struct FakeInvitationStore {
    invitations: TenantRows<Invitation<ResolvedTenant>>,
    pending_reads: Mutex<Vec<Option<Vec<UserId>>>>,
    lapsed_reads: Mutex<Vec<usize>>,
}

impl TenantScoped for FakeInvitationStore {}

impl FakeInvitationStore {
    /// The number of invitations returned by each expiry-sweep read.
    #[must_use]
    pub fn lapsed_reads(&self) -> Vec<usize> {
        self.lapsed_reads.lock().unwrap().clone()
    }

    /// Whether an open invitation of this tenant's user matches the requested state.
    pub(crate) fn matches_state(
        &self,
        tenant: &TenantId,
        user: &UserId,
        filter: InvitationFilter,
    ) -> bool {
        self.invitations
            .find(
                tenant,
                |invitation| {
                    invitation.user_id() == user
                        && is_open(invitation)
                        && InvitationState::of(invitation.state(filter.at)) == Some(filter.state)
                },
                |_| (),
            )
            .is_some()
    }

    /// The users requested by each pending read, or no restriction for a tenant-wide read.
    #[must_use]
    pub fn pending_reads(&self) -> Vec<Option<Vec<UserId>>> {
        self.pending_reads.lock().unwrap().clone()
    }

    /// Creates an empty store.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `invitation` for the tenant [`test_ctx`] carries.
    ///
    /// [`test_ctx`]: crate::test_support::test_ctx
    #[must_use]
    pub fn holding(invitation: Invitation<ResolvedTenant>) -> Self {
        let store = Self::empty();
        store.invitations.insert(seeded_tenant(), invitation);
        store
    }

    /// Returns the number of stored invitations, across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.invitations.count()
    }
}

#[async_trait]
impl InvitationStore for FakeInvitationStore {
    async fn latest_pending_for_users(
        &self,
        tenant_id: &ScopedTenant,
        users: &[UserId],
    ) -> Result<Vec<Invitation<ResolvedTenant>>, DomainError> {
        self.pending_reads
            .lock()
            .unwrap()
            .push(Some(users.to_vec()));
        let mut found: Vec<_> = self
            .invitations
            .collect(
                tenant_id,
                |invitation| users.contains(invitation.user_id()) && is_open(invitation),
                copy_invitation,
            )
            .into_iter()
            .collect::<Result<_, _>>()?;
        found.sort_by_key(|invitation| {
            (
                *invitation.user_id().as_uuid(),
                std::cmp::Reverse((invitation.created_at(), *invitation.id().as_uuid())),
            )
        });
        found.dedup_by_key(|invitation| *invitation.user_id());
        Ok(found)
    }

    async fn find_by_token_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<Invitation<ResolvedTenant>>, DomainError> {
        let pick = |invitation: &Invitation<ResolvedTenant>| invitation.token_hash() == token_hash;
        self.invitations
            .find(tenant_id, pick, copy_invitation)
            .transpose()
    }

    async fn find_pending_by_email(
        &self,
        tenant_id: &ScopedTenant,
        email: &Email,
    ) -> Result<Option<Invitation<ResolvedTenant>>, DomainError> {
        let now = clock::now();
        let pick = |invitation: &Invitation<ResolvedTenant>| {
            invitation.email() == email && invitation.is_pending(now)
        };
        self.invitations
            .find(tenant_id, pick, copy_invitation)
            .transpose()
    }

    async fn find_pending_by_user_id(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<Invitation<ResolvedTenant>>, DomainError> {
        let pick = |invitation: &Invitation<ResolvedTenant>| {
            invitation.user_id() == user_id && is_open(invitation)
        };
        self.invitations
            .find(tenant_id, pick, copy_invitation)
            .transpose()
    }

    async fn list_by_user_id(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<Invitation<ResolvedTenant>>, DomainError> {
        let theirs = |invitation: &Invitation<ResolvedTenant>| invitation.user_id() == user_id;
        let mut held: Vec<_> = self.invitations.collect(tenant_id, theirs, |invitation| {
            (invitation.created_at(), copy_invitation(invitation))
        });
        held.sort_by_key(|(created_at, _)| std::cmp::Reverse(*created_at));
        held.into_iter().map(|(_, invitation)| invitation).collect()
    }

    async fn list_pending(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<Invitation<ResolvedTenant>>, DomainError> {
        self.pending_reads.lock().unwrap().push(None);
        self.invitations
            .collect(tenant_id, is_open, copy_invitation)
            .into_iter()
            .collect()
    }

    async fn find_lapsed(
        &self,
        tenant_id: &ScopedTenant,
        now: OffsetDateTime,
        request: &PageRequest,
    ) -> Result<Page<Invitation<ResolvedTenant>>, DomainError> {
        let lapsed = |invitation: &Invitation<ResolvedTenant>| {
            is_open(invitation) && invitation.expires_at() <= now
        };
        let rows = self
            .invitations
            .collect(tenant_id, lapsed, copy_invitation)
            .into_iter()
            .collect::<Result<_, _>>()?;
        let sort = SortOrder::<InvitationSweepSortField>::default();
        let page = request.keyset(&sort)?.cut(rows);
        self.lapsed_reads.lock().unwrap().push(page.items.len());
        Ok(page)
    }

    async fn count_pending_for_role(
        &self,
        tenant_id: &ScopedTenant,
        role_id: &RoleId,
    ) -> Result<u64, DomainError> {
        let giving = |invitation: &Invitation<ResolvedTenant>| {
            is_open(invitation) && invitation.role_id() == role_id
        };
        let pending = self.invitations.collect(tenant_id, giving, |_| ()).len();
        Ok(u64::try_from(pending).expect("a test holds fewer invitations than u64 counts"))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        invitation: &Invitation<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let kept = copy_invitation(invitation)?;
        self.invitations
            .upsert(**tenant_id, |held| held.id() == invitation.id(), kept);
        Ok(())
    }
}

impl Fake for Arc<dyn InvitationStore> {
    fn fake() -> Self {
        Arc::new(FakeInvitationStore::empty())
    }
}

/// What a stored invitation a test seeds is made of.
pub struct InvitationSeed {
    /// The invited account.
    pub user_id: UserId,
    /// The address the invitation went to.
    pub email: Email,
    /// The role accepting it gives.
    pub role_id: RoleId,
    /// Who sent it.
    pub invited_by: ActorRef,
    /// The hash of its link's token.
    pub token_hash: TokenHash,
    /// When its link runs out.
    pub expires_at: OffsetDateTime,
}

impl InvitationSeed {
    /// An invitation for `user_id` at `email` offering `role_id`, sent an
    /// hour ago by someone the test does not name, whose link carries
    /// `link` and works for another day.
    ///
    /// # Panics
    ///
    /// If `email` is not a valid address. Tests pass literals that are.
    #[must_use]
    pub fn for_user(user_id: UserId, email: &str, role_id: RoleId, link: &str) -> Self {
        Self {
            user_id,
            email: Email::new(email).expect("a valid address"),
            role_id,
            invited_by: ActorRef::User(UserId::new()),
            token_hash: hash_of_link(link),
            expires_at: clock::now() + time::Duration::days(1),
        }
    }

    /// The same invitation, whose link ran out at `expires_at`.
    #[must_use]
    pub fn expiring_at(self, expires_at: OffsetDateTime) -> Self {
        Self { expires_at, ..self }
    }

    /// The same invitation, sent by `invited_by`.
    #[must_use]
    pub fn sent_by(self, invited_by: ActorRef) -> Self {
        Self { invited_by, ..self }
    }

    /// The invitation, pending, as storage would hand it back.
    #[must_use]
    pub fn stored(self) -> Invitation<ResolvedTenant> {
        self.stored_as(OfferState::Pending)
    }

    /// The invitation, standing at `state`, as storage would hand it back.
    ///
    /// # Panics
    ///
    /// When `state` was accepted before the invitation was sent, an hour
    /// before its link runs out or now, whichever is earlier.
    #[must_use]
    pub fn stored_as(self, state: OfferState) -> Invitation<ResolvedTenant> {
        let sent = self.expires_at.min(clock::now()) - time::Duration::hours(1);
        Invitation::reconstitute(InvitationRow {
            id: InvitationId::new(),
            user_id: self.user_id,
            email: self.email,
            invited_by: self.invited_by,
            role_id: self.role_id,
            token_hash: self.token_hash,
            state,
            message: None,
            expires_at: self.expires_at,
            created_at: sent,
        })
        .expect("a seeded invitation is a consistent row")
    }
}

/// Whether `invitation` is stored as pending, whatever its expiry.
fn is_open(invitation: &Invitation<ResolvedTenant>) -> bool {
    invitation.status() == InvitationStatus::Pending
}

/// A copy of `invitation`, which does not implement `Clone`, read back as a
/// real store would.
fn copy_invitation(
    invitation: &Invitation<ResolvedTenant>,
) -> Result<Invitation<ResolvedTenant>, DomainError> {
    Invitation::reconstitute(InvitationRow {
        id: *invitation.id(),
        user_id: *invitation.user_id(),
        email: invitation.email().clone(),
        invited_by: invitation.invited_by().clone(),
        role_id: *invitation.role_id(),
        token_hash: invitation.token_hash().clone(),
        state: OfferState::from_stored(invitation.status(), invitation.accepted_at())?,
        message: invitation.message().cloned(),
        expires_at: invitation.expires_at(),
        created_at: invitation.created_at(),
    })
}

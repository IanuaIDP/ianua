//! Who adds a passkey on the organization plane: a member signed in, or a
//! member whose sign-in waits for them to set up the second factor the
//! organization requires.
//!
//! The second has no finished session to act through. The sign-in they
//! hold lets them set up that factor and nothing else, and they show it by
//! its refresh token, which their browser holds.

use std::sync::Arc;

use ianua_domain::domains::authentication::risk_engine::origin::AttemptOrigin;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::organization::access::session::OrgSession;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::shared::clock;
use ianua_domain::shared::security::secret::Secret;

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgSessionStore, OrgUserStore, OrganizationStore};
use crate::use_cases::organization::lookup::{existing_member, owned_org_session};

/// Who adds a passkey.
pub enum MemberRegistrant {
    /// A member signed in to a session of their organization.
    SignedIn(OrgCaller),
    /// A member whose sign-in waits for them to set up a second factor.
    SettingUpFactor(PendingMemberToken),
}

/// A member's sign-in that waits for them to set up a second factor, shown
/// by its refresh token. The token is a credential, so this has no `Debug`.
pub struct PendingMemberToken {
    /// The sign-in's refresh token, as the browser holds it.
    pub refresh_token: Secret,
}

/// The ports that find out who a [`MemberRegistrant`] is.
#[derive(ianua_macros::Fakes)]
pub struct MemberRegistrantPorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// Members' sessions, for a sign-in still waiting.
    pub sessions: Arc<dyn OrgSessionStore>,
    /// The members, whose change of how they sign in is kept.
    pub members: Arc<dyn OrgUserStore>,
    /// Organizations, for a waiting sign-in's organization.
    pub organizations: Arc<dyn OrganizationStore>,
    /// Hashes a refresh token the way sessions keep it.
    pub token_hasher: Arc<dyn RefreshTokenGenerator>,
}

/// Where the member adds the passkey from.
pub(crate) enum RegisteringFrom {
    /// Their own finished session, which the passkey leaves as it is.
    SignedIn,
    /// The sign-in that waits for this factor, which the passkey finishes.
    WaitingSignIn(Box<OrgSession>),
}

/// The member adding a passkey, their organization, and where they add it
/// from.
pub(crate) struct MemberRegistering {
    /// The member, as they are now.
    pub member: OrgUser,
    /// Their organization, as it is now.
    pub organization: Organization,
    /// Where they add it from.
    pub from: RegisteringFrom,
    /// Where the request came from, which a password typed again counts
    /// against: the caller's request, or for a waiting sign-in, where it
    /// was made moments ago.
    pub origin: AttemptOrigin,
}

impl MemberRegistrantPorts {
    /// The member `registrant` adds a passkey for, and where from.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the session no longer counts, the
    ///   caller acts through a key, or the sign-in is not one waiting,
    ///   moments ago, for a factor to be set up.
    /// - `AppError::Forbidden` when the session is another member's.
    /// - `AppError::NotFound` when the member is gone.
    /// - `AppError::Internal` on storage failure.
    pub(crate) async fn registering(
        &self,
        registrant: &MemberRegistrant,
    ) -> Result<MemberRegistering, AppError> {
        match registrant {
            MemberRegistrant::SignedIn(caller) => self.signed_in(caller).await,
            MemberRegistrant::SettingUpFactor(pending) => self.waiting(pending).await,
        }
    }

    /// The member signed in to `caller`'s own session.
    async fn signed_in(&self, caller: &OrgCaller) -> Result<MemberRegistering, AppError> {
        let (organization, actor) = self.org_actors.actor(caller).await?;
        actor.signed_in()?;
        let member = existing_member(
            self.members.as_ref(),
            organization.id(),
            actor.member().id(),
        )
        .await?;
        Ok(MemberRegistering {
            member,
            organization,
            from: RegisteringFrom::SignedIn,
            origin: caller.origin(),
        })
    }

    /// The sign-in `pending` shows, while it waits for a factor to be set
    /// up, with its member and organization.
    async fn waiting(&self, pending: &PendingMemberToken) -> Result<MemberRegistering, AppError> {
        let hash = self.token_hasher.hash_raw(pending.refresh_token.expose());
        let session = self
            .sessions
            .find_by_refresh_token_hash(&hash)
            .await
            .or_internal()?
            .filter(|session| session.enrolment_proof(clock::now()).is_some())
            .ok_or(AppError::Unauthenticated)?;
        let member = self
            .members
            .find_by_id(session.org_user_id())
            .await
            .or_internal()?
            .ok_or(AppError::Unauthenticated)?;
        let organization = self
            .organizations
            .find_by_id(session.organization_id())
            .await
            .or_internal()?
            .ok_or(AppError::Unauthenticated)?;
        Ok(MemberRegistering {
            member,
            organization,
            origin: AttemptOrigin::of(session.ip_address()),
            from: RegisteringFrom::WaitingSignIn(Box::new(session)),
        })
    }

    /// The session `caller` signed in to, as stored, for a change of how
    /// they sign in to keep it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the session no longer counts, or
    ///   the caller acts through a key.
    /// - `AppError::NotFound` when the session is gone.
    /// - `AppError::Internal` on storage failure.
    pub(in crate::use_cases::organization::passkeys) async fn own_session(
        &self,
        caller: &OrgCaller,
    ) -> Result<OrgSession, AppError> {
        let (organization, actor) = self.org_actors.actor(caller).await?;
        owned_org_session(self.sessions.as_ref(), &organization, &actor).await
    }
}

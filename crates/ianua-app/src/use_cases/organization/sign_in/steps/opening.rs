//! Opening a member's session once their sign-in has begun, the one step
//! every way of signing in to the organization ends with.
//!
//! The session is the domain's to open: it checks the sign-in was begun for
//! this member, that the organization lets them in, and that they may reach
//! the tenant it opens in. Signing in ends the member's earlier sessions,
//! so a sign-in on a new device leaves no older session behind, and spends
//! whatever the setup token or an accepted invitation vouched for, so only
//! the first sign-in after one may set a factor up on its word.

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::account::vouching::Vouching;
use ianua_domain::domains::organization::access::session::{
    CreateOrgSessionParams, OrgSession, SessionEntry, SessionPlace,
};
use ianua_domain::domains::organization::access::sign_in_start::OrgSignInStart;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::organization::members::tenant_grant::OrgTenantGrant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Fact, Lifetime, SessionId};

use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgSessionStore, OrgTenantGrantStore, OrgUserStore};
use crate::services::authentication::sign_in_gate::ClientOrigin;
use crate::use_cases::organization::lookup::existing_member;
use crate::use_cases::organization::sign_in::sessions::sign_out::sign_out_member;

/// Where a new session is kept, and what it is made with.
#[derive(Clone, Copy)]
pub(in crate::use_cases::organization) struct SessionOpener<'a> {
    /// The members, to record that one signed in.
    pub(in crate::use_cases::organization) members: &'a dyn OrgUserStore,
    /// Members' sessions.
    pub(in crate::use_cases::organization) sessions: &'a dyn OrgSessionStore,
    /// The tenants a member was let into.
    pub(in crate::use_cases::organization) grants: &'a dyn OrgTenantGrantStore,
    /// Makes the session's refresh token.
    pub(in crate::use_cases::organization) token_generator: &'a dyn RefreshTokenGenerator,
}

/// Who a session opens for, where, and from what sign-in.
pub(in crate::use_cases::organization) struct Opening<'a> {
    /// The member signing in, as they stand now.
    pub(in crate::use_cases::organization) member: &'a OrgUser,
    /// Their organization, as it stands now.
    pub(in crate::use_cases::organization) organization: &'a Organization,
    /// Where the session works: a tenant, or the organization alone.
    pub(in crate::use_cases::organization) place: SessionPlace,
    /// The sign-in begun for the member.
    pub(in crate::use_cases::organization) start: OrgSignInStart,
    /// Where the sign-in came from.
    pub(in crate::use_cases::organization) origin: &'a ClientOrigin,
}

/// A session just opened, with its raw refresh token. It holds the token,
/// so it has no `Debug`.
pub(in crate::use_cases::organization) struct OpenedSession {
    /// The session, saved.
    pub(in crate::use_cases::organization) session: OrgSession,
    /// The raw refresh token, sent to the client and never stored.
    pub(in crate::use_cases::organization) refresh_token: Secret,
}

impl SessionOpener<'_> {
    /// Opens and saves the session `opening` describes, after ending the
    /// member's earlier sessions, and records that the member signed in.
    /// It lives as long as the organization's settings say.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the domain refuses the session: the
    ///   sign-in was begun for someone else, the member may not sign in,
    ///   the organization keeps them out, or they may not reach the tenant.
    /// - `AppError::Domain` when the organization's session lifetime is out
    ///   of range.
    /// - `AppError::NotFound` when the member is gone by now.
    /// - `AppError::Internal` when a store fails or no token can be made.
    pub(in crate::use_cases::organization) async fn open(
        &self,
        opening: Opening<'_>,
    ) -> Result<OpenedSession, AppError> {
        let member = opening.member;
        let grants = self.grants_at(member, opening.place).await?;
        let (raw, hash) = self.token_generator.generate().or_internal()?.into_parts();
        let params = CreateOrgSessionParams {
            id: SessionId::new(),
            place: opening.place,
            refresh_token_hash: hash,
            ip_address: opening.origin.ip_address.clone(),
            user_agent: Fact::from_option(opening.origin.user_agent.clone()),
            lifetime: session_lifetime(opening.organization)?,
        };
        let entry = SessionEntry {
            member,
            organization: opening.organization,
            grants: &grants,
        };
        let session =
            OrgSession::create(params, entry, opening.start).map_err(AppError::from_domain)?;
        sign_out_member(self.sessions, member.id()).await?;
        self.sessions.save(&session).await.or_internal()?;
        self.spend_vouching(member).await?;
        Ok(OpenedSession {
            session,
            refresh_token: raw,
        })
    }

    /// Records that `member` signed in, when the setup token or an accepted
    /// invitation still vouched for them. Nothing else changes on a sign-in,
    /// so a member nothing vouches for is left unsaved.
    async fn spend_vouching(&self, member: &OrgUser) -> Result<(), AppError> {
        if member.vouching() == Vouching::Absent {
            return Ok(());
        }
        let mut signed_in =
            existing_member(self.members, member.organization_id(), member.id()).await?;
        signed_in.record_sign_in();
        self.members.save(&signed_in).await.or_internal()
    }

    /// The grants `member` holds in the tenant `place` names: none for a
    /// session on the organization alone.
    async fn grants_at(
        &self,
        member: &OrgUser,
        place: SessionPlace,
    ) -> Result<Vec<OrgTenantGrant>, AppError> {
        let SessionPlace::Tenant(tenant_id) = place else {
            return Ok(Vec::new());
        };
        self.grants
            .list_by_user_in_tenant(member.id(), &tenant_id)
            .await
            .or_internal()
    }
}

/// How long the organization's sessions live.
///
/// # Errors
///
/// - `AppError::Domain` when the setting is not a lifetime.
fn session_lifetime(organization: &Organization) -> Result<Lifetime, AppError> {
    let seconds = organization.auth_config().session_lifetime_secs();
    Lifetime::new(seconds.duration())
        .map_err(|error| AppError::from_domain(DomainError::from(error)))
}

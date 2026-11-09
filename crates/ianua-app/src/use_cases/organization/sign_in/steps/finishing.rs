//! Finishing a member's sign-in that proved them some other way than a
//! password: through the organization's identity provider, or by a link
//! mailed to them.
//!
//! What it owes depends only on whether the member set a second factor up,
//! as for a tenant's sign-in links and single sign-on: the way in already
//! proved more than a password, so no device or place asks for more. The
//! session lands in the tenant asked for, or the first the member reaches,
//! or on the organization alone when they reach no tenant, and the member
//! is told what they reach once nothing more is owed.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInRefused;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::organization::access::landing::SignInLanding;
use ianua_domain::domains::organization::access::session::OrgSession;
use ianua_domain::domains::organization::access::sign_in_start::OrgSignInStart;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::types::TenantSlug;

use crate::error::AppError;
use crate::ports::authorization::RoleStore;
use crate::ports::organization::{
    OrgMfaEnrollmentStore, OrgPasskeyStore, OrgSessionStore, OrgTenantGrantStore, OrgUserStore,
};
use crate::ports::tenant::TenantStore;
use crate::services::authentication::sign_in_gate::ClientOrigin;
use crate::use_cases::organization::members::rights::access::{AccessSources, OrgUserAccess};
use crate::use_cases::organization::sign_in::OrgLoginSuccess;
use crate::use_cases::organization::sign_in::password::held_factors::MemberFactorSources;
use crate::use_cases::organization::sign_in::steps::landing::{LandedTenant, Landing};
use crate::use_cases::organization::sign_in::steps::opening::{
    OpenedSession, Opening, SessionOpener,
};

/// The ports a sign-in is finished with: the member's factors, the tenants
/// it may land in, the session it opens and what the member reaches.
#[derive(ianua_macros::Fakes)]
pub struct FinishingPorts {
    /// The members, to record that one signed in.
    pub members: Arc<dyn OrgUserStore>,
    /// Members' authenticator apps.
    pub enrollments: Arc<dyn OrgMfaEnrollmentStore>,
    /// Members' passkeys.
    pub passkeys: Arc<dyn OrgPasskeyStore>,
    /// The organization's tenants, to land in one.
    pub tenants: Arc<dyn TenantStore>,
    /// Where the new session is kept.
    pub sessions: Arc<dyn OrgSessionStore>,
    /// The tenants and roles members were granted.
    pub grants: Arc<dyn OrgTenantGrantStore>,
    /// Makes the session's refresh token.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// The roles of each tenant, to describe what the member reaches.
    pub roles: Arc<dyn RoleStore>,
}

/// Who signs in to which organization, from where, and the tenant they
/// asked to land in.
#[derive(Clone, Copy)]
pub(in crate::use_cases::organization::sign_in) struct Arrival<'a> {
    /// The member signing in, as they stand now.
    pub(in crate::use_cases::organization::sign_in) member: &'a OrgUser,
    /// Their organization, as it stands now.
    pub(in crate::use_cases::organization::sign_in) organization: &'a Organization,
    /// The tenant named, if any.
    pub(in crate::use_cases::organization::sign_in) tenant_slug: Option<&'a TenantSlug>,
    /// Where the sign-in came from.
    pub(in crate::use_cases::organization::sign_in) origin: &'a ClientOrigin,
}

impl FinishingPorts {
    /// What `member`'s sign-in to `organization` owes: their own factor
    /// when they set one up, or setting one up when the organization
    /// requires it.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` when the member's factors cannot be
    /// read.
    pub(in crate::use_cases::organization::sign_in) async fn owed(
        &self,
        member: &OrgUser,
        organization: &Organization,
    ) -> Result<SecondFactor, AppError> {
        let sources = MemberFactorSources {
            enrollments: self.enrollments.as_ref(),
            passkeys: self.passkeys.as_ref(),
        };
        let enrolment = sources.held_by(member.id()).await?;
        let policy = organization.auth_config().mfa_policy();
        Ok(SecondFactor::for_enrolment(policy, enrolment))
    }

    /// Opens the session `start` begins for the member `arrival` names,
    /// where they land, and describes it for them.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when no tenant of the organization has the
    ///   slug named.
    /// - `AppError::Forbidden` when the domain refuses the session, such as
    ///   for a named tenant the member does not reach.
    /// - `AppError::Domain` when the organization's session lifetime is out
    ///   of range.
    /// - `AppError::Internal` on storage or token failure.
    pub(in crate::use_cases::organization::sign_in) async fn finish(
        &self,
        arrival: Arrival<'_>,
        start: OrgSignInStart,
    ) -> Result<OrgLoginSuccess, AppError> {
        let landing = Landing {
            tenants: self.tenants.as_ref(),
            grants: self.grants.as_ref(),
        };
        let place = landing
            .place_for(arrival.member, arrival.organization, arrival.tenant_slug)
            .await?;
        let opening = Opening {
            member: arrival.member,
            organization: arrival.organization,
            place: place.place(),
            start,
            origin: arrival.origin,
        };
        let opened = self.opener().open(opening).await?;
        let access = self
            .access_once_finished(arrival.member, &opened.session)
            .await?;
        Ok(success(arrival, &place, opened, access))
    }

    /// Where the session is opened and kept.
    fn opener(&self) -> SessionOpener<'_> {
        SessionOpener {
            members: self.members.as_ref(),
            sessions: self.sessions.as_ref(),
            grants: self.grants.as_ref(),
            token_generator: self.token_generator.as_ref(),
        }
    }

    /// What `member` reaches, or nothing while the session owes more.
    async fn access_once_finished(
        &self,
        member: &OrgUser,
        session: &OrgSession,
    ) -> Result<Option<OrgUserAccess>, AppError> {
        if !session.mfa_satisfied() {
            return Ok(None);
        }
        let sources = AccessSources {
            tenants: self.tenants.as_ref(),
            roles: self.roles.as_ref(),
            grants: self.grants.as_ref(),
        };
        sources.reach_of(member).await.map(Some)
    }
}

/// The answer to a sign-in the domain would not begin: never an internal
/// error, since the member's own proof fell short or the organization
/// signs them in another way.
pub(in crate::use_cases::organization::sign_in) fn start_refused(
    refused: SignInRefused,
) -> AppError {
    AppError::Forbidden(refused.to_string().into())
}

/// What the member is told about the session `opened` for them at
/// `place`.
fn success(
    arrival: Arrival<'_>,
    place: &SignInLanding,
    opened: OpenedSession,
    access: Option<OrgUserAccess>,
) -> OrgLoginSuccess {
    let Arrival {
        member,
        organization,
        ..
    } = arrival;
    OrgLoginSuccess {
        session_id: *opened.session.id(),
        org_user_id: *member.id(),
        second_factor: opened.session.owed(),
        refresh_token: opened.refresh_token,
        tenant: LandedTenant::from(place),
        organization_id: *organization.id(),
        org_slug: organization.slug().clone(),
        organization_name: organization.name().clone(),
        display_name: member.display_name().clone(),
        access,
    }
}

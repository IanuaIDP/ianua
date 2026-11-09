//! What a member's password sign-in keeps once the domain began it: the
//! session opened where it lands, the remembered device it came from
//! stamped as used, the confirmation by email it may owe, and what the
//! member is told about it.

use ianua_domain::domains::organization::access::landing::SignInLanding;
use ianua_domain::domains::organization::access::session::OrgSession;
use ianua_domain::domains::organization::access::sign_in_start::OrgSignInStart;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::OrgUser;

use crate::error::AppError;
use crate::use_cases::authentication::password::sign_in::confirmation::owes_email_confirmation;
use crate::use_cases::organization::members::rights::access::{AccessSources, OrgUserAccess};
use crate::use_cases::organization::sign_in::mailed::confirmation_mail::MemberConfirming;
use crate::use_cases::organization::sign_in::password::login::{
    OrgLoginSettings, OrgLoginSuccess, OrgPasswordLoginPorts, OrgPasswordLoginRequest,
};
use crate::use_cases::organization::sign_in::password::second_factor::OwedFactor;
use crate::use_cases::organization::sign_in::steps::landing::LandedTenant;
use crate::use_cases::organization::sign_in::steps::opening::{
    OpenedSession, Opening, SessionOpener,
};

/// Who signed in, to which organization, landing where.
#[derive(Clone, Copy)]
pub(super) struct Landed<'a> {
    /// The member signed in.
    pub(super) member: &'a OrgUser,
    /// The owning account whose policy governs the completed sign-in.
    pub(super) organization: &'a Organization,
    /// Where the session lands.
    pub(super) place: &'a SignInLanding,
}

/// Where a member's sign-in is kept, under the deployment's settings.
pub(super) struct KeptSignIn<'a> {
    /// The ports the sign-in runs through.
    pub(super) ports: &'a OrgPasswordLoginPorts,
    /// What the deployment sets for members' password sign-ins.
    pub(super) settings: &'a OrgLoginSettings,
    /// The devices members remembered, to stamp the one the sign-in came
    /// from.
    pub(super) owed: OwedFactor<'a>,
}

impl KeptSignIn<'_> {
    /// Opens the session where `landed` says, stamps the remembered device
    /// it came from as used, and describes it for the member.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` on storage, token or mail failure.
    pub(super) async fn opened(
        &self,
        landed: Landed<'_>,
        start: OrgSignInStart,
        request: &OrgPasswordLoginRequest,
    ) -> Result<OrgLoginSuccess, AppError> {
        let origin = &request.origin;
        let opener = SessionOpener {
            members: self.ports.members.as_ref(),
            sessions: self.ports.session.sessions.as_ref(),
            grants: self.ports.session.grants.as_ref(),
            token_generator: self.ports.session.token_generator.as_ref(),
        };
        let opening = Opening {
            member: landed.member,
            organization: landed.organization,
            place: landed.place.place(),
            start,
            origin,
        };
        let opened = opener.open(opening).await?;
        self.owed
            .stamp_member_device(landed.member, request.device_secret.as_ref(), origin)
            .await?;
        self.mail_confirmation(landed, &opened.session).await?;
        let access = self
            .access_once_finished(landed.member, &opened.session)
            .await?;
        Ok(login_success(landed, opened, access))
    }

    /// Mails the confirmation link when the sign-in waits for one.
    async fn mail_confirmation(
        &self,
        landed: Landed<'_>,
        session: &OrgSession,
    ) -> Result<(), AppError> {
        if !owes_email_confirmation(session.owed()) {
            return Ok(());
        }
        let to = MemberConfirming {
            member: landed.member,
            organization: landed.organization,
        };
        self.ports
            .confirmation
            .send(to, &self.settings.confirmation)
            .await
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
            tenants: self.ports.tenants.as_ref(),
            roles: self.ports.session.roles.as_ref(),
            grants: self.ports.session.grants.as_ref(),
        };
        sources.reach_of(member).await.map(Some)
    }
}

/// What the member is told about the session `opened` for them.
fn login_success(
    landed: Landed<'_>,
    opened: OpenedSession,
    access: Option<OrgUserAccess>,
) -> OrgLoginSuccess {
    let Landed {
        member,
        organization,
        place,
    } = landed;
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

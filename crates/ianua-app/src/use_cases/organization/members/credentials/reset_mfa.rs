//! An owner clearing the second factor of a member who lost their
//! authenticator and their recovery codes.
//!
//! The member cannot turn the factor off without proving they hold it, so
//! this is the way back in for someone who holds nothing. It ends every
//! session the member has and every device they remembered, so whoever has
//! the lost device is out with them, and it tells the member by email: a
//! reset they did not ask for is the sign of a takeover in progress.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::{MfaEnrollment, MfaEnrollmentError};
use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::domains::organization::members::account_control::OrgAccountControl;
use ianua_domain::domains::organization::members::control::OrgControl;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::organization::members::permission::{MemberAction, OrgPermission};
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::message;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, OrgUserId};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::organization::{
    OrgMfaEnrollmentStore, OrgSessionStore, OrgUserStore, OrganizationStore,
};
use crate::ports::shared::Mailer;
use crate::use_case::Command;
use crate::use_cases::organization::lookup::existing_member;
use crate::use_cases::organization::mail_labels::organization_name;
use crate::use_cases::organization::sign_in::sessions::sign_out::sign_out_member;

/// The ports [`ResetMfaUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResetMfaPorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// The organization's members.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Members' second factors.
    pub enrollments: Arc<dyn OrgMfaEnrollmentStore>,
    /// Members' sessions, ended after the reset.
    pub org_sessions: Arc<dyn OrgSessionStore>,
    /// Organizations, for the name the email gives.
    pub organizations: Arc<dyn OrganizationStore>,
    /// Tells the member.
    pub mailer: Arc<dyn Mailer>,
}

/// Clears a member's second factor on an owner's say.
pub struct ResetMfaUseCase {
    ports: ResetMfaPorts,
}

impl ResetMfaUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: ResetMfaPorts) -> Self {
        Self { ports }
    }

    /// The member's second factor, turned off as `control` decides, and
    /// saved.
    async fn reset_factor(
        &self,
        member: &OrgUser,
        control: OrgControl<'_>,
    ) -> Result<(), AppError> {
        let mut enrollment = self
            .ports
            .enrollments
            .find_by_user(member.id())
            .await
            .or_internal()?
            .or_not_found(message!(
                "organization-the-member-has-no-second-factor",
                "the member has no second factor to reset"
            ))?;
        reset_by(&mut enrollment, &OrgAccountControl::new(control, member))?;
        self.ports
            .enrollments
            .save(member.id(), &enrollment)
            .await
            .or_internal()
    }

    /// Emails the member that their factor was reset. A mail that fails to
    /// send leaves the reset done and recorded.
    async fn tell_member(&self, member: &OrgUser) {
        let variables = HashMap::from([
            (
                TemplateVariable::UserName,
                member.display_name().as_str().to_owned(),
            ),
            (
                TemplateVariable::OrganizationName,
                organization_name(self.ports.organizations.as_ref(), member).await,
            ),
        ]);
        let template = EmailTemplateType::OrgMfaReset;
        let sent = self
            .ports
            .mailer
            .send(member.email(), None, template, &variables)
            .await;
        if let Err(error) = sent {
            tracing::warn!(org_user_id = %member.id(), %error, "second factor reset: notice not sent");
        }
    }
}

impl Command for ResetMfaUseCase {
    type Caller = OrgCaller;
    type Input = OrgUserId;
    type Output = Result<(), AppError>;

    /// Turns off the second factor of the member `id`, ends their sessions
    /// and remembered devices, records `organization.org_member_mfa_reset`
    /// and emails them.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller names themselves, may not
    ///   update members, or resets an owner without being one.
    /// - `AppError::NotFound` when the organization has no such member, or
    ///   the member has no second factor in force.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        id: OrgUserId,
    ) -> Result<(), AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        control
            .ensure_may(
                organization.id(),
                OrgPermission::Members(MemberAction::Update),
            )
            .map_err(AppError::from_domain)?;
        let users = self.ports.org_users.as_ref();
        let mut member = existing_member(users, organization.id(), &id).await?;
        self.reset_factor(&member, control).await?;
        member.record_mfa_reset();
        users.save(&member).await.or_internal()?;
        sign_out_member(self.ports.org_sessions.as_ref(), member.id()).await?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*caller.member()), member.take_events())
            .await
            .or_internal()?;
        self.tell_member(&member).await;
        Ok(())
    }
}

/// Turns `enrollment` off as `control` decides.
///
/// # Errors
///
/// - `AppError::Forbidden` when `control` refuses it.
/// - `AppError::NotFound` when the factor is not in force.
fn reset_by(
    enrollment: &mut MfaEnrollment<ResolvedOrganization>,
    control: &OrgAccountControl<'_>,
) -> Result<(), AppError> {
    enrollment
        .reset_by_admin(control)
        .map_err(|refused| refused_reset(&refused))
}

/// The error a reset the domain refused answers with.
fn refused_reset(refused: &MfaEnrollmentError) -> AppError {
    match refused {
        MfaEnrollmentError::AccountHoldsMore | MfaEnrollmentError::NotThisAccount => {
            AppError::Forbidden(message!(
                "organization-an-owner-resets-another-member-s",
                "an owner resets another member's second factor; your own is turned off with a code"
            ))
        }
        MfaEnrollmentError::NotPending
        | MfaEnrollmentError::NotActive
        | MfaEnrollmentError::NotItsCode
        | MfaEnrollmentError::NotProvedNow
        | MfaEnrollmentError::NotOffered => AppError::NotFound(message!(
            "organization-the-member-has-no-second-factor",
            "the member has no second factor to reset"
        )),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::mfa::enrollment_status::MfaEnrollmentStatus;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::clock;
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::authentication::FakeMfaEnrollmentStore;
    use crate::test_support::organization::{
        FakeOrgUserStore, RecordingOrgSessionStore, org_user_store_with, stored_caller,
        test_org_user,
    };
    use crate::test_support::{
        FakeEventDispatcher, FakeMailer, block_on, test_auditor, test_org_caller,
    };

    struct Reset {
        uc: ResetMfaUseCase,
        enrollments: Arc<FakeMfaEnrollmentStore>,
        users: Arc<FakeOrgUserStore>,
        sessions: Arc<RecordingOrgSessionStore>,
        mailer: Arc<FakeMailer>,
        audit: Arc<FakeEventDispatcher>,
        sam: OrgUserId,
        oscar: OrgUserId,
    }

    impl Reset {
        /// Sam, a member, and Oscar, an owner, each with an authenticator
        /// app, and the caller in Acme.
        fn with(actors: FakeOrgActors) -> Self {
            let organization_id = test_org_caller().organization_id();
            let sam = test_org_user(organization_id, "sam@acme.test", OrgRole::Member);
            let oscar = test_org_user(organization_id, "oscar@acme.test", OrgRole::Owner);
            let caller = stored_caller(OrgRole::Owner, "pw");
            let (sam_id, oscar_id) = (*sam.id(), *oscar.id());
            let enrollments = Arc::new(FakeMfaEnrollmentStore::active_for_all([
                sam_id,
                oscar_id,
                *caller.id(),
            ]));
            let users = Arc::new(org_user_store_with([sam, oscar, caller]));
            let sessions = Arc::new(RecordingOrgSessionStore::new());
            let mailer = Arc::new(FakeMailer::new());
            Self {
                uc: ResetMfaUseCase::new(ResetMfaPorts {
                    org_actors: Arc::new(actors),
                    org_users: users.clone(),
                    enrollments: enrollments.clone(),
                    org_sessions: sessions.clone(),
                    mailer: mailer.clone(),
                    ..ResetMfaPorts::fakes()
                }),
                enrollments,
                users,
                sessions,
                mailer,
                audit: Arc::new(FakeEventDispatcher::new()),
                sam: sam_id,
                oscar: oscar_id,
            }
        }

        fn owner() -> Self {
            Self::with(FakeOrgActors::in_role(OrgRole::Owner))
        }

        fn reset(&self, member: OrgUserId) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                member,
            ))
        }

        fn status(&self, member: OrgUserId) -> Option<MfaEnrollmentStatus> {
            self.enrollments.enrollment_of(member).map(|e| e.status())
        }
    }

    /// Olivia, an owner, resets Sam's lost authenticator. It is off, Sam is
    /// signed out and his remembered devices stop counting, the reset is
    /// recorded and Sam is told.
    #[test]
    fn an_owner_resets_a_members_factor_and_the_member_is_told() {
        let r = Reset::owner();

        r.reset(r.sam).unwrap();

        assert_eq!(r.status(r.sam), Some(MfaEnrollmentStatus::Disabled));
        assert!(r.sessions.revoked(&r.sam));
        let sam = block_on(r.users.find_by_id(&r.sam)).unwrap().unwrap();
        assert!(
            sam.credentials_changed_at()
                .since(clock::now() - time::Duration::minutes(1))
        );
        assert_eq!(
            *r.audit.records.lock().unwrap(),
            ["organization.org_member_mfa_reset"]
        );
        assert_eq!(
            r.mailer.sent.lock().unwrap()[0].template,
            EmailTemplateType::OrgMfaReset
        );
    }

    /// An owner cannot use an administrative reset on their own factor;
    /// it remains verified.
    #[test]
    fn an_owner_cannot_reset_their_own_factor() {
        let r = Reset::owner();
        let olivia = *test_org_caller().member();

        let result = r.reset(olivia);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(r.status(olivia), Some(MfaEnrollmentStatus::Verified));
    }

    /// A plain member cannot reset an owner's factor; it remains verified
    /// and no notice is mailed.
    #[test]
    fn a_member_resetting_an_owners_factor_is_refused() {
        let r = Reset::with(FakeOrgActors::in_role(OrgRole::Member));

        let result = r.reset(r.oscar);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(r.status(r.oscar), Some(MfaEnrollmentStatus::Verified));
        assert!(r.mailer.sent.lock().unwrap().is_empty());
    }

    /// A plain member naming an unknown account receives a permission refusal
    /// rather than a not-found response.
    #[test]
    fn a_member_who_may_not_update_members_learns_nothing_of_an_unknown_member() {
        let r = Reset::with(FakeOrgActors::in_role(OrgRole::Member));

        let result = r.reset(OrgUserId::new());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Another organization's stored member is not found for a factor reset.
    #[test]
    fn a_member_of_another_organization_is_not_found() {
        let r = Reset::owner();
        let eve = test_org_user(OrganizationId::new(), "eve@other.test", OrgRole::Member);
        let eve_id = *eve.id();
        block_on(r.users.save(&eve)).unwrap();

        let result = r.reset(eve_id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A member with no second factor in force has nothing to reset.
    #[test]
    fn a_member_without_a_factor_is_not_found() {
        let r = Reset::owner();
        r.reset(r.sam).unwrap();

        let again = r.reset(r.sam);

        assert!(matches!(again, Err(AppError::NotFound(_))));
    }

    /// A signed-out caller cannot reset Sam's factor, which remains verified.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let r = Reset::with(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = r.reset(r.sam);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(r.status(r.sam), Some(MfaEnrollmentStatus::Verified));
    }

    /// Refused organization authority prevents resetting Sam's factor.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let r = Reset::with(FakeOrgActors::refusing(Refusal::Forbidden));

        let result = r.reset(r.sam);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}

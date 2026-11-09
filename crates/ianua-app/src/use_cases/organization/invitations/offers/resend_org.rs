//! Resend org invitation: an owner sends a waiting invitation again with a
//! fresh link, and the old link stops working.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::organization::members::control::OrgControl;
use ianua_domain::domains::organization::members::invitation::OrgInvitation;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, OrgUserId};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::email::{InvitationDelivery, InvitationMailing, LinkScope};
use crate::error::{AppError, OrInternal};
use crate::ports::limits::{MailPurpose, MailThrottle};
use crate::ports::organization::{OrgInvitationStore, OrgUserStore};
use crate::services::limits::mail_cooldown::ensure_mail_admitted;
use crate::use_case::Command;
use crate::use_cases::organization::invitations::offers::mail::{
    OrgInvitationMail, deliver_org_invitation,
};
use crate::use_cases::organization::lookup::{existing_member, existing_pending_invitation};

/// The ports [`ResendOrgUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResendOrgPorts {
    /// Loads the invited member.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// Loads and saves invitations.
    pub org_invitation_store: Arc<dyn OrgInvitationStore>,
    /// Who acts on the organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// Mails the invitation under the invitation policy.
    pub mailing: InvitationMailing,
    /// Lets one invitation a minute through to an address.
    pub mail_throttle: Arc<dyn MailThrottle>,
    /// Makes invitation links.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// Whose invitation to send again, and where its link lands.
pub struct ResendOrgRequest {
    /// The invited member, in the caller's organization.
    pub org_user_id: OrgUserId,
    /// Where the new link lands.
    pub scope: LinkScope,
}

/// Sends a waiting invitation of the caller's organization again.
pub struct ResendOrgUseCase {
    ports: ResendOrgPorts,
}

impl ResendOrgUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ResendOrgPorts) -> Self {
        Self { ports }
    }

    /// `invitation` with a fresh link for `invitee`, as `control` sends it,
    /// and the raw token the link carries.
    fn renewed(
        &self,
        invitation: &mut OrgInvitation,
        invitee: &OrgUser,
        control: &OrgControl<'_>,
    ) -> Result<Secret, AppError> {
        let generator = self.ports.token_generator.as_ref();
        let (raw_token, token_hash) = generator.generate().or_internal()?.into_parts();
        let lifetime = self.ports.mailing.policy.lifetime;
        invitation
            .rotate_token(invitee, control, token_hash, lifetime)
            .map_err(AppError::from_domain)?;
        Ok(raw_token)
    }
}

impl Command for ResendOrgUseCase {
    type Caller = OrgCaller;
    type Input = ResendOrgRequest;
    type Output = Result<InvitationDelivery, AppError>;

    /// Gives the pending invitation of `request.org_user_id` a fresh link
    /// and expiry, records `organization.org_user_invitation_resent` and
    /// mails it. The link sent before stops working. On a deployment with
    /// no mail server nothing is mailed: the answer hands the caller the new
    /// link to pass on.
    ///
    /// The member is looked up in the caller's own organization only, so a
    /// member of another organization reads as not found.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without invitation rights or for a changed invited address.
    /// - `AppError::NotFound` for a member/pending invitation outside the organization; `Domain` for an invitation no longer pending.
    /// - `AppError::Upstream` for refused mail after saving and recording the replacement link.
    /// - `AppError::TooManyRequests` for an invitation sent within a minute; `Internal` on persistence or token failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: ResendOrgRequest,
    ) -> Result<InvitationDelivery, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let (members, invitations) = (
            self.ports.org_user_store.as_ref(),
            self.ports.org_invitation_store.as_ref(),
        );
        let invitee = existing_member(members, organization.id(), &request.org_user_id).await?;
        let mut invitation =
            existing_pending_invitation(invitations, organization.id(), invitee.id()).await?;
        let raw_token = self.renewed(&mut invitation, &invitee, &control)?;
        let throttle = self.ports.mail_throttle.as_ref();
        ensure_mail_admitted(throttle, MailPurpose::OrgInvitation, invitee.email()).await?;

        invitations.save(&invitation).await.or_internal()?;
        let by = ActorRef::OrgUser(*actor.member().id());
        auditor
            .dispatch_by(&by, invitation.take_events())
            .await
            .or_internal()?;
        let mail = OrgInvitationMail {
            invitee: &invitee,
            organization_name: organization.name().as_str(),
            raw_token: &raw_token,
            scope: &request.scope,
        };
        deliver_org_invitation(&self.ports.mailing, mail).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{OrganizationId, TokenHash};

    use super::*;
    use crate::email::InvitationPolicy;
    use crate::ports::shared::MailSetup;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        FakeOrgInvitationStore, invited_org_user, org_user_store_with, pending_org_invitation,
    };
    use crate::test_support::{
        Fake, FakeEventDispatcher, FakeMailSetup, FakeMailer, block_on, test_auditor,
        test_org_caller, test_org_link_scope,
    };

    const BOB: &str = "bob@acme.test";

    /// The hash Bob's first link carried. Not the generator's first output,
    /// so a resend visibly rotates away from it.
    fn first_link() -> TokenHash {
        TokenHash::from_stored("first_link_hash".to_owned())
    }

    struct Setup {
        uc: ResendOrgUseCase,
        bob: OrgUserId,
        invitations: Arc<FakeOrgInvitationStore>,
        mailer: Arc<FakeMailer>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn with(actors: FakeOrgActors, mailer: FakeMailer, invited_at: OrganizationId) -> Self {
            Self::reaching(actors, (mailer, Fake::fake()), invited_at)
        }

        /// An owner sending again on a deployment with no mail server.
        fn without_mail() -> Self {
            Self::reaching(
                FakeOrgActors::in_role(OrgRole::Owner),
                (FakeMailer::new(), FakeMailSetup::not_set_up()),
                test_org_caller().organization_id(),
            )
        }

        fn reaching(
            actors: FakeOrgActors,
            (mailer, mail): (FakeMailer, Arc<dyn MailSetup>),
            invited_at: OrganizationId,
        ) -> Self {
            let bob = invited_org_user(invited_at, BOB, OrgRole::Member);
            let bob_id = *bob.id();
            let invitations = Arc::new(FakeOrgInvitationStore::holding([pending_org_invitation(
                invited_at,
                bob_id,
                BOB,
                first_link(),
            )]));
            let mailer = Arc::new(mailer);
            Self {
                uc: ResendOrgUseCase::new(ResendOrgPorts {
                    org_user_store: Arc::new(org_user_store_with([bob])),
                    org_invitation_store: invitations.clone(),
                    org_actors: Arc::new(actors),
                    mailing: InvitationMailing {
                        mailer: mailer.clone(),
                        mail,
                        ..InvitationMailing::fakes()
                    },
                    ..ResendOrgPorts::fakes()
                }),
                bob: bob_id,
                invitations,
                mailer,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn new() -> Self {
            Self::with(
                FakeOrgActors::in_role(OrgRole::Owner),
                FakeMailer::new(),
                test_org_caller().organization_id(),
            )
        }

        fn resend(&self) -> Result<InvitationDelivery, AppError> {
            let request = ResendOrgRequest {
                org_user_id: self.bob,
                scope: test_org_link_scope(),
            };
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                request,
            ))
        }

        fn invitation_under(&self, hash: &TokenHash) -> Option<OrgInvitation> {
            let organization = test_org_caller().organization_id();
            block_on(self.invitations.find_by_token_hash(&organization, hash)).unwrap()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Olivia sends Bob's invitation again. It gets a new link, his old one
    /// stops working, the mail goes out and the resend is recorded.
    #[test]
    fn a_resend_rotates_the_link_mails_and_records() {
        let setup = Setup::new();

        setup.resend().unwrap();

        assert!(setup.invitation_under(&first_link()).is_none());
        assert!(
            setup
                .invitation_under(&TokenHash::from_stored("fake_hash_0".to_owned()))
                .is_some()
        );
        assert_eq!(setup.mailer.recipients(), vec![BOB.to_owned()]);
        assert_eq!(
            setup.recorded(),
            vec!["organization.org_user_invitation_resent"]
        );
    }

    /// The mail service refuses the resend. Olivia learns it, and the new
    /// link is kept and recorded so she can try again.
    #[test]
    fn a_refused_resend_mail_is_reported_and_the_resend_recorded() {
        let setup = Setup::with(
            FakeOrgActors::in_role(OrgRole::Owner),
            FakeMailer::refusing(),
            test_org_caller().organization_id(),
        );

        let result = setup.resend();

        assert!(matches!(result, Err(AppError::Upstream(_))));
        assert_eq!(
            setup.recorded(),
            vec!["organization.org_user_invitation_resent"]
        );
    }

    /// The resent link lasts as long as the policy says, from the resend.
    #[test]
    fn a_resent_invitation_lasts_the_configured_time_from_now() {
        let setup = Setup::new();
        let before = clock::now();

        setup.resend().unwrap();

        let lifetime = InvitationPolicy::fake().lifetime.duration();
        let invitation = setup
            .invitation_under(&TokenHash::from_stored("fake_hash_0".to_owned()))
            .unwrap();
        assert!(invitation.expires_at() >= before + lifetime);
        assert!(invitation.expires_at() <= clock::now() + lifetime);
    }

    /// Bob has no pending invitation. There is nothing to resend.
    #[test]
    fn a_member_without_a_pending_invitation_is_not_found() {
        let setup = Setup::new();
        let request = ResendOrgRequest {
            org_user_id: OrgUserId::new(),
            scope: test_org_link_scope(),
        };

        let result = block_on(setup.uc.execute(
            &test_org_caller(),
            &test_auditor(setup.audit.clone()),
            request,
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Another organization's invited member is not found for a resend,
    /// and no mail is sent.
    #[test]
    fn a_member_of_another_organization_is_not_found() {
        let setup = Setup::with(
            FakeOrgActors::in_role(OrgRole::Owner),
            FakeMailer::new(),
            OrganizationId::new(),
        );

        let result = setup.resend();

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.mailer.recipients().is_empty());
    }

    /// A member without invitation rights cannot resend an invitation,
    /// and no mail is sent.
    #[test]
    fn a_member_without_the_invite_right_is_refused() {
        let setup = Setup::with(
            FakeOrgActors::in_role(OrgRole::Member),
            FakeMailer::new(),
            test_org_caller().organization_id(),
        );

        let result = setup.resend();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.mailer.recipients().is_empty());
    }

    /// A signed-out session cannot authorize an invitation resend.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::with(
            FakeOrgActors::refusing(Refusal::SignedOut),
            FakeMailer::new(),
            test_org_caller().organization_id(),
        );

        let result = setup.resend();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// With a mail server set up, the new link is mailed and Olivia is
    /// handed nothing.
    #[test]
    fn a_mailed_resend_hands_over_no_link() {
        let setup = Setup::new();

        let delivery = setup.resend().unwrap();

        assert!(matches!(delivery, InvitationDelivery::Mailed));
    }

    /// Olivia sends Bob's invitation again on a deployment with no mail
    /// server. Nothing is mailed; she is handed the new link to pass on,
    /// and Bob's first link stops working.
    #[test]
    fn without_mail_the_new_link_is_handed_to_the_inviter() {
        let setup = Setup::without_mail();

        let delivery = setup.resend().unwrap();

        assert!(delivery.handed_over().is_some());
        assert_eq!(setup.mailer.count(), 0);
        assert!(setup.invitation_under(&first_link()).is_none());
    }

    /// An invitation cannot be resent when its address differs from the
    /// member's current address.
    #[test]
    fn an_invitation_to_an_address_the_member_left_is_refused() {
        let organization = test_org_caller().organization_id();
        let bob = invited_org_user(organization, "bob.new@acme.test", OrgRole::Member);
        let bob_id = *bob.id();
        let invitations = FakeOrgInvitationStore::holding([pending_org_invitation(
            organization,
            bob_id,
            BOB,
            first_link(),
        )]);
        let uc = ResendOrgUseCase::new(ResendOrgPorts {
            org_invitation_store: Arc::new(invitations),
            org_user_store: Arc::new(org_user_store_with([bob])),
            ..ResendOrgPorts::fakes()
        });
        let request = ResendOrgRequest {
            org_user_id: bob_id,
            scope: test_org_link_scope(),
        };

        let result = block_on(uc.execute(
            &test_org_caller(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            request,
        ));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}

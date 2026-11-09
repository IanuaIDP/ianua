//! Renewing an organization invitation from its own link: the invitee
//! holding a link that ran out asks for another, sent to the same address.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::organization::members::invitation::OrgInvitation;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::message;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, OrganizationId};

use crate::auditor::RequestAuditor;
use crate::email::{InvitationMailing, LinkScope, TokenResent};
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::limits::{MailPurpose, MailThrottle};
use crate::ports::organization::{OrgInvitationStore, OrgUserStore, OrganizationStore};
use crate::services::authentication::channels::{NO_INVITATION_RENEWALS, ensure_mail_reaches};
use crate::services::limits::mail_cooldown::ensure_mail_admitted;
use crate::use_case::Command;
use crate::use_cases::identity::renewal::renewed_link;
use crate::use_cases::organization::invitations::offers::link::InvitationLinks;
use crate::use_cases::organization::invitations::offers::mail::{
    OrgInvitationMail, deliver_org_invitation,
};
use crate::use_cases::organization::lookup::{existing_member, existing_organization};

/// The ports [`RenewOrgUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RenewOrgPorts {
    /// Loads the invited member.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// Loads and saves invitations.
    pub org_invitation_store: Arc<dyn OrgInvitationStore>,
    /// The organization the invitation is into, named in the mail.
    pub organization_store: Arc<dyn OrganizationStore>,
    /// Mails the new link under the invitation policy.
    pub mailing: InvitationMailing,
    /// Lets one invitation a minute through to an address.
    pub mail_throttle: Arc<dyn MailThrottle>,
    /// Makes and hashes invitation links.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// The dead invitation link to renew, by its token, and the pages the new
/// one opens.
pub struct RenewOrgRequest {
    /// The organization the invitation link names.
    pub organization_id: OrganizationId,
    /// The token from the link the invitee still holds.
    pub raw_token: String,
    /// Where the new link lands.
    pub scope: LinkScope,
}

/// Mails a new invitation link to the holder of one that ran out.
pub struct RenewOrgUseCase {
    ports: RenewOrgPorts,
}

impl RenewOrgUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RenewOrgPorts) -> Self {
        Self { ports }
    }

    /// The invitation the link `raw_token` of `organization_id` belongs to,
    /// whatever it is worth now.
    async fn followed(
        &self,
        organization_id: &OrganizationId,
        raw_token: &str,
    ) -> Result<OrgInvitation, AppError> {
        let links = InvitationLinks {
            invitations: self.ports.org_invitation_store.as_ref(),
            token_generator: self.ports.token_generator.as_ref(),
        };
        links
            .followed(organization_id, raw_token)
            .await?
            .or_not_found(message!(
                "identity-invalid-invitation-token",
                "invalid invitation token"
            ))
    }

    /// `invitation` renewed for `invitee` from the link `raw_token`, with
    /// the raw token of the new link.
    fn renewed(
        &self,
        invitation: &mut OrgInvitation,
        invitee: &OrgUser,
        raw_token: &str,
    ) -> Result<Secret, AppError> {
        let generator = self.ports.token_generator.as_ref();
        let presented = generator.hash_raw(raw_token);
        let (raw_link, renewed) = renewed_link(generator, self.ports.mailing.policy.lifetime)?;
        invitation
            .renew_from_link(invitee, &presented, renewed)
            .map_err(AppError::from_domain)?;
        Ok(raw_link)
    }
}

impl Command for RenewOrgUseCase {
    type Caller = ();
    type Input = RenewOrgRequest;
    type Output = Result<TokenResent, AppError>;

    /// Renews the invitation `request.raw_token` belongs to with a new link,
    /// records `organization.org_user_invitation_resent` and mails the link
    /// to the invited address, never one the caller names. Answers how long
    /// before another may be asked for.
    ///
    /// Only a link that ran out is renewed, and only while the invitation
    /// stands as it was sent: nobody withdrew it, and the member still
    /// waits to join at the invited address without having changed how
    /// they sign in.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` for a malformed token or accepted/declined/revoked invitation; `NotFound` for an unknown link or missing member/organization.
    /// - `AppError::Conflict` for a live link, a member no longer joining or changed sign-in credentials.
    /// - `AppError::Forbidden` for a changed invited address or no mail server, checked before lookup; without mail the inviter must resend.
    /// - `AppError::TooManyRequests` for mail within a minute; `Upstream` for refused mail; `Internal` on persistence, token or audit failure.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        request: RenewOrgRequest,
    ) -> Result<TokenResent, AppError> {
        ensure_mail_reaches(self.ports.mailing.mail.as_ref(), NO_INVITATION_RENEWALS)?;
        let organization_id = &request.organization_id;
        let mut invitation = self.followed(organization_id, &request.raw_token).await?;
        let organization =
            existing_organization(self.ports.organization_store.as_ref(), organization_id).await?;
        let members = self.ports.org_user_store.as_ref();
        let invitee = existing_member(members, organization_id, invitation.org_user_id()).await?;
        let raw_link = self.renewed(&mut invitation, &invitee, &request.raw_token)?;
        let throttle = self.ports.mail_throttle.as_ref();
        ensure_mail_admitted(throttle, MailPurpose::OrgInvitation, invitee.email()).await?;
        self.ports
            .org_invitation_store
            .save(&invitation)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*invitee.id()), invitation.take_events())
            .await
            .or_internal()?;
        let mail = OrgInvitationMail {
            invitee: &invitee,
            organization_name: organization.name().as_str(),
            raw_token: &raw_link,
            scope: &request.scope,
        };
        deliver_org_invitation(&self.ports.mailing, mail).await?;
        Ok(self.ports.mailing.policy.resend_cooldown.sent())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::TokenHash;

    use super::*;
    use crate::ports::shared::MailSetup;
    use crate::test_support::organization::{
        FakeOrgInvitationStore, expired_org_invitation, invited_org_user, org_store_with,
        org_user_store_with, pending_org_invitation, test_org,
    };
    use crate::test_support::{
        Fake, FakeEventDispatcher, FakeMailSetup, FakeMailer, block_on, test_auditor,
        test_org_caller, test_org_link_scope,
    };

    const BOB: &str = "bob@acme.test";
    const LINK: &str = "fake_refresh_7";

    /// The hash the link Bob holds carries.
    fn held_link() -> TokenHash {
        TokenHash::from_stored("fake_hash_7".to_owned())
    }

    struct Setup {
        uc: RenewOrgUseCase,
        mailer: Arc<FakeMailer>,
        audit: Arc<FakeEventDispatcher>,
    }

    /// Bob, invited to Acme, holding a link as `invitation` stands.
    fn holding(invitation: impl FnOnce(OrganizationId, &OrgUser) -> OrgInvitation) -> Setup {
        holding_reaching(Fake::fake(), invitation)
    }

    /// As [`holding`], on a deployment whose mail is set up as `mail` says.
    fn holding_reaching(
        mail: Arc<dyn MailSetup>,
        invitation: impl FnOnce(OrganizationId, &OrgUser) -> OrgInvitation,
    ) -> Setup {
        let acme = test_org_caller().organization_id();
        let bob = invited_org_user(acme, BOB, OrgRole::Member);
        let held = invitation(acme, &bob);
        let mailer = Arc::new(FakeMailer::new());
        Setup {
            uc: RenewOrgUseCase::new(RenewOrgPorts {
                org_user_store: Arc::new(org_user_store_with([bob])),
                org_invitation_store: Arc::new(FakeOrgInvitationStore::holding([held])),
                organization_store: org_store_with([test_org(acme, "acme")]),
                mailing: InvitationMailing {
                    mailer: mailer.clone(),
                    mail,
                    ..InvitationMailing::fakes()
                },
                ..RenewOrgPorts::fakes()
            }),
            mailer,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    impl Setup {
        fn renew(&self) -> Result<TokenResent, AppError> {
            block_on(self.uc.execute(
                &(),
                &test_auditor(self.audit.clone()),
                RenewOrgRequest {
                    organization_id: test_org_caller().organization_id(),
                    raw_token: LINK.to_owned(),
                    scope: test_org_link_scope(),
                },
            ))
        }
    }

    /// Bob opens his invitation a week late. A new link goes to his own
    /// address, and the resend is recorded as his.
    #[test]
    fn a_link_that_ran_out_is_renewed_and_mailed() {
        let setup = holding(|acme, bob| expired_org_invitation(acme, *bob.id(), BOB, held_link()));

        setup.renew().unwrap();

        assert_eq!(setup.mailer.recipients(), vec![BOB.to_owned()]);
        assert_eq!(
            *setup.audit.records.lock().unwrap(),
            ["organization.org_user_invitation_resent"]
        );
    }

    /// Without mail configured, renewal from an expired invitation link
    /// is forbidden and produces no email or audit record.
    #[test]
    fn without_mail_a_dead_link_is_not_renewed() {
        let setup = holding_reaching(FakeMailSetup::not_set_up(), |acme, bob| {
            expired_org_invitation(acme, *bob.id(), BOB, held_link())
        });

        let result = setup.renew();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.mailer.recipients().is_empty());
        assert!(setup.audit.records.lock().unwrap().is_empty());
    }

    /// Renewing a live invitation link conflicts and sends no replacement mail.
    #[test]
    fn a_link_that_still_works_is_not_renewed() {
        let setup = holding(|acme, bob| pending_org_invitation(acme, *bob.id(), BOB, held_link()));

        let result = setup.renew();

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(setup.mailer.recipients().is_empty());
    }

    /// An unknown invitation link is not found and sends no renewal email.
    #[test]
    fn an_unknown_link_renews_nothing() {
        let other = TokenHash::from_stored("another_hash".to_owned());
        let setup = holding(|acme, bob| expired_org_invitation(acme, *bob.id(), BOB, other));

        let result = setup.renew();

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.mailer.recipients().is_empty());
    }
}

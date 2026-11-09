//! Request org email change: a member of an organization asks to move their
//! own account to a new address. A link to confirm goes to the new address;
//! the account keeps its old one until the link is followed.
//!
//! The member proves who they are again first, so whoever stole their
//! session cannot move the address to their own mailbox.

use std::sync::Arc;

use ianua_domain::domains::authentication::sessions::fresh_sign_in::FreshSignIn;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::account::email_change::ChangingAccount;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, Email};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgUserStore;
use crate::ports::shared::{MailSetup, Mailer, OrgEmailChangeStore};
use crate::services::authentication::channels::{NO_EMAIL_CHANGES, ensure_mail_reaches};
use crate::services::authentication::fresh_proof::FreshProofs;
use crate::services::identity::address_free::ensure_member_address_free;
use crate::use_case::Command;
use crate::use_cases::identity::email::RequestChangeRequest;
use crate::use_cases::identity::email::changes::links::{
    ChangeMails, EmailChangePolicy, MailedIn, NewChange, ProvedAddress, mail_change_links,
    proved_change,
};

/// The ports [`RequestOrgChangeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RequestOrgChangePorts {
    /// Saves the pending change.
    pub change_store: Arc<dyn OrgEmailChangeStore>,
    /// Finds addresses another organization account already has.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// Who acts on the organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// Turns what the member typed again into a fresh proof of them.
    pub fresh_proofs: Arc<dyn FreshProofs>,
    /// Mails the confirmation link.
    pub mailer: Arc<dyn Mailer>,
    /// Whether anything can be mailed here at all.
    pub mail: Arc<dyn MailSetup>,
    /// Makes confirmation and cancel links.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// How long the link lasts and the address it is built on.
    pub policy: EmailChangePolicy,
}

/// Starts a change of the signed-in member's own address.
pub struct RequestOrgChangeUseCase {
    ports: RequestOrgChangePorts,
}

impl RequestOrgChangeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RequestOrgChangePorts) -> Self {
        Self { ports }
    }

    /// The change of `member`'s address to `new_email` they proved with
    /// `fresh`, and the raw links that confirm and stop it.
    fn pending_change(
        &self,
        member: &OrgUser,
        fresh: &FreshSignIn,
        new_email: Email,
    ) -> Result<NewChange, AppError> {
        proved_change(
            self.ports.token_generator.as_ref(),
            &self.ports.policy,
            ChangingAccount::from(member),
            ProvedAddress { new_email, fresh },
        )
    }

    /// Warns the current address of `asked` and mails the confirmation.
    async fn mail(&self, asked: &NewChange, mails: ChangeMails<'_>) -> Result<(), AppError> {
        mail_change_links(self.ports.mailer.as_ref(), &self.ports.policy, asked, mails).await
    }

    /// Refuses `email` when another member of `member`'s organization
    /// already has it. An account on it in another organization leaves it
    /// free.
    async fn ensure_address_free(&self, member: &OrgUser, email: &Email) -> Result<(), AppError> {
        let members = self.ports.org_user_store.as_ref();
        ensure_member_address_free(members, member.organization_id(), email).await
    }
}

impl Command for RequestOrgChangeUseCase {
    type Caller = OrgCaller;
    type Input = RequestChangeRequest;
    type Output = Result<(), AppError>;

    /// Records a change of the calling member's own address to
    /// `request.new_email` and mails a link to confirm it there.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for key-based callers or invalid sessions; `StepUpRequired` for a missing factor code.
    /// - `AppError::Forbidden` for inadequate fresh proof or no mail server, the latter checked before any other work.
    /// - `AppError::AccountLocked` after wrong codes; `Domain` for an unchanged address; `Conflict` for another member's address.
    /// - `AppError::Internal` on persistence or mail failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: RequestChangeRequest,
    ) -> Result<(), AppError> {
        ensure_mail_reaches(self.ports.mail.as_ref(), NO_EMAIL_CHANGES)?;
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        actor.signed_in()?;
        let member = actor.member();
        let fresh = self
            .ports
            .fresh_proofs
            .prove_member(member, &organization, request.proof, caller.origin())
            .await?;
        self.ensure_address_free(member, &request.new_email).await?;
        let mut asked = self.pending_change(member, &fresh, request.new_email)?;
        self.ports
            .change_store
            .save(&asked.change)
            .await
            .or_internal()?;
        let mails = ChangeMails {
            current: member.email(),
            mailed_in: MailedIn::Organization,
            scope: &request.scope,
            requested_from: caller.audit_context().ip_address().clone(),
        };
        self.mail(&asked, mails).await?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*member.id()), asked.change.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::{OrganizationId, Scope};

    use super::*;
    use crate::services::authentication::fresh_proof::ReenteredProof;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::authentication::{right_password, wrong_password};
    use crate::test_support::identity::FakeEmailChangeStore;
    use crate::test_support::organization::{FakeOrgUserStore, test_org_user};
    use crate::test_support::{
        FakeEventDispatcher, FakeMailSetup, FakeMailer, block_on, test_auditor, test_link_scope,
        test_org_caller,
    };

    const NEW_ADDRESS: &str = "new@acme.test";

    struct Fixture {
        changes: Arc<FakeEmailChangeStore>,
        mailer: Arc<FakeMailer>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn new() -> Self {
            Self::with_mailer(FakeMailer::new())
        }

        fn with_mailer(mailer: FakeMailer) -> Self {
            Self {
                changes: Arc::new(FakeEmailChangeStore::empty()),
                mailer: Arc::new(mailer),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn request_through(
            &self,
            ports: RequestOrgChangePorts,
            proof: ReenteredProof,
        ) -> Result<(), AppError> {
            let use_case = RequestOrgChangeUseCase::new(RequestOrgChangePorts {
                change_store: self.changes.clone(),
                mailer: self.mailer.clone(),
                ..ports
            });
            block_on(use_case.execute(
                &test_org_caller(),
                &test_auditor(self.sink.clone()),
                RequestChangeRequest {
                    new_email: Email::new(NEW_ADDRESS).unwrap(),
                    proof,
                    scope: test_link_scope(),
                },
            ))
        }

        fn request(&self, proof: ReenteredProof) -> Result<(), AppError> {
            self.request_through(RequestOrgChangePorts::fakes(), proof)
        }

        fn recorded(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    /// Owen types his password again and asks to move to a new address. The
    /// change waits, a warning goes to the address they have now, a link to confirm goes
    /// to the new address, and the
    /// request is recorded as a management account's.
    #[test]
    fn a_proved_request_waits_for_the_new_address_to_confirm() {
        let fixture = Fixture::new();

        fixture.request(right_password()).unwrap();

        assert_eq!(fixture.changes.count(), 1);
        let recipients = fixture.mailer.recipients();
        assert_eq!(recipients.len(), 2);
        assert_ne!(recipients[0], NEW_ADDRESS);
        assert_eq!(recipients[1], NEW_ADDRESS);
        assert_eq!(
            fixture.recorded(),
            vec!["identity.management_email_change_requested"]
        );
    }

    /// Without a mail server, an organization email-change request is
    /// refused before saving a change, sending mail or recording an event.
    #[test]
    fn a_change_is_refused_where_nothing_is_mailed() {
        let fixture = Fixture::new();
        let ports = RequestOrgChangePorts {
            mail: FakeMailSetup::not_set_up(),
            ..RequestOrgChangePorts::fakes()
        };

        let result = fixture.request_through(ports, right_password());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.changes.count(), 0);
        assert_eq!(fixture.mailer.count(), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// Mallory holds Owen's session and password and asks to move the account
    /// to her own mailbox. Owen's current address is warned first, naming the
    /// address asked for and carrying the link that stops the change.
    #[test]
    fn the_current_address_is_warned_with_a_link_that_stops_the_change() {
        let fixture = Fixture::new();

        fixture.request(right_password()).unwrap();

        let sent = fixture.mailer.sent.lock().unwrap();
        let warning = &sent[0];
        assert_eq!(warning.template, EmailTemplateType::OrgEmailChangeRequested);
        assert_eq!(
            warning
                .variables
                .get(&TemplateVariable::UserEmail)
                .map(String::as_str),
            Some(NEW_ADDRESS)
        );
        assert!(warning.variables[&TemplateVariable::ActionUrl].contains("cancel-email-change"));
    }

    /// Failure to mail the warning to the current address returns an
    /// internal error from the organization email-change request.
    #[test]
    fn no_change_is_asked_for_when_the_warning_cannot_be_sent() {
        let fixture = Fixture::with_mailer(FakeMailer::refusing());

        let result = fixture.request(right_password());

        assert!(matches!(result, Err(AppError::Internal(_))));
    }

    /// A wrong password prevents an organization email change despite an
    /// active session. No change is saved and no mail is sent.
    #[test]
    fn a_wrong_password_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.request(wrong_password());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.changes.count(), 0);
        assert_eq!(fixture.mailer.count(), 0);
    }

    /// A signed-out member cannot request an email change, and no change
    /// is saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::new();
        let ports = RequestOrgChangePorts {
            org_actors: Arc::new(FakeOrgActors::refusing(Refusal::SignedOut)),
            ..RequestOrgChangePorts::fakes()
        };

        let result = fixture.request_through(ports, right_password());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.changes.count(), 0);
    }

    /// An organization key cannot substitute for a member's session when
    /// requesting an email change. No change is saved.
    #[test]
    fn a_caller_acting_through_a_key_is_refused() {
        let fixture = Fixture::new();
        let ports = RequestOrgChangePorts {
            org_actors: Arc::new(FakeOrgActors::through_key(
                OrgRole::Member,
                Vec::<Scope>::new(),
            )),
            ..RequestOrgChangePorts::fakes()
        };

        let result = fixture.request_through(ports, right_password());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.changes.count(), 0);
    }

    /// Owen's change, through a member store holding `other`.
    fn requested_beside(fixture: &Fixture, other: &OrgUser) -> Result<(), AppError> {
        let members = FakeOrgUserStore::empty();
        block_on(members.save(other)).unwrap();
        let ports = RequestOrgChangePorts {
            org_user_store: Arc::new(members),
            ..RequestOrgChangePorts::fakes()
        };
        fixture.request_through(ports, right_password())
    }

    /// An address held by another member of the same organization conflicts
    /// with the requested change, and no mail is sent.
    #[test]
    fn an_address_another_member_has_is_refused() {
        let fixture = Fixture::new();
        let acme = test_org_caller().organization_id();
        let other = test_org_user(acme, NEW_ADDRESS, OrgRole::Member);

        let result = requested_beside(&fixture, &other);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(fixture.mailer.count(), 0);
    }

    /// Owen asks to move to an address an account of another organization
    /// has. An address is unique within an organization only, so the
    /// change waits for its link.
    #[test]
    fn an_address_held_in_another_organization_is_free() {
        let fixture = Fixture::new();
        let other = test_org_user(OrganizationId::new(), NEW_ADDRESS, OrgRole::Member);

        let result = requested_beside(&fixture, &other);

        assert!(result.is_ok());
    }
}

//! Request email change: a tenant user asks to move their own account to a
//! new address. A link to confirm goes to the new address; the account keeps
//! its old one until the link is followed.
//!
//! Asking for a change needs more than an open session: the person proves
//! who they are again, so whoever stole one cannot move the address to
//! their own mailbox.
//!
//! It is a tenant user's change, so it records the tenant's event. A member
//! of an organization asks through
//! [`RequestOrgChangeUseCase`](crate::use_cases::identity::email::RequestOrgChangeUseCase),
//! which records a management account's.

use std::sync::Arc;

use ianua_domain::domains::authentication::sessions::fresh_sign_in::FreshSignIn;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::account::email_change::ChangingAccount;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::Email;

use crate::acting::TenantAuthorities;
use crate::acting::tenant::SignedInAccount;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserStore;
use crate::ports::shared::{MailSetup, Mailer, TenantEmailChangeStore};
use crate::services::authentication::channels::{NO_EMAIL_CHANGES, ensure_mail_reaches};
use crate::services::authentication::fresh_proof::{FreshProofs, ReenteredProof, proved_person};
use crate::services::identity::address_free::ensure_email_free;
use crate::use_case::Command;
use crate::use_cases::identity::email::changes::links::{
    ChangeMails, EmailChangePolicy, MailedIn, NewChange, ProvedAddress, mail_change_links,
    proved_change,
};

/// The ports [`RequestChangeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RequestChangePorts {
    /// Saves the pending change.
    pub change_store: Arc<dyn TenantEmailChangeStore>,
    /// Finds addresses already taken.
    pub user_store: Arc<dyn UserStore>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Turns what the person typed again into a fresh proof of them.
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

/// The address the signed-in person wants, and their proof that it is them.
pub struct RequestChangeRequest {
    /// The address they want.
    pub new_email: Email,
    /// Their password, and a code from their second factor when they have
    /// one, typed again.
    pub proof: ReenteredProof,
    /// Where the confirmation link lands.
    pub scope: LinkScope,
}

/// Starts a change of the signed-in person's own address.
pub struct RequestChangeUseCase {
    ports: RequestChangePorts,
}

impl RequestChangeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RequestChangePorts) -> Self {
        Self { ports }
    }

    /// Warns the current address of `asked` and mails the confirmation.
    async fn mail(&self, asked: &NewChange, mails: ChangeMails<'_>) -> Result<(), AppError> {
        mail_change_links(self.ports.mailer.as_ref(), &self.ports.policy, asked, mails).await
    }

    /// The change of `person`'s address to `new_email` they proved with
    /// `fresh`, and the raw links that confirm and stop it.
    fn pending_change(
        &self,
        person: &SignedInAccount,
        fresh: &FreshSignIn,
        new_email: Email,
    ) -> Result<NewChange, AppError> {
        proved_change(
            self.ports.token_generator.as_ref(),
            &self.ports.policy,
            ChangingAccount::from(&person.account),
            ProvedAddress { new_email, fresh },
        )
    }
}

impl Command for RequestChangeUseCase {
    type Caller = CallerContext;
    type Input = RequestChangeRequest;
    type Output = Result<(), AppError>;

    /// Records a change of the caller's own address to `request.new_email`,
    /// warns the address they have now with a link that stops it, and mails
    /// a link to confirm it to the new one.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with no tenant
    ///   session, or it no longer counts.
    /// - `AppError::Forbidden` when the re-entered proof does not prove the
    ///   person, or the deployment has no mail server, so the new address
    ///   could never be confirmed. That comes first, before anything is
    ///   checked or kept.
    /// - `AppError::Domain` when the new address is the one they have.
    /// - `AppError::Conflict` when another user already has it.
    /// - `AppError::Internal` on persistence or mail failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: RequestChangeRequest,
    ) -> Result<(), AppError> {
        ensure_mail_reaches(self.ports.mail.as_ref(), NO_EMAIL_CHANGES)?;
        let tenant = ctx.tenant();
        let (person, fresh) = proved_person(
            self.ports.tenant_authorities.as_ref(),
            self.ports.fresh_proofs.as_ref(),
            ctx,
            request.proof,
        )
        .await?;
        ensure_email_free(self.ports.user_store.as_ref(), &tenant, &request.new_email).await?;
        let mut asked = self.pending_change(&person, &fresh, request.new_email)?;
        self.ports
            .change_store
            .save(&tenant, &asked.change)
            .await
            .or_internal()?;
        self.mail(&asked, change_mails(ctx, &person, &request.scope))
            .await?;
        auditor
            .dispatch_by(&ctx.actor(), asked.change.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// Where the mails of the change `person` asked for in `ctx`'s request go:
/// to them, in their tenant's branding and the language they read.
fn change_mails<'a>(
    ctx: &CallerContext,
    person: &'a SignedInAccount,
    scope: &'a LinkScope,
) -> ChangeMails<'a> {
    ChangeMails {
        current: person.account.email(),
        mailed_in: MailedIn::Tenant {
            tenant: ctx.tenant(),
            locale: person.account.locale(),
        },
        scope,
        requested_from: ctx.audit_context().ip_address().clone(),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{right_password, wrong_password};
    use crate::test_support::identity::{FakeEmailChangeStore, FakeUserStore};
    use crate::test_support::{
        FakeEventDispatcher, FakeMailSetup, FakeMailer, block_on, test_auditor, test_ctx,
        test_link_scope,
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
            ports: RequestChangePorts,
            proof: ReenteredProof,
        ) -> Result<(), AppError> {
            let use_case = RequestChangeUseCase::new(RequestChangePorts {
                change_store: self.changes.clone(),
                mailer: self.mailer.clone(),
                ..ports
            });
            block_on(use_case.execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                RequestChangeRequest {
                    new_email: Email::new(NEW_ADDRESS).unwrap(),
                    proof,
                    scope: test_link_scope(),
                },
            ))
        }

        fn request(&self, proof: ReenteredProof) -> Result<(), AppError> {
            self.request_through(RequestChangePorts::fakes(), proof)
        }

        fn recorded(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    /// Ann types her password again and asks to move to a new address. The
    /// change waits, a warning goes to the address they have now, a link to confirm goes
    /// to the new address, and the
    /// request is recorded.
    #[test]
    fn a_proved_request_waits_for_the_new_address_to_confirm() {
        let fixture = Fixture::new();

        fixture.request(right_password()).unwrap();

        assert_eq!(fixture.changes.count(), 1);
        let recipients = fixture.mailer.recipients();
        assert_eq!(recipients.len(), 2);
        assert_ne!(recipients[0], NEW_ADDRESS);
        assert_eq!(recipients[1], NEW_ADDRESS);
        assert_eq!(fixture.recorded(), vec!["identity.email_change_requested"]);
    }

    /// Mallory holds Ann's session and password and asks to move the account
    /// to her own mailbox. Ann's current address is warned first, naming the
    /// address asked for and carrying the link that stops the change.
    #[test]
    fn the_current_address_is_warned_with_a_link_that_stops_the_change() {
        let fixture = Fixture::new();

        fixture.request(right_password()).unwrap();

        let sent = fixture.mailer.sent.lock().unwrap();
        let warning = &sent[0];
        assert_eq!(warning.template, EmailTemplateType::EmailChangeRequested);
        assert_eq!(
            warning
                .variables
                .get(&TemplateVariable::UserEmail)
                .map(String::as_str),
            Some(NEW_ADDRESS)
        );
        assert!(warning.variables[&TemplateVariable::ActionUrl].contains("cancel-email-change"));
    }

    /// Without a mail server, an email-change request is refused before
    /// saving a change, sending mail or recording an event.
    #[test]
    fn a_change_is_refused_where_nothing_is_mailed() {
        let fixture = Fixture::new();
        let ports = RequestChangePorts {
            mail: FakeMailSetup::not_set_up(),
            ..RequestChangePorts::fakes()
        };

        let result = fixture.request_through(ports, right_password());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.changes.count(), 0);
        assert_eq!(fixture.mailer.count(), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// Failure to mail the warning to the current address returns an
    /// internal error from the email-change request.
    #[test]
    fn no_change_is_asked_for_when_the_warning_cannot_be_sent() {
        let fixture = Fixture::with_mailer(FakeMailer::refusing());

        let result = fixture.request(right_password());

        assert!(matches!(result, Err(AppError::Internal(_))));
    }

    /// A wrong password prevents the requested email change despite an
    /// active session. No change is saved and no mail is sent.
    #[test]
    fn a_wrong_password_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.request(wrong_password());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.changes.count(), 0);
        assert_eq!(fixture.mailer.count(), 0);
    }

    /// A signed-out caller cannot request an email change, and no change
    /// is saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::new();
        let ports = RequestChangePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..RequestChangePorts::fakes()
        };

        let result = fixture.request_through(ports, right_password());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.changes.count(), 0);
    }

    /// An address held by another tenant user conflicts with the requested
    /// email change, and no mail is sent.
    #[test]
    fn an_address_another_user_has_is_refused() {
        let fixture = Fixture::new();
        let ports = RequestChangePorts {
            user_store: Arc::new(FakeUserStore::with_user(UserId::new(), NEW_ADDRESS)),
            ..RequestChangePorts::fakes()
        };

        let result = fixture.request_through(ports, right_password());

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(fixture.mailer.count(), 0);
    }
}

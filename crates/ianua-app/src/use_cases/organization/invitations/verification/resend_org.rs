//! Resend org verification: someone who cannot sign in yet asks for another
//! link for an address in one organization.

use ianua_domain::types::{Email, OrganizationId};

use crate::auditor::RequestAuditor;
use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::services::authentication::channels::NO_CONFIRMATION_LINKS;
use crate::use_case::Command;
use crate::use_cases::organization::invitations::verification::mail::{
    OrgVerificationMail, VerificationLink,
};

/// The address to send another link to, and the pages it opens.
pub struct ResendOrgVerificationRequest {
    /// The organization whose sign-in page asks.
    pub organization_id: OrganizationId,
    /// The address the member signed up with.
    pub email: Email,
    /// Where the link lands.
    pub scope: LinkScope,
}

/// Mails another link to whoever holds an address in one organization.
pub struct ResendOrgVerificationUseCase {
    ports: OrgVerificationMail,
}

impl ResendOrgVerificationUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: OrgVerificationMail) -> Self {
        Self { ports }
    }
}

impl Command for ResendOrgVerificationUseCase {
    type Caller = ();
    type Input = ResendOrgVerificationRequest;
    type Output = Result<(), AppError>;

    /// Mails a new link to whoever holds `request.email` in
    /// `organization_id`, unless their address is already confirmed or
    /// their last link went out within the wait between links.
    ///
    /// The person asking cannot sign in, which is why they ask, so this
    /// takes no caller and must not tell whether the address is registered:
    /// it answers the same either way, and the link goes only to the address
    /// on the account. Anyone may ask, so a resend held back by the wait
    /// answers the same too. A link that goes out records
    /// `organization.org_verification_email_sent`.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` on a deployment with no mail server, before
    ///   any member is looked up, so every address is answered alike.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        request: ResendOrgVerificationRequest,
    ) -> Result<(), AppError> {
        self.ports.ensure_mailable(NO_CONFIRMATION_LINKS)?;
        let organization_id = &request.organization_id;
        let found = self
            .ports
            .org_user_store
            .find_by_email(organization_id, &request.email)
            .await
            .or_internal()?;
        let Some(member) = found else {
            return Ok(());
        };
        let link = VerificationLink {
            member: &member,
            scope: &request.scope,
        };
        let events = self.ports.send_after_wait(link).await?;
        auditor.dispatch(&events).await.or_internal()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::ports::shared::MailSetup;
    use crate::test_support::organization::{org_user_store_with, unconfirmed_org_user};
    use crate::test_support::{
        Fake, FakeEventDispatcher, FakeMailSetup, FakeMailer, block_on, test_auditor,
        test_org_link_scope,
    };

    /// Fiona of Acme, whose address is not confirmed yet.
    struct Setup {
        uc: ResendOrgVerificationUseCase,
        organization_id: OrganizationId,
        mailer: Arc<FakeMailer>,
    }

    fn setup() -> Setup {
        setup_reaching(Fake::fake())
    }

    /// As [`setup`], on a deployment whose mail is set up as `mail` says.
    fn setup_reaching(mail: Arc<dyn MailSetup>) -> Setup {
        let organization_id = OrganizationId::new();
        let fiona = unconfirmed_org_user(organization_id, "fiona@acme.test");
        let mailer = Arc::new(FakeMailer::new());
        Setup {
            uc: ResendOrgVerificationUseCase::new(OrgVerificationMail {
                org_user_store: Arc::new(org_user_store_with([fiona])),
                mailer: mailer.clone(),
                mail,
                ..OrgVerificationMail::fakes()
            }),
            organization_id,
            mailer,
        }
    }

    /// Without mail configured, a verification resend is forbidden and
    /// sends no message.
    #[test]
    fn no_link_is_sent_where_nothing_is_mailed() {
        let setup = setup_reaching(FakeMailSetup::not_set_up());

        let result = resend(&setup, "fiona@acme.test");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.mailer.count(), 0);
    }

    fn resend(setup: &Setup, email: &str) -> Result<(), AppError> {
        let request = ResendOrgVerificationRequest {
            organization_id: setup.organization_id,
            email: Email::new(email).unwrap(),
            scope: test_org_link_scope(),
        };
        block_on(setup.uc.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            request,
        ))
    }

    /// Fiona cannot sign in until she confirms her address, and asks for
    /// another link. It goes to her address.
    #[test]
    fn a_registered_address_is_sent_another_link() {
        let setup = setup();

        resend(&setup, "fiona@acme.test").unwrap();

        assert_eq!(
            setup.mailer.recipients(),
            vec!["fiona@acme.test".to_owned()]
        );
    }

    /// An unknown address receives the usual successful response without mail.
    #[test]
    fn an_unknown_address_answers_the_same_and_sends_nothing() {
        let setup = setup();

        resend(&setup, "nobody@acme.test").unwrap();

        assert_eq!(setup.mailer.count(), 0);
    }

    /// A second request within the resend cooldown succeeds without sending
    /// another verification email.
    #[test]
    fn asking_again_before_the_wait_sends_nothing_and_answers_the_same() {
        let setup = setup();
        resend(&setup, "fiona@acme.test").unwrap();

        let again = resend(&setup, "fiona@acme.test");

        assert!(again.is_ok());
        assert_eq!(setup.mailer.count(), 1);
    }
}

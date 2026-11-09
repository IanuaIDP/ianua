//! Resend org verification by email: someone who cannot sign in yet, and
//! does not know their organization's address, asks for another link.

use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::types::Email;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::services::authentication::channels::NO_CONFIRMATION_LINKS;
use crate::use_case::Command;
use crate::use_cases::organization::invitations::verification::mail::{
    OrgVerificationMail, VerificationLink,
};

/// Mails another link to whoever holds an address, in every organization.
pub struct ResendOrgVerificationByEmailUseCase {
    ports: OrgVerificationMail,
}

impl ResendOrgVerificationByEmailUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: OrgVerificationMail) -> Self {
        Self { ports }
    }

    /// Mails `member` another link, landing on their own organization's
    /// pages, and hands back what it recorded. A member whose organization
    /// is gone, or whose last link is too recent, is sent nothing.
    async fn sent_to(&self, member: &OrgUser) -> Result<Vec<DomainEvent>, AppError> {
        let Some(scope) = self.ports.pages_of(member).await? else {
            return Ok(Vec::new());
        };
        let link = VerificationLink {
            member,
            scope: &scope,
        };
        self.ports.send_after_wait(link).await
    }
}

impl Command for ResendOrgVerificationByEmailUseCase {
    type Caller = ();
    type Input = Email;
    type Output = Result<(), AppError>;

    /// Mails a new link to each member holding `email`, in whichever
    /// organizations they are, landing on their own organization's pages.
    ///
    /// An unconfirmed member cannot sign in, so they may not know their
    /// organization's address; an address may hold an account in several
    /// organizations, and each unconfirmed one gets its own link. It answers
    /// the same whether or not the address is registered, and a confirmed
    /// address is sent nothing. Anyone may ask, so a member whose last link
    /// went out within the wait between links is sent nothing either, with
    /// the same answer. A link that goes out records
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
        email: Email,
    ) -> Result<(), AppError> {
        self.ports.ensure_mailable(NO_CONFIRMATION_LINKS)?;
        let members = self
            .ports
            .org_user_store
            .find_all_by_email(&email)
            .await
            .or_internal()?;
        for member in &members {
            let events = self.sent_to(member).await?;
            auditor.dispatch(&events).await.or_internal()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::branding::email_template::TemplateVariable;
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::test_support::organization::{
        org_store_with, org_user_store_with, test_org, unconfirmed_org_user,
    };
    use crate::test_support::{FakeEventDispatcher, FakeMailer, block_on, test_auditor};

    /// Fiona of Globex, whose address is not confirmed yet.
    fn fionas_globex(mailer: &Arc<FakeMailer>) -> ResendOrgVerificationByEmailUseCase {
        let organization_id = OrganizationId::new();
        let fiona = unconfirmed_org_user(organization_id, "fiona@globex.test");
        ResendOrgVerificationByEmailUseCase::new(OrgVerificationMail {
            org_user_store: Arc::new(org_user_store_with([fiona])),
            organization_store: org_store_with([test_org(organization_id, "globex")]),
            mailer: mailer.clone(),
            ..OrgVerificationMail::fakes()
        })
    }

    fn ask(uc: &ResendOrgVerificationByEmailUseCase, email: &str) -> Result<(), AppError> {
        block_on(uc.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            Email::new(email).unwrap(),
        ))
    }

    fn resend(email: &str) -> Arc<FakeMailer> {
        let mailer = Arc::new(FakeMailer::new());
        ask(&fionas_globex(&mailer), email).unwrap();
        mailer
    }

    /// Fiona asks for another link with only her address. It goes to her,
    /// landing on Globex's own pages.
    #[test]
    fn the_link_lands_on_the_members_own_organization() {
        let mailer = resend("fiona@globex.test");

        let link = mailer.sent.lock().unwrap()[0]
            .variables
            .get(&TemplateVariable::ActionUrl)
            .cloned()
            .unwrap();
        assert!(link.contains("globex"), "{link}");
    }

    /// An unknown address receives the usual successful response without mail.
    #[test]
    fn an_unknown_address_answers_the_same_and_sends_nothing() {
        let mailer = resend("nobody@globex.test");

        assert_eq!(mailer.count(), 0);
    }

    /// A second request within the resend cooldown succeeds without sending
    /// another verification email.
    #[test]
    fn asking_again_before_the_wait_sends_nothing_and_answers_the_same() {
        let mailer = Arc::new(FakeMailer::new());
        let uc = fionas_globex(&mailer);
        ask(&uc, "fiona@globex.test").unwrap();

        let again = ask(&uc, "fiona@globex.test");

        assert!(again.is_ok());
        assert_eq!(mailer.count(), 1);
    }
}

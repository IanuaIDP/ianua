//! Send org activation welcome: tell a member who just finished joining, by
//! confirming their address or accepting an invitation, that it worked.

use ianua_domain::domains::branding::email_template::EmailTemplateType;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::types::OrgUserId;

use crate::auditor::RequestAuditor;
use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::use_case::Command;
use crate::use_cases::organization::invitations::welcome::mail::{
    OrgWelcome, OrgWelcomePorts, mail_org_welcome, welcome_record,
};

/// Welcomes a member who has just become active.
pub struct SendOrgActivationWelcomeUseCase {
    ports: OrgWelcomePorts,
}

impl SendOrgActivationWelcomeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: OrgWelcomePorts) -> Self {
        Self { ports }
    }

    /// The member `org_user_id` with the sign-in pages of their own
    /// organization, or nothing once either is gone.
    async fn member_and_pages(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Option<(OrgUser, LinkScope)>, AppError> {
        let Some(member) = self
            .ports
            .org_user_store
            .find_by_id(org_user_id)
            .await
            .or_internal()?
        else {
            return Ok(None);
        };
        let organization = self
            .ports
            .organization_store
            .find_by_id(member.organization_id())
            .await
            .or_internal()?;
        Ok(organization
            .map(|organization| LinkScope::organization(organization.slug().clone()))
            .map(|scope| (member, scope)))
    }
}

impl Command for SendOrgActivationWelcomeUseCase {
    type Caller = ();
    type Input = OrgUserId;
    type Output = Result<(), AppError>;

    /// Tells `org_user_id`, who did the last step themselves, that their
    /// account is ready, with a sign-in link to their own organization.
    /// Records `organization.org_welcome_email_sent` once the mail is
    /// accepted.
    ///
    /// It follows the member's own step, which the composing flow has just
    /// checked, so it needs no caller of its own. That step happens on a
    /// public page that knows only a token, so the organization is read from
    /// the member.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` if the member or organization lookup fails or
    ///   the event cannot be recorded.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        org_user_id: OrgUserId,
    ) -> Result<(), AppError> {
        let Some((member, scope)) = self.member_and_pages(&org_user_id).await? else {
            return Ok(());
        };
        let welcome = OrgWelcome {
            member: &member,
            scope: &scope,
            template: EmailTemplateType::ActivationWelcome,
        };
        let mailed = mail_org_welcome(&self.ports, welcome).await;
        auditor
            .dispatch(&welcome_record(&member, mailed))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::branding::email_template::TemplateVariable;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::test_support::organization::{
        org_store_with, org_user_store_with, test_org, test_org_user,
    };
    use crate::test_support::{FakeEventDispatcher, FakeMailer, block_on, test_auditor};

    /// Dana just joined Globex. She is sent to Globex's own sign-in, and the
    /// welcome is recorded.
    #[test]
    fn a_member_who_just_joined_is_sent_to_their_own_organizations_sign_in() {
        let organization = OrganizationId::new();
        let dana = test_org_user(organization, "dana@globex.test", OrgRole::Member);
        let dana_id = *dana.id();
        let mailer = Arc::new(FakeMailer::new());
        let audit = Arc::new(FakeEventDispatcher::new());
        let uc = SendOrgActivationWelcomeUseCase::new(OrgWelcomePorts {
            org_user_store: Arc::new(org_user_store_with([dana])),
            organization_store: org_store_with([test_org(organization, "globex")]),
            mailer: mailer.clone(),
            ..OrgWelcomePorts::fakes()
        });

        block_on(uc.execute(&(), &test_auditor(audit.clone()), dana_id)).unwrap();

        let sent = mailer.sent.lock().unwrap();
        assert_eq!(sent[0].template, EmailTemplateType::ActivationWelcome);
        assert_eq!(
            sent[0]
                .variables
                .get(&TemplateVariable::ActionUrl)
                .map(String::as_str),
            Some("https://app.test/login?org=globex")
        );
        assert_eq!(
            audit.records.lock().unwrap().clone(),
            vec!["organization.org_welcome_email_sent"]
        );
    }

    /// A member who is gone is no error, and nothing is sent.
    #[test]
    fn an_unknown_member_is_not_an_error() {
        let mailer = Arc::new(FakeMailer::new());
        let uc = SendOrgActivationWelcomeUseCase::new(OrgWelcomePorts {
            mailer: mailer.clone(),
            ..OrgWelcomePorts::fakes()
        });

        let result = block_on(uc.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            OrgUserId::new(),
        ));

        assert!(result.is_ok());
        assert_eq!(mailer.count(), 0);
    }

    /// The mail service refuses the welcome. It is no error, and nothing is
    /// recorded.
    #[test]
    fn a_refused_welcome_records_nothing() {
        let organization = OrganizationId::new();
        let dana = test_org_user(organization, "dana@globex.test", OrgRole::Member);
        let dana_id = *dana.id();
        let audit = Arc::new(FakeEventDispatcher::new());
        let uc = SendOrgActivationWelcomeUseCase::new(OrgWelcomePorts {
            org_user_store: Arc::new(org_user_store_with([dana])),
            organization_store: org_store_with([test_org(organization, "globex")]),
            mailer: Arc::new(FakeMailer::refusing()),
            ..OrgWelcomePorts::fakes()
        });

        block_on(uc.execute(&(), &test_auditor(audit.clone()), dana_id)).unwrap();

        assert!(audit.records.lock().unwrap().is_empty());
    }
}

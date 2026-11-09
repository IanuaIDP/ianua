//! Send org welcome: tell a member an owner made an account for them, and
//! where to sign in.
//!
//! An account let in at once is one its owner has never heard of. This is
//! the notice. It carries a sign-in link and no secret.

use std::sync::Arc;

use ianua_domain::domains::branding::email_template::EmailTemplateType;
use ianua_domain::domains::organization::members::permission::{MemberAction, OrgPermission};
use ianua_domain::types::OrgUserId;

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::use_case::Command;
use crate::use_cases::organization::invitations::welcome::mail::{
    OrgWelcome, OrgWelcomePorts, mail_org_welcome, welcome_record,
};

/// The ports [`SendOrgWelcomeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SendOrgWelcomePorts {
    /// Where the mail reads its member and organization from, and how it
    /// goes.
    pub welcome: OrgWelcomePorts,
    /// Who acts on the organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Who to welcome, and the pages the sign-in link opens.
pub struct SendOrgWelcomeRequest {
    /// The member being welcomed.
    pub org_user_id: OrgUserId,
    /// Where the sign-in link lands.
    pub scope: LinkScope,
}

/// Welcomes a member an owner just made an account for.
pub struct SendOrgWelcomeUseCase {
    ports: SendOrgWelcomePorts,
}

impl SendOrgWelcomeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SendOrgWelcomePorts) -> Self {
        Self { ports }
    }
}

impl Command for SendOrgWelcomeUseCase {
    type Caller = OrgCaller;
    type Input = SendOrgWelcomeRequest;
    type Output = Result<(), AppError>;

    /// Mails `request.org_user_id`, a member of the caller's organization,
    /// that their account exists and where to sign in, for a caller who may
    /// add members. Records `organization.org_welcome_email_sent` once the
    /// mail is accepted.
    ///
    /// A member who is gone, or a refused send, is no error: the account was
    /// made a moment ago, and failing here would fail what succeeded.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not add members.
    /// - `AppError::Internal` if the member lookup fails or the event cannot
    ///   be recorded.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: SendOrgWelcomeRequest,
    ) -> Result<(), AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        actor
            .control()?
            .ensure_may(
                organization.id(),
                OrgPermission::Members(MemberAction::Create),
            )
            .map_err(AppError::from_domain)?;
        let members = self.ports.welcome.org_user_store.as_ref();
        let found = members
            .find_by_id_in_org(organization.id(), &request.org_user_id)
            .await
            .or_internal()?;
        let Some(member) = found else {
            return Ok(());
        };
        let welcome = OrgWelcome {
            member: &member,
            scope: &request.scope,
            template: EmailTemplateType::OrgWelcome,
        };
        let mailed = mail_org_welcome(&self.ports.welcome, welcome).await;
        auditor
            .dispatch(&welcome_record(&member, mailed))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::branding::email_template::TemplateVariable;
    use ianua_domain::domains::organization::members::membership::OrgRole;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        org_store_with, org_user_store_with, test_org, test_org_user,
    };
    use crate::test_support::{
        FakeEventDispatcher, FakeMailer, block_on, test_auditor, test_org_caller,
        test_org_link_scope,
    };

    struct Setup {
        uc: SendOrgWelcomeUseCase,
        dana: OrgUserId,
        mailer: Arc<FakeMailer>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn with(actors: FakeOrgActors) -> Self {
            let organization = test_org_caller().organization_id();
            let dana = test_org_user(organization, "dana@acme.test", OrgRole::Member);
            let dana_id = *dana.id();
            let mailer = Arc::new(FakeMailer::new());
            Self {
                uc: SendOrgWelcomeUseCase::new(SendOrgWelcomePorts {
                    welcome: OrgWelcomePorts {
                        org_user_store: Arc::new(org_user_store_with([dana])),
                        organization_store: org_store_with([test_org(organization, "acme")]),
                        mailer: mailer.clone(),
                        ..OrgWelcomePorts::fakes()
                    },
                    org_actors: Arc::new(actors),
                }),
                dana: dana_id,
                mailer,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn welcome(&self, member: OrgUserId) -> Result<(), AppError> {
            let request = SendOrgWelcomeRequest {
                org_user_id: member,
                scope: test_org_link_scope(),
            };
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                request,
            ))
        }
    }

    /// Olivia made an account for Dana. Dana is mailed where to sign in,
    /// under Acme's name, and the welcome is recorded.
    #[test]
    fn a_member_an_owner_created_is_told_where_to_sign_in() {
        let setup = Setup::with(FakeOrgActors::in_role(OrgRole::Owner));

        setup.welcome(setup.dana).unwrap();

        let sent = setup.mailer.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, "dana@acme.test");
        assert_eq!(sent[0].template, EmailTemplateType::OrgWelcome);
        assert_eq!(
            sent[0]
                .variables
                .get(&TemplateVariable::ActionUrl)
                .map(String::as_str),
            Some("https://app.test/login?org=acme")
        );
        assert_eq!(
            sent[0]
                .variables
                .get(&TemplateVariable::OrganizationName)
                .map(String::as_str),
            Some("Acme")
        );
        assert_eq!(
            setup.audit.records.lock().unwrap().clone(),
            vec!["organization.org_welcome_email_sent"]
        );
    }

    /// Olivia names a member who is gone. It is no error, and nothing is
    /// sent.
    #[test]
    fn an_unknown_member_is_not_an_error() {
        let setup = Setup::with(FakeOrgActors::in_role(OrgRole::Owner));

        let result = setup.welcome(OrgUserId::new());

        assert!(result.is_ok());
        assert_eq!(setup.mailer.count(), 0);
    }

    /// A member without creation rights cannot send another member a
    /// welcome email, and no message is sent.
    #[test]
    fn a_member_without_the_create_right_is_refused() {
        let setup = Setup::with(FakeOrgActors::in_role(OrgRole::Member));

        let result = setup.welcome(setup.dana);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.mailer.count(), 0);
    }

    /// A signed-out session cannot authorize a welcome email.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::with(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = setup.welcome(setup.dana);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

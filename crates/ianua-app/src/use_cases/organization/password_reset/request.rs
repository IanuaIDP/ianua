//! A member who forgot their password asks for a reset link by address.
//!
//! Someone who cannot sign in cannot be expected to know their
//! organization. An address is unique within an organization only, so it
//! may name a member in several: each is mailed a link of their own, naming
//! their organization, and following one resets that account alone. The
//! answer is the same whether or not a member has the address, so it cannot
//! be used to find members. Each link supersedes the ones sent before it.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::{RefreshToken, RefreshTokenGenerator};
use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::domains::identity::tokens::password_reset::PasswordReset;
use ianua_domain::domains::organization::access::token::{NewOrgToken, OrgPasswordResetToken};
use ianua_domain::domains::organization::events::access::OrgUserPasswordResetRequested;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, Email, HttpsUrl, Lifetime};

use crate::auditor::RequestAuditor;
use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::ports::limits::{MailPurpose, MailThrottle};
use crate::ports::organization::{OrgTokenStore, OrgUserStore, OrganizationStore};
use crate::ports::shared::{MailSetup, Mailer};
use crate::services::authentication::channels::{NO_RESET_LINKS, ensure_mail_reaches};
use crate::services::authentication::organization_accounts::organizations_of;
use crate::use_case::Command;
use crate::use_cases::organization::link_mail::{LinkPerOrganization, Recipient, mail_each};

/// How long a member's reset link works and the address it is built on.
#[derive(Debug, Clone)]
pub struct OrgResetPolicy {
    /// How long the link works, at most an hour.
    pub lifetime: Lifetime,
    /// The base URL the link is built on.
    pub base_url: HttpsUrl,
}

/// The ports [`RequestOrgResetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RequestOrgResetPorts {
    /// Finds the member behind an address.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// The member's organization, whose sign-in pages the link opens.
    pub org_store: Arc<dyn OrganizationStore>,
    /// Members' reset links.
    pub token_store: Arc<dyn OrgTokenStore<PasswordReset>>,
    /// Composes and sends the reset email.
    pub mailer: Arc<dyn Mailer>,
    /// Lets one reset link a minute through to an address.
    pub mail_throttle: Arc<dyn MailThrottle>,
    /// Makes the link's token and its hash.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// Whether anything can be mailed here at all.
    pub mail: Arc<dyn MailSetup>,
}

/// Mails a member a password reset link.
pub struct RequestOrgResetUseCase {
    policy: OrgResetPolicy,
    ports: RequestOrgResetPorts,
}

impl RequestOrgResetUseCase {
    /// A use case under `policy`, working through `ports`.
    #[must_use]
    pub fn new(policy: OrgResetPolicy, ports: RequestOrgResetPorts) -> Self {
        Self { policy, ports }
    }

    /// Every member holding `email`, one per organization, with their
    /// organization. A member whose organization is gone is left out.
    async fn recipients(&self, email: &Email) -> Result<Vec<Recipient>, AppError> {
        let members = self
            .ports
            .org_user_store
            .find_all_by_email(email)
            .await
            .or_internal()?;
        let mut organizations = organizations_of(self.ports.org_store.as_ref(), &members).await?;
        let mut recipients = Vec::with_capacity(members.len());
        for member in members {
            let found = organizations.remove(member.organization_id());
            let Some(organization) = found else {
                continue;
            };
            recipients.push(Recipient {
                member,
                organization,
            });
        }
        Ok(recipients)
    }

    /// Supersedes the member's earlier links and keeps a fresh one, handing
    /// back the raw token it carries.
    async fn fresh_link(&self, member: &OrgUser) -> Result<Secret, AppError> {
        let store = self.ports.token_store.as_ref();
        store.consume_outstanding(member.id()).await.or_internal()?;
        let (raw, token_hash) = self
            .ports
            .token_generator
            .generate()
            .map(RefreshToken::into_parts)
            .or_internal()?;
        let link = OrgPasswordResetToken::issue(NewOrgToken {
            token_hash,
            org_user_id: *member.id(),
            sent_to: member.email().clone(),
            lifetime: self.policy.lifetime,
        })
        .map_err(AppError::from_domain)?;
        store.save(&link).await.or_internal()?;
        Ok(raw)
    }

    /// Mails the link. Delivery is best effort, and the answer is the same
    /// either way, so it reveals nothing about the address.
    async fn mail_link(&self, to: &Recipient, raw: &Secret) {
        let scope = LinkScope::organization(to.organization.slug().clone());
        let variables = HashMap::from([
            (
                TemplateVariable::UserName,
                to.member.display_name().as_str().to_owned(),
            ),
            (
                TemplateVariable::OrganizationName,
                to.organization.name().as_str().to_owned(),
            ),
            (
                TemplateVariable::ActionUrl,
                scope.action_url(&self.policy.base_url, "reset-password", raw.expose()),
            ),
            (
                TemplateVariable::ExpiresAt,
                format!("{} minutes", self.policy.lifetime.whole_seconds() / 60),
            ),
        ]);
        let mailer = self.ports.mailer.as_ref();
        let sent = mailer.send(
            to.member.email(),
            None,
            EmailTemplateType::PasswordReset,
            &variables,
        );
        let _ = sent.await;
    }
}

impl Command for RequestOrgResetUseCase {
    type Caller = ();
    type Input = Email;
    type Output = Result<(), AppError>;

    /// Mails each membership at `email` a reset link, replacing its earlier links
    /// and recording `organization.org_user_password_reset_requested`.
    /// Unknown or throttled addresses also answer `Ok`, but record nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` without mail, before lookup, directing every caller to an admin reset.
    /// - `AppError::Domain` when the configured lifetime is longer than a
    ///   reset link may live.
    /// - `AppError::Internal` on persistence, token or audit failure.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        email: Email,
    ) -> Result<(), AppError> {
        ensure_mail_reaches(self.ports.mail.as_ref(), NO_RESET_LINKS)?;
        let recipients = self.recipients(&email).await?;
        mail_each(self, auditor, &email, &recipients).await
    }
}

impl LinkPerOrganization for RequestOrgResetUseCase {
    /// Whether a reset link may go to `email` now: it had none in the past
    /// minute. A request held back answers as one that was sent.
    async fn admitted(&self, email: &Email) -> Result<bool, AppError> {
        self.ports
            .mail_throttle
            .admit(MailPurpose::OrgPasswordReset, email)
            .await
            .or_internal()
    }

    /// Mails `to` a fresh link and records the request as theirs.
    async fn sent(&self, auditor: &RequestAuditor, to: &Recipient) -> Result<(), AppError> {
        let raw = self.fresh_link(&to.member).await?;
        self.mail_link(to, &raw).await;
        auditor
            .dispatch_by(
                &ActorRef::OrgUser(*to.member.id()),
                vec![OrgUserPasswordResetRequested::observed(&to.member)],
            )
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::clock;
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::test_support::identity::hash_of_link;
    use crate::test_support::organization::{
        FakeOrgTokenStore, org_store_with, org_user_store_with, test_org, test_org_user,
    };
    use crate::test_support::{
        Fake, FakeEventDispatcher, FakeMailSetup, FakeMailer, OpenMailThrottle, ShutMailThrottle,
        block_on, test_auditor,
    };

    const ADDRESS: &str = "alice@acme.test";

    struct Fixture {
        tokens: Arc<FakeOrgTokenStore<PasswordReset>>,
        mailer: Arc<FakeMailer>,
        audit: Arc<FakeEventDispatcher>,
        use_case: RequestOrgResetUseCase,
    }

    impl Fixture {
        fn behind(mail_throttle: Arc<dyn MailThrottle>) -> Self {
            Self::reaching(mail_throttle, Fake::fake())
        }

        fn reaching(mail_throttle: Arc<dyn MailThrottle>, mail: Arc<dyn MailSetup>) -> Self {
            let organization = OrganizationId::new();
            let tokens = Arc::new(FakeOrgTokenStore::empty());
            let mailer = Arc::new(FakeMailer::new());
            let use_case = RequestOrgResetUseCase::new(
                policy(),
                RequestOrgResetPorts {
                    org_user_store: Arc::new(org_user_store_with([test_org_user(
                        organization,
                        ADDRESS,
                        OrgRole::Member,
                    )])),
                    org_store: org_store_with([test_org(organization, "acme")]),
                    token_store: tokens.clone(),
                    mailer: mailer.clone(),
                    mail_throttle,
                    mail,
                    ..RequestOrgResetPorts::fakes()
                },
            );
            Self {
                tokens,
                mailer,
                audit: Arc::new(FakeEventDispatcher::new()),
                use_case,
            }
        }

        fn new() -> Self {
            Self::behind(Arc::new(OpenMailThrottle))
        }

        fn link(&self, raw: &str) -> OrgPasswordResetToken {
            block_on(self.tokens.find_by_hash(&hash_of_link(raw)))
                .unwrap()
                .unwrap()
        }

        fn request(&self, address: &str) {
            block_on(self.use_case.execute(
                &(),
                &test_auditor(self.audit.clone()),
                Email::new(address).unwrap(),
            ))
            .expect("a reset request always answers the same way");
        }
    }

    fn policy() -> OrgResetPolicy {
        OrgResetPolicy {
            lifetime: Lifetime::seconds(3600).unwrap(),
            base_url: HttpsUrl::new("https://test.example.com").unwrap(),
        }
    }

    /// Alice forgot her password and types her address. A link that lasts
    /// the configured hour goes to her, and the request is recorded.
    #[test]
    fn a_known_address_is_sent_a_link_that_lasts_the_configured_time() {
        let fixture = Fixture::new();
        let before = clock::now();

        fixture.request(ADDRESS);

        assert_eq!(fixture.mailer.recipients(), vec![ADDRESS.to_owned()]);
        assert_eq!(fixture.tokens.count(), 1);
        let sent = fixture.link("fake_refresh_0");
        assert!(sent.expires_at() >= before + time::Duration::seconds(3600));
        assert_eq!(
            *fixture.audit.records.lock().unwrap(),
            vec!["organization.org_user_password_reset_requested"]
        );
    }

    /// Without mail configured, a reset request directs the member to an
    /// administrator and creates no token, mail or audit record.
    #[test]
    fn no_link_is_sent_where_nothing_is_mailed() {
        let fixture = Fixture::reaching(Arc::new(OpenMailThrottle), FakeMailSetup::not_set_up());

        let answer = block_on(fixture.use_case.execute(
            &(),
            &test_auditor(fixture.audit.clone()),
            Email::new(ADDRESS).unwrap(),
        ));

        assert!(
            matches!(answer, Err(AppError::Forbidden(why)) if why.as_str().contains("administrator"))
        );
        assert!(fixture.mailer.recipients().is_empty());
        assert_eq!(fixture.tokens.count(), 0);
        assert!(fixture.audit.records.lock().unwrap().is_empty());
    }

    /// An unknown address receives the usual successful response without
    /// creating a token, mail or audit record.
    #[test]
    fn an_unknown_address_is_sent_nothing() {
        let fixture = Fixture::new();

        fixture.request("nobody@acme.test");

        assert!(fixture.mailer.recipients().is_empty());
        assert_eq!(fixture.tokens.count(), 0);
        assert!(fixture.audit.records.lock().unwrap().is_empty());
    }

    /// A throttled reset request succeeds without creating a token or
    /// sending mail.
    #[test]
    fn a_throttled_request_sends_nothing() {
        let fixture = Fixture::behind(Arc::new(ShutMailThrottle));

        fixture.request(ADDRESS);

        assert!(fixture.mailer.recipients().is_empty());
        assert_eq!(fixture.tokens.count(), 0);
    }

    /// Alice is a member of Acme and of Globex under one address. Each
    /// account is mailed its own link, and each request is recorded.
    #[test]
    fn an_address_in_two_organizations_is_sent_a_link_for_each() {
        let (acme, globex) = (OrganizationId::new(), OrganizationId::new());
        let organizations = org_store_with([test_org(acme, "acme"), test_org(globex, "globex")]);
        let tokens = Arc::new(FakeOrgTokenStore::empty());
        let mailer = Arc::new(FakeMailer::new());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = RequestOrgResetUseCase::new(
            policy(),
            RequestOrgResetPorts {
                org_user_store: Arc::new(org_user_store_with([
                    test_org_user(acme, ADDRESS, OrgRole::Member),
                    test_org_user(globex, ADDRESS, OrgRole::Owner),
                    test_org_user(OrganizationId::new(), ADDRESS, OrgRole::Member),
                ])),
                org_store: organizations.clone(),
                token_store: tokens.clone(),
                mailer: mailer.clone(),
                mail_throttle: Arc::new(OpenMailThrottle),
                ..RequestOrgResetPorts::fakes()
            },
        );

        block_on(use_case.execute(
            &(),
            &test_auditor(audit.clone()),
            Email::new(ADDRESS).unwrap(),
        ))
        .unwrap();

        assert_eq!(mailer.count(), 2);
        assert_eq!(tokens.count(), 2);
        assert_eq!(audit.records.lock().unwrap().len(), 2);
        assert_eq!(organizations.id_reads(), 1);
    }

    /// Alice asks twice. The second link supersedes the first, which can
    /// no longer be followed.
    #[test]
    fn a_new_link_supersedes_the_one_before() {
        let fixture = Fixture::new();
        fixture.request(ADDRESS);

        fixture.request(ADDRESS);

        assert_eq!(fixture.tokens.count(), 2);
        assert!(fixture.link("fake_refresh_0").consumed_at().is_some());
        assert!(fixture.link("fake_refresh_1").consumed_at().is_none());
    }
}

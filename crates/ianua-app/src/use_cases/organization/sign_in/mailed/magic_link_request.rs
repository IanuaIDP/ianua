//! A member asking for a sign-in link to the dashboard by address.
//!
//! The answer is the same whether or not a member has the address, whether
//! or not their organization allows mailed links, and whether or not the
//! mail went, so it cannot be used to find members. A link goes only to a
//! member who could use it: one their organization lets sign in by mail,
//! and not one it signs in through single sign-on. An address may hold an
//! account in several organizations; each gets its own link, naming its
//! organization, so the mailbox holder chooses by following one. Each link
//! supersedes the ones sent before it.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::tokens::refresh::{RefreshToken, RefreshTokenGenerator};
use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::domains::identity::tokens::magic_link::MagicLink;
use ianua_domain::domains::organization::access::token::{NewOrgToken, OrgMagicLinkToken};
use ianua_domain::domains::organization::events::access::OrgMagicLinkRequested;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, Email, HttpsUrl, Lifetime};

use crate::auditor::RequestAuditor;
use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::ports::limits::{MailPurpose, MailThrottle};
use crate::ports::organization::{OrgTokenStore, OrgUserStore, OrganizationStore};
use crate::ports::shared::{MailSetup, Mailer};
use crate::services::authentication::channels::{NO_MAGIC_LINKS, ensure_mail_reaches};
use crate::services::authentication::organization_accounts::organizations_of;
use crate::use_case::Command;
use crate::use_cases::organization::link_mail::{LinkPerOrganization, Recipient, mail_each};

/// How long a member's sign-in link works and the address it is built on.
#[derive(Debug, Clone)]
pub struct OrgMagicLinkPolicy {
    /// How long the link works, at most an hour.
    pub lifetime: Lifetime,
    /// The base URL the link is built on.
    pub base_url: HttpsUrl,
}

/// The ports [`RequestOrgMagicLinkUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RequestOrgMagicLinkPorts {
    /// Finds the member behind an address.
    pub members: Arc<dyn OrgUserStore>,
    /// The member's organization, whose settings decide whether a link
    /// goes.
    pub organizations: Arc<dyn OrganizationStore>,
    /// Members' sign-in links.
    pub links: Arc<dyn OrgTokenStore<MagicLink>>,
    /// Composes and sends the mail.
    pub mailer: Arc<dyn Mailer>,
    /// Lets one sign-in link a minute through to an address.
    pub mail_throttle: Arc<dyn MailThrottle>,
    /// Makes the link's token and its hash.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// Whether anything can be mailed here at all.
    pub mail: Arc<dyn MailSetup>,
}

/// Mails a member a link that signs them in to the dashboard.
pub struct RequestOrgMagicLinkUseCase {
    policy: OrgMagicLinkPolicy,
    ports: RequestOrgMagicLinkPorts,
}

impl RequestOrgMagicLinkUseCase {
    /// A use case under `policy`, working through `ports`.
    #[must_use]
    pub fn new(policy: OrgMagicLinkPolicy, ports: RequestOrgMagicLinkPorts) -> Self {
        Self { policy, ports }
    }

    /// Every member holding `email` who could sign in with a link, one per
    /// organization, with their organization.
    async fn recipients(&self, email: &Email) -> Result<Vec<Recipient>, AppError> {
        let members = self
            .ports
            .members
            .find_all_by_email(email)
            .await
            .or_internal()?;
        let mut organizations =
            organizations_of(self.ports.organizations.as_ref(), &members).await?;
        let mut recipients = Vec::with_capacity(members.len());
        for member in members {
            let found = organizations.remove(member.organization_id());
            let Some(organization) = found.filter(|held| may_use_link(&member, held)) else {
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
        let links = self.ports.links.as_ref();
        links.consume_outstanding(member.id()).await.or_internal()?;
        let (raw, token_hash) = self
            .ports
            .token_generator
            .generate()
            .map(RefreshToken::into_parts)
            .or_internal()?;
        let link = OrgMagicLinkToken::issue(NewOrgToken {
            token_hash,
            org_user_id: *member.id(),
            sent_to: member.email().clone(),
            lifetime: self.policy.lifetime,
        })
        .map_err(AppError::from_domain)?;
        links.save(&link).await.or_internal()?;
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
                scope.action_url(&self.policy.base_url, "magic-link", raw.expose()),
            ),
            (
                TemplateVariable::ExpiresAt,
                format!("{} minutes", self.policy.lifetime.whole_seconds() / 60),
            ),
        ]);
        let sent = self.ports.mailer.send(
            to.member.email(),
            None,
            EmailTemplateType::MagicLink,
            &variables,
        );
        let _ = sent.await;
    }
}

impl Command for RequestOrgMagicLinkUseCase {
    type Caller = ();
    type Input = Email;
    type Output = Result<(), AppError>;

    /// Mails each eligible membership at `email` a sign-in link for its organization,
    /// recording `organization.org_magic_link_requested` per link. Unknown addresses
    /// also answer `Ok`, hiding membership from the caller.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the deployment has no mail server, for
    ///   every address alike, before any member is looked up.
    /// - `AppError::Domain` when the configured lifetime is longer than a
    ///   sign-in link may live.
    /// - `AppError::Internal` on persistence, token or audit failure.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        email: Email,
    ) -> Result<(), AppError> {
        ensure_mail_reaches(self.ports.mail.as_ref(), NO_MAGIC_LINKS)?;
        let recipients = self.recipients(&email).await?;
        mail_each(self, auditor, &email, &recipients).await
    }
}

impl LinkPerOrganization for RequestOrgMagicLinkUseCase {
    /// Whether a sign-in link may go to `email` now: it had none in the
    /// past minute.
    async fn admitted(&self, email: &Email) -> Result<bool, AppError> {
        self.ports
            .mail_throttle
            .admit(MailPurpose::MagicLink, email)
            .await
            .or_internal()
    }

    /// Mails `to` a fresh link and records it against their organization.
    async fn sent(&self, auditor: &RequestAuditor, to: &Recipient) -> Result<(), AppError> {
        let raw = self.fresh_link(&to.member).await?;
        self.mail_link(to, &raw).await;
        auditor
            .with_organization(*to.organization.id())
            .dispatch_by(
                &ActorRef::System,
                vec![OrgMagicLinkRequested::observed(&to.member)],
            )
            .await
            .or_internal()
    }
}

/// Whether `member` could sign in with a mailed link: they may sign in at
/// all, `organization` allows links, and it does not sign them in through
/// single sign-on.
fn may_use_link(member: &OrgUser, organization: &Organization) -> bool {
    let config = organization.auth_config();
    member.status().can_authenticate()
        && config.is_method_enabled(AuthMethod::MagicLink)
        && config.ensure_may_skip_sso(member).is_ok()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::risk_engine::step_up::StepUpPolicy;
    use ianua_domain::domains::organization::access::auth_config::{
        OrganizationAuthSettings, SsoEnforcement,
    };
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::status::Suspension;
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::test_support::identity::hash_of_link;
    use crate::test_support::organization::{
        FakeOrgTokenStore, FakeOrganizationStore, OrgShape, org_shaped, org_store_with,
        org_user_store_with, test_org_user,
    };
    use crate::test_support::{
        Fake, FakeEventDispatcher, FakeMailSetup, FakeMailer, OpenMailThrottle, ShutMailThrottle,
        block_on, test_auditor,
    };

    const ALICE: &str = "alice@acme.test";

    struct Fixture {
        organizations: Arc<FakeOrganizationStore>,
        links: Arc<FakeOrgTokenStore<MagicLink>>,
        mailer: Arc<FakeMailer>,
        audit: Arc<FakeEventDispatcher>,
        use_case: RequestOrgMagicLinkUseCase,
    }

    /// How Acme and Alice stand for a test.
    struct Acme {
        settings: OrganizationAuthSettings,
        role: OrgRole,
        throttle: Arc<dyn MailThrottle>,
        mail: Arc<dyn MailSetup>,
    }

    impl Acme {
        fn allowing_links() -> Self {
            Self {
                settings: OrganizationAuthSettings {
                    enabled_methods: vec![AuthMethod::Password, AuthMethod::MagicLink],
                    step_up_policy: StepUpPolicy::relaxed(),
                    ..OrganizationAuthSettings::default()
                },
                role: OrgRole::Member,
                throttle: Arc::new(OpenMailThrottle),
                mail: Fake::fake(),
            }
        }

        /// As [`Self::allowing_links`], on a deployment with no mail server.
        fn allowing_links_without_mail() -> Self {
            Self {
                mail: FakeMailSetup::not_set_up(),
                ..Self::allowing_links()
            }
        }

        fn enforcing_sso(role: OrgRole) -> Self {
            let allowing = Self::allowing_links();
            let mut settings = allowing.settings.clone();
            settings.enabled_methods.push(AuthMethod::Saml);
            settings.sso = SsoEnforcement::Enforced;
            Self {
                settings,
                role,
                ..allowing
            }
        }

        /// An organization standing as this says, with Alice a member.
        fn organization_with_alice(&self) -> (Organization, OrgUser) {
            let id = OrganizationId::new();
            let organization = org_shaped(
                id,
                OrgShape {
                    tenants: Vec::new(),
                    settings: self.settings.clone(),
                    suspension: Suspension::NotSuspended,
                },
            );
            (organization, test_org_user(id, ALICE, self.role))
        }

        fn build(self) -> Fixture {
            self.build_in(1)
        }

        /// Alice a member of `count` organizations standing alike.
        fn build_in(self, count: usize) -> Fixture {
            let (organizations, members): (Vec<_>, Vec<_>) =
                (0..count).map(|_| self.organization_with_alice()).unzip();
            let organizations = org_store_with(organizations);
            let links = Arc::new(FakeOrgTokenStore::empty());
            let mailer = Arc::new(FakeMailer::new());
            let use_case = RequestOrgMagicLinkUseCase::new(
                policy(),
                RequestOrgMagicLinkPorts {
                    members: Arc::new(org_user_store_with(members)),
                    organizations: organizations.clone(),
                    links: links.clone(),
                    mailer: mailer.clone(),
                    mail_throttle: self.throttle,
                    mail: self.mail,
                    ..RequestOrgMagicLinkPorts::fakes()
                },
            );
            Fixture {
                organizations,
                links,
                mailer,
                audit: Arc::new(FakeEventDispatcher::new()),
                use_case,
            }
        }
    }

    impl Fixture {
        fn request(&self, address: &str) {
            block_on(self.use_case.execute(
                &(),
                &test_auditor(self.audit.clone()),
                Email::new(address).unwrap(),
            ))
            .expect("a link request always answers the same way");
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }

        fn link(&self, raw: &str) -> OrgMagicLinkToken {
            block_on(self.links.find_by_hash(&hash_of_link(raw)))
                .unwrap()
                .unwrap()
        }
    }

    fn policy() -> OrgMagicLinkPolicy {
        OrgMagicLinkPolicy {
            lifetime: Lifetime::seconds(900).unwrap(),
            base_url: HttpsUrl::new("https://app.acme.test").unwrap(),
        }
    }

    /// Without a configured mail server, Alice's link request returns a
    /// forbidden error, sends no mail and records no audit event.
    #[test]
    fn no_link_is_sent_where_nothing_is_mailed() {
        let fixture = Acme::allowing_links_without_mail().build();

        let result = block_on(fixture.use_case.execute(
            &(),
            &test_auditor(fixture.audit.clone()),
            Email::new(ALICE).unwrap(),
        ));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(fixture.mailer.recipients().is_empty());
        assert!(fixture.recorded().is_empty());
    }

    /// Alice asks for a sign-in link. Acme allows links, so one goes to
    /// her and is kept.
    #[test]
    fn a_member_whose_organization_allows_links_is_sent_one() {
        let fixture = Acme::allowing_links().build();

        fixture.request(ALICE);

        assert_eq!(fixture.mailer.recipients(), vec![ALICE.to_owned()]);
        assert_eq!(fixture.links.count(), 1);
        assert_eq!(
            fixture.recorded(),
            ["organization.org_magic_link_requested"]
        );
    }

    /// Alice is a member of two organizations that both allow links. Each
    /// is sent its own link, naming its organization, and each is
    /// recorded: following one is her choice of where to sign in.
    #[test]
    fn an_address_in_two_organizations_is_sent_a_link_for_each() {
        let fixture = Acme::allowing_links().build_in(2);

        fixture.request(ALICE);

        assert_eq!(fixture.mailer.count(), 2);
        assert_eq!(fixture.links.count(), 2);
        assert_eq!(fixture.recorded().len(), 2);
        assert_eq!(fixture.organizations.id_reads(), 1);
    }

    /// An unknown address receives the usual successful response, with no
    /// mail sent, link stored or audit event recorded.
    #[test]
    fn an_unknown_address_is_sent_nothing() {
        let fixture = Acme::allowing_links().build();

        fixture.request("nobody@acme.test");

        assert!(fixture.mailer.recipients().is_empty());
        assert_eq!(fixture.links.count(), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// Acme does not allow sign-in links. None is sent to Alice, though the
    /// answer is the same.
    #[test]
    fn an_organization_without_links_is_sent_nothing() {
        let mut acme = Acme::allowing_links();
        acme.settings.enabled_methods = vec![AuthMethod::Password];
        let fixture = acme.build();

        fixture.request(ALICE);

        assert!(fixture.mailer.recipients().is_empty());
        assert_eq!(fixture.links.count(), 0);
    }

    /// Under enforced SSO, a member's link request succeeds without sending
    /// mail.
    #[test]
    fn a_member_signed_in_through_sso_is_sent_nothing() {
        let fixture = Acme::enforcing_sso(OrgRole::Member).build();

        fixture.request(ALICE);

        assert!(fixture.mailer.recipients().is_empty());
    }

    /// Acme enforces single sign-on, but owners keep their other ways in,
    /// so Ann, its owner, is sent a link while the provider is down.
    #[test]
    fn an_owner_is_sent_a_link_under_enforced_sso() {
        let fixture = Acme::enforcing_sso(OrgRole::Owner).build();

        fixture.request(ALICE);

        assert_eq!(fixture.mailer.recipients(), vec![ALICE.to_owned()]);
    }

    /// A throttled request succeeds without sending mail or storing a link.
    #[test]
    fn a_throttled_request_sends_nothing() {
        let fixture = Acme {
            throttle: Arc::new(ShutMailThrottle),
            ..Acme::allowing_links()
        }
        .build();

        fixture.request(ALICE);

        assert!(fixture.mailer.recipients().is_empty());
        assert_eq!(fixture.links.count(), 0);
    }

    /// Alice asks twice. The second link supersedes the first.
    #[test]
    fn a_new_link_supersedes_the_one_before() {
        let fixture = Acme::allowing_links().build();
        fixture.request(ALICE);

        fixture.request(ALICE);

        assert!(fixture.link("fake_refresh_0").consumed_at().is_some());
        assert!(fixture.link("fake_refresh_1").consumed_at().is_none());
    }
}

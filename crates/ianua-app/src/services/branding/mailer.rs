//! Choosing the template a recipient gets and the address it comes from,
//! before the mail is queued.
//!
//! A tenant writes its mail once for every locale, and may write it again
//! for a locale of its own. The recipient gets the template the domain's
//! [`template_for`] picks for their locale, or for the tenant's when they
//! follow it. The mail goes out from the tenant's own address only while
//! [`TenantBranding::sender_on`] still allows it: the address is on a
//! domain the tenant has verified. A domain that fails verification later
//! puts the mail back on the platform's address at once.
//!
//! [`TenantBranding::sender_on`]: ianua_domain::domains::branding::config::TenantBranding::sender_on

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::branding::config::MailSender;
use ianua_domain::domains::branding::email_template::{
    EmailTemplateType, TemplateVariable, template_for,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, Locale, Preference};

use crate::ports::branding::{BrandingStore, EmailTemplateStore};
use crate::ports::domain::RegisteredDomainStore;
use crate::ports::shared::{MailOutbox, MailRecipient, Mailer, OutgoingMail};
use crate::ports::tenant::TenantStore;
use crate::services::branding::sender::TenantSenders;
use crate::tenancy::ScopedTenant;

/// The ports a [`TenantMailer`] reads and queues through.
#[derive(ianua_macros::Fakes)]
pub struct TenantMailerPorts {
    /// The tenant's own templates.
    pub templates: Arc<dyn EmailTemplateStore>,
    /// The tenant's sender address and name.
    pub branding: Arc<dyn BrandingStore>,
    /// The domains the sender address must be on.
    pub domains: Arc<dyn RegisteredDomainStore>,
    /// The tenant's own locale.
    pub tenants: Arc<dyn TenantStore>,
    /// Where the chosen mail is queued.
    pub outbox: Arc<dyn MailOutbox>,
}

/// The [`Mailer`] every use case sends through: it picks the template and
/// the sender, then queues the mail.
pub struct TenantMailer {
    ports: TenantMailerPorts,
    senders: TenantSenders,
}

impl TenantMailer {
    /// A mailer reading and queueing through `ports`.
    #[must_use]
    pub fn new(ports: TenantMailerPorts) -> Self {
        let senders = TenantSenders::new(Arc::clone(&ports.branding), Arc::clone(&ports.domains));
        Self { ports, senders }
    }

    /// The locale the recipient reads: their own, or the tenant's.
    async fn locale_of(
        &self,
        tenant: &ScopedTenant,
        chosen: &Preference<Locale>,
    ) -> Result<Locale, DomainError> {
        if let Preference::Own(locale) = chosen {
            return Ok(locale.clone());
        }
        let Some(found) = self.ports.tenants.find_by_id(tenant).await? else {
            return Err(DomainError::infra_msg("the tenant a mail is for is gone"));
        };
        Ok(found.locale().clone())
    }
}

#[async_trait]
impl Mailer for TenantMailer {
    async fn send(
        &self,
        to: &Email,
        tenant_id: Option<ScopedTenant>,
        template_type: EmailTemplateType,
        variables: &HashMap<TemplateVariable, String>,
    ) -> Result<(), DomainError> {
        let Some(tenant) = tenant_id else {
            return self
                .ports
                .outbox
                .queue(&platform_mail(to, template_type, variables))
                .await;
        };
        let recipient = MailRecipient {
            email: to,
            locale: &Preference::Inherited,
        };
        self.send_to_person(recipient, tenant, template_type, variables)
            .await
    }

    async fn send_to_person(
        &self,
        to: MailRecipient<'_>,
        tenant_id: ScopedTenant,
        template_type: EmailTemplateType,
        variables: &HashMap<TemplateVariable, String>,
    ) -> Result<(), DomainError> {
        let locale = self.locale_of(&tenant_id, to.locale).await?;
        let templates = self
            .ports
            .templates
            .list_for_type(&tenant_id, template_type)
            .await?;
        let sent_as = self.senders.of(&tenant_id).await?;
        let mail = OutgoingMail {
            to: to.email,
            tenant: Some(&tenant_id),
            template_type,
            template: template_for(&templates, template_type, &locale),
            locale: Some(&locale),
            sender: sent_as.sender(),
            sender_name: sent_as.sender_name(),
            variables,
        };
        self.ports.outbox.queue(&mail).await
    }
}

/// Mail of no tenant: the platform's template, from the platform's address.
fn platform_mail<'a>(
    to: &'a Email,
    template_type: EmailTemplateType,
    variables: &'a HashMap<TemplateVariable, String>,
) -> OutgoingMail<'a> {
    OutgoingMail {
        to,
        tenant: None,
        template_type,
        template: Preference::Inherited,
        locale: None,
        sender: MailSender::Platform,
        sender_name: None,
        variables,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{BrandingAction, SystemPermission};
    use ianua_domain::domains::branding::config::TenantBranding;
    use ianua_domain::domains::branding::control::BrandingControl;
    use ianua_domain::domains::branding::email_template::{
        EmailHtmlBody, EmailTemplate, TemplateLocale, TemplateSlot,
    };
    use ianua_domain::domains::tenant::custom_domains::registered_domain::{
        DomainConnection, DomainProof, DomainVerificationToken, RegisteredDomain,
        RegisteredDomainRow,
    };
    use ianua_domain::domains::tenant::custom_domains::verification_status::TlsStatus;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::test_support::authority::anyone_holding;
    use ianua_domain::test_support::builders::label;
    use ianua_domain::types::{DomainId, DomainName};

    use super::*;
    use crate::test_support::branding::{FakeBrandingStore, FakeEmailTemplateStore};
    use crate::test_support::domain::FakeDomainStore;
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{FakeMailOutbox, QueuedMail, block_on, test_ctx};

    struct Setup {
        mailer: TenantMailer,
        outbox: Arc<FakeMailOutbox>,
    }

    impl Setup {
        fn with(ports: TenantMailerPorts) -> Self {
            let outbox = Arc::new(FakeMailOutbox::new());
            let mailer = TenantMailer::new(TenantMailerPorts {
                outbox: outbox.clone(),
                tenants: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                ..ports
            });
            Self { mailer, outbox }
        }

        /// Seeds the templates available when choosing a recipient's mail.
        fn holding_templates(templates: &[EmailTemplate]) -> Self {
            let store = FakeEmailTemplateStore::empty();
            for template in templates {
                block_on(store.save(&test_ctx().tenant(), template)).unwrap();
            }
            Self::with(TenantMailerPorts {
                templates: Arc::new(store),
                ..TenantMailerPorts::fakes()
            })
        }

        fn sending_from(address: &str, proof: DomainProof) -> Self {
            let tenant = test_ctx().tenant();
            let domains = Arc::new(FakeDomainStore::empty());
            let registered = domain("acme.com", proof);
            block_on(domains.save(&tenant, &registered)).unwrap();
            let mut branding = TenantBranding::default_branding();
            branding
                .send_from(
                    Email::new(address).unwrap(),
                    &domain("acme.com", verified()),
                    &editor(),
                )
                .unwrap();
            Self::with(TenantMailerPorts {
                branding: Arc::new(FakeBrandingStore::holding(*tenant, branding)),
                domains,
                ..TenantMailerPorts::fakes()
            })
        }

        /// Queues a welcome mail in the requested language and returns it.
        fn send_to(&self, locale: &Preference<Locale>) -> QueuedMail {
            let to = Email::new("ann@acme.com").unwrap();
            let recipient = MailRecipient { email: &to, locale };
            block_on(self.mailer.send_to_person(
                recipient,
                test_ctx().tenant(),
                EmailTemplateType::Welcome,
                &HashMap::new(),
            ))
            .unwrap();
            self.outbox.last()
        }
    }

    fn editor() -> BrandingControl<'static> {
        BrandingControl::new(anyone_holding(&[SystemPermission::Branding(
            BrandingAction::Update,
        )]))
    }

    fn locale(tag: &str) -> Locale {
        Locale::new(tag).unwrap()
    }

    fn verified() -> DomainProof {
        DomainProof::Verified { at: clock::now() }
    }

    fn domain(name: &str, proof: DomainProof) -> RegisteredDomain<ResolvedTenant> {
        RegisteredDomain::reconstitute(RegisteredDomainRow {
            id: DomainId::new(),
            domain: DomainName::new(name).unwrap(),
            connection: DomainConnection::SelfManaged,
            proof,
            dns_challenge_token: DomainVerificationToken::new("token").unwrap(),
            tls_status: TlsStatus::NotRequired,
            created_at: clock::now() - time::Duration::hours(1),
        })
        .unwrap()
    }

    /// Acme's welcome mail for `for_locale`, its subject naming it.
    fn welcome(for_locale: TemplateLocale, subject: &str) -> EmailTemplate {
        EmailTemplate::custom(
            TemplateSlot {
                template_type: EmailTemplateType::Welcome,
                locale: for_locale,
            },
            Preference::Own(label(subject)),
            Preference::Own(EmailHtmlBody::new("<p>Welcome</p>").unwrap()),
            Preference::Inherited,
            &editor(),
        )
        .unwrap()
    }

    fn acme_welcomes() -> Vec<EmailTemplate> {
        vec![
            welcome(TemplateLocale::Fallback, "Welcome"),
            welcome(TemplateLocale::For(locale("de-DE")), "Willkommen"),
        ]
    }

    /// Ann chose German. Acme wrote no welcome mail of its own, so the
    /// platform's is queued, carrying her locale for the worker to render
    /// it in German.
    #[test]
    fn the_platform_mail_carries_the_recipients_own_locale() {
        let setup = Setup::holding_templates(&[]);

        let queued = setup.send_to(&Preference::Own(locale("de-AT")));

        assert_eq!(queued.template, Preference::Inherited);
        assert_eq!(queued.locale.as_deref(), Some("de-AT"));
    }

    /// Ann follows her tenant's locale, so the mail carries the tenant's.
    #[test]
    fn the_platform_mail_carries_the_tenants_locale_when_followed() {
        let setup = Setup::holding_templates(&[]);
        let tenant_locale = test_tenant_for_ctx().locale().as_str().to_owned();

        let queued = setup.send_to(&Preference::Inherited);

        assert_eq!(queued.locale, Some(tenant_locale));
    }

    /// Ann reads German in Austria. Acme wrote its welcome mail for
    /// `de-DE` and for every locale. Ann gets the German one.
    #[test]
    fn a_recipient_gets_the_template_of_their_language() {
        let setup = Setup::holding_templates(&acme_welcomes());

        let queued = setup.send_to(&Preference::Own(locale("de-AT")));

        assert_eq!(queued.subject.as_deref(), Some("Willkommen"));
    }

    /// Bob reads Japanese. Acme wrote no Japanese mail, so he gets its
    /// template for every locale.
    #[test]
    fn a_recipient_without_a_template_of_their_own_gets_the_fallback() {
        let setup = Setup::holding_templates(&acme_welcomes());

        let queued = setup.send_to(&Preference::Own(locale("ja-JP")));

        assert_eq!(queued.subject.as_deref(), Some("Welcome"));
    }

    /// Cat follows Acme's language, which is the test tenant's own locale.
    /// She gets the template the tenant's locale picks, not the German one.
    #[test]
    fn a_recipient_following_the_tenant_gets_the_tenants_locale() {
        let setup = Setup::holding_templates(&acme_welcomes());

        let queued = setup.send_to(&Preference::Inherited);

        assert_eq!(queued.subject.as_deref(), Some("Welcome"));
    }

    /// Acme wrote no welcome mail of its own. Dan gets the platform's.
    #[test]
    fn a_tenant_without_templates_sends_the_platforms_mail() {
        let setup = Setup::holding_templates(&[]);

        let queued = setup.send_to(&Preference::Own(locale("en-US")));

        assert_eq!(queued.template, Preference::Inherited);
    }

    /// Acme sends from `hello@acme.com` and still holds `acme.com`
    /// verified. Its mail goes out from that address.
    #[test]
    fn mail_goes_out_from_the_tenants_address_on_a_verified_domain() {
        let setup = Setup::sending_from("hello@acme.com", verified());

        let queued = setup.send_to(&Preference::Inherited);

        assert_eq!(queued.sender.as_deref(), Some("hello@acme.com"));
    }

    /// Losing verification of the configured sender's domain queues mail
    /// with the platform sender instead of Acme's address.
    #[test]
    fn a_domain_that_lost_verification_puts_mail_back_on_the_platform() {
        let failed = DomainProof::Lost {
            verified_at: clock::now() - time::Duration::minutes(30),
            failed_at: clock::now(),
        };
        let setup = Setup::sending_from("hello@acme.com", failed);

        let queued = setup.send_to(&Preference::Inherited);

        assert_eq!(queued.sender, None);
    }

    /// Mail of no tenant, such as to an organization member, goes out
    /// with the platform's template from the platform's address.
    #[test]
    fn mail_of_no_tenant_is_the_platforms() {
        let setup = Setup::holding_templates(&acme_welcomes());
        let to = Email::new("org@acme.com").unwrap();

        block_on(
            setup
                .mailer
                .send(&to, None, EmailTemplateType::Welcome, &HashMap::new()),
        )
        .unwrap();

        let queued = setup.outbox.last();
        assert_eq!(queued.template, Preference::Inherited);
        assert_eq!(queued.sender, None);
        assert_eq!(queued.tenant, None);
    }
}

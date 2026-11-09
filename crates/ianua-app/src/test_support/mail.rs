//! Mail a use case sends in tests, kept for the test to read back.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::branding::config::MailSender;
use ianua_domain::domains::branding::email_template::{
    EmailTemplateType, TemplateLocale, TemplateVariable,
};
use ianua_domain::domains::identity::account::address::MailReach;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, Locale, Preference, TenantId};

use crate::ports::shared::{MailOutbox, MailRecipient, MailSetup, Mailer, OutgoingMail};
use crate::test_support::Fake;

/// A record of one email a [`FakeMailer`] was asked to send.
pub struct SentEmail {
    /// The recipient address.
    pub to: String,
    /// The locale the mail was written for.
    pub locale: Preference<Locale>,
    /// Which template was rendered.
    pub template: EmailTemplateType,
    /// The variables the template was rendered with.
    pub variables: HashMap<TemplateVariable, String>,
}

/// Mailer that records every mail instead of sending it.
///
/// Composition and transport are exercised by the infra adapter's own
/// tests; here we only assert which emails a use case dispatched.
pub struct FakeMailer {
    /// Every dispatched email: recipient, template, and the variables it was
    /// rendered with, the action link included.
    pub sent: Mutex<Vec<SentEmail>>,
    delivery: Delivery,
}

/// Whether a fake mailer's mail service takes the mail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// The mail is accepted and recorded as sent.
    Accepts,
    /// The mail service refuses it, as if it were down.
    Refuses,
}

impl FakeMailer {
    /// Creates an empty mailer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            delivery: Delivery::Accepts,
        }
    }

    /// A mailer whose mail service refuses every mail.
    #[must_use]
    pub fn refusing() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            delivery: Delivery::Refuses,
        }
    }

    /// Number of emails dispatched.
    #[must_use]
    pub fn count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }

    /// The action link of the first email sent, as the recipient would click it.
    ///
    /// # Panics
    ///
    /// Panics if nothing was sent, or the email carried no action link.
    #[must_use]
    pub fn action_url(&self) -> String {
        self.sent
            .lock()
            .unwrap()
            .first()
            .expect("an email was sent")
            .variables
            .get(&TemplateVariable::ActionUrl)
            .expect("the email carries an action link")
            .clone()
    }

    /// Recipient addresses in dispatch order.
    #[must_use]
    pub fn recipients(&self) -> Vec<String> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .map(|sent| sent.to.clone())
            .collect()
    }
}

impl Default for FakeMailer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Mailer for FakeMailer {
    async fn send(
        &self,
        to: &Email,
        _tenant_id: Option<crate::tenancy::ScopedTenant>,
        template_type: EmailTemplateType,
        variables: &HashMap<TemplateVariable, String>,
    ) -> Result<(), DomainError> {
        self.record(to, Preference::Inherited, template_type, variables)
    }

    async fn send_to_person(
        &self,
        to: MailRecipient<'_>,
        _tenant_id: crate::tenancy::ScopedTenant,
        template_type: EmailTemplateType,
        variables: &HashMap<TemplateVariable, String>,
    ) -> Result<(), DomainError> {
        self.record(to.email, to.locale.clone(), template_type, variables)
    }
}

impl FakeMailer {
    /// Keeps one mail, or refuses it when the mail service is down.
    fn record(
        &self,
        to: &Email,
        locale: Preference<Locale>,
        template_type: EmailTemplateType,
        variables: &HashMap<TemplateVariable, String>,
    ) -> Result<(), DomainError> {
        if self.delivery == Delivery::Refuses {
            return Err(DomainError::infra_msg("the mail service is down"));
        }
        self.sent.lock().unwrap().push(SentEmail {
            to: to.as_str().to_owned(),
            locale,
            template: template_type,
            variables: variables.clone(),
        });
        Ok(())
    }
}

impl Fake for Arc<dyn Mailer> {
    fn fake() -> Self {
        Arc::new(FakeMailer::new())
    }
}

/// A deployment that can send mail, or one with no mail server set up.
pub struct FakeMailSetup(pub MailReach);

impl FakeMailSetup {
    /// A deployment with no mail server.
    #[must_use]
    pub fn not_set_up() -> Arc<dyn MailSetup> {
        Arc::new(Self(MailReach::NotSetUp))
    }
}

impl MailSetup for FakeMailSetup {
    fn reach(&self) -> MailReach {
        self.0
    }
}

impl Fake for Arc<dyn MailSetup> {
    fn fake() -> Self {
        Arc::new(FakeMailSetup(MailReach::Available))
    }
}

/// What a [`FakeMailOutbox`] kept of one queued mail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedMail {
    /// The recipient address.
    pub to: String,
    /// The tenant it was sent for.
    pub tenant: Option<TenantId>,
    /// The locale of the tenant's template it is rendered from, or
    /// inherited for the platform's mail.
    pub template: Preference<TemplateLocale>,
    /// The subject of the tenant's template, when it set one.
    pub subject: Option<String>,
    /// The tenant's address it goes out from, or none for the platform's.
    pub sender: Option<String>,
    /// The locale the recipient reads, when known.
    pub locale: Option<String>,
}

impl From<&OutgoingMail<'_>> for QueuedMail {
    fn from(mail: &OutgoingMail<'_>) -> Self {
        let custom = mail.template.value();
        Self {
            to: mail.to.as_str().to_owned(),
            tenant: mail.tenant.map(|tenant| **tenant),
            locale: mail.locale.map(|locale| locale.as_str().to_owned()),
            template: Preference::from_stored(custom.map(|template| template.locale().clone())),
            subject: custom
                .and_then(|template| template.subject().value())
                .map(|subject| subject.as_str().to_owned()),
            sender: match mail.sender {
                MailSender::Platform => None,
                MailSender::Tenant(address) => Some(address.as_str().to_owned()),
            },
        }
    }
}

/// Mail outbox that keeps every mail queued on it.
#[derive(Default)]
pub struct FakeMailOutbox {
    queued: Mutex<Vec<QueuedMail>>,
}

impl FakeMailOutbox {
    /// An outbox with nothing queued.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The mail queued last.
    ///
    /// # Panics
    ///
    /// Panics if nothing was queued.
    #[must_use]
    pub fn last(&self) -> QueuedMail {
        self.queued
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("a mail was queued")
    }
}

#[async_trait]
impl MailOutbox for FakeMailOutbox {
    async fn queue(&self, mail: &OutgoingMail<'_>) -> Result<(), DomainError> {
        self.queued.lock().unwrap().push(QueuedMail::from(mail));
        Ok(())
    }
}

impl Fake for Arc<dyn MailOutbox> {
    fn fake() -> Self {
        Arc::new(FakeMailOutbox::new())
    }
}

//! Sending mail, and who it goes to.

use std::collections::HashMap;

use async_trait::async_trait;
use ianua_domain::domains::branding::config::MailSender;
use ianua_domain::domains::branding::email_template::{
    EmailTemplate, EmailTemplateType, TemplateVariable,
};
use ianua_domain::domains::identity::account::address::MailReach;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, Label, Locale, Preference};

use crate::tenancy::ScopedTenant;

/// Dyn-safe port use cases send templated email through.
///
/// The use case decides *which* email to send (template type) and *what*
/// to put in it (variables). The app's
/// [`TenantMailer`](crate::services::branding::mailer::TenantMailer)
/// implements it: it picks the tenant's template for the recipient's
/// locale and the address the mail goes out from, then hands the mail to
/// the [`MailOutbox`].
#[async_trait]
pub trait Mailer: Send + Sync {
    /// Sends the `template_type` email filled with `variables`.
    ///
    /// When `tenant_id` is `Some`, the tenant's template for its own locale
    /// is used, as [`send_to_person`](Self::send_to_person) picks it for a
    /// recipient who follows the tenant's language. `None`, for
    /// organization mail that belongs to no tenant, always uses the
    /// platform's mail and address.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if a lookup or the queue fails.
    async fn send(
        &self,
        to: &Email,
        tenant_id: Option<ScopedTenant>,
        template_type: EmailTemplateType,
        variables: &HashMap<TemplateVariable, String>,
    ) -> Result<(), DomainError>;

    /// Sends the `template_type` email of `tenant_id` in `to`'s language,
    /// as [`send`](Self::send) does otherwise.
    ///
    /// The tenant's template is the one
    /// [`template_for`](ianua_domain::domains::branding::email_template::template_for)
    /// picks for the recipient's locale: their own locale's, else one of
    /// their language, else the tenant's template for every locale, else
    /// the platform's mail. A recipient who follows the tenant's language
    /// gets the tenant's locale.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if a lookup or the queue fails.
    async fn send_to_person(
        &self,
        to: MailRecipient<'_>,
        tenant_id: ScopedTenant,
        template_type: EmailTemplateType,
        variables: &HashMap<TemplateVariable, String>,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port saying whether this deployment can send mail at all.
///
/// A deployment with no mail server must not leave a sign-in waiting for a
/// confirmation link that never arrives: the sign-in owes a second factor
/// instead, or is refused when the person has none, as
/// [`FactorOwed::under`] decides from this answer.
///
/// [`FactorOwed::under`]: ianua_domain::domains::authentication::mfa::owed::FactorOwed::under
pub trait MailSetup: Send + Sync {
    /// Whether mail sent now goes out.
    fn reach(&self) -> MailReach;
}

/// Dyn-safe port taking mail whose template and sender are already chosen.
///
/// The adapter owns the template engine and the queue. It keeps the mail
/// sealed until it is sent, because the variables carry live links. When
/// it is sent it renders `template` over the platform's mail field by
/// field (subject, HTML, text), substitutes the variables as inert,
/// HTML-escaped data, so names and labels cannot inject markup or template
/// expressions, and sends it from `sender`.
#[async_trait]
pub trait MailOutbox: Send + Sync {
    /// Accepts `mail` for delivery.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the mail cannot be sealed
    /// or queued.
    async fn queue(&self, mail: &OutgoingMail<'_>) -> Result<(), DomainError>;
}

/// One mail, ready to be queued: who it goes to, which template it is
/// rendered from, and whose address it is sent from.
///
/// It has no `Debug`: the variables carry live sign-in and reset links.
pub struct OutgoingMail<'a> {
    /// The address it goes to.
    pub to: &'a Email,
    /// The tenant it is sent for, or none for mail of no tenant.
    pub tenant: Option<&'a ScopedTenant>,
    /// Which email it is.
    pub template_type: EmailTemplateType,
    /// The tenant's template picked for the recipient, or the platform's
    /// mail when it inherits.
    pub template: Preference<&'a EmailTemplate>,
    /// The locale the recipient reads, their own or their tenant's, which
    /// picks the language of the platform's mail. None for mail of no
    /// tenant to someone not known yet, which is sent in English.
    pub locale: Option<&'a Locale>,
    /// The address it is sent from.
    pub sender: MailSender<'a>,
    /// The name it is sent under, when the tenant set one.
    pub sender_name: Option<&'a Label>,
    /// The values the template is filled with.
    pub variables: &'a HashMap<TemplateVariable, String>,
}

/// A person a mail goes to: their address, and the language they read.
#[derive(Debug, Clone, Copy)]
pub struct MailRecipient<'a> {
    /// The address it goes to.
    pub email: &'a Email,
    /// The locale they chose, or that they follow the tenant's.
    pub locale: &'a Preference<Locale>,
}

//! Branding-specific ports.

use async_trait::async_trait;
use ianua_domain::domains::branding::config::{MailSender, TenantBranding};
use ianua_domain::domains::branding::email_template::{
    EmailTemplate, EmailTemplateType, TemplateSlot,
};
use ianua_domain::domains::branding::logo::LogoImage;
use ianua_domain::domains::branding::mail_provider::{MailProvider, TenantMailProvider};
use ianua_domain::domains::branding::renderer::RenderedEmail;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    Email, HttpsUrl, Label, Locale, Preference, RawCss, SanitizedCss, TenantId,
};

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::authentication::{SealOwner, SealedField, SealedFor};
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// Field an email-template listing can be ordered by.
    ///
    /// The `email_templates` table keys on `(tenant_id, template_type)` and
    /// carries no timestamp columns, so the email kind is the only stable
    /// ordering key.
    pub enum EmailTemplateSortField {
        /// Order by template type (the transactional email kind).
        TemplateType => "template_type",
    }
    default = TemplateType;
}

/// A tenant keeps one template per type and locale, so the locale breaks
/// ties between templates of one type.
impl SortKeys<EmailTemplateSortField> for EmailTemplate {
    fn sort_key(&self, field: EmailTemplateSortField) -> SortKey {
        match field {
            EmailTemplateSortField::TemplateType => self.template_type().name().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.locale().locale().map(Locale::as_str).into()
    }
}

/// Dyn-safe port for persisting and retrieving tenant branding.
#[async_trait]
pub trait BrandingStore: Send + Sync + TenantScoped {
    /// Loads the tenant's branding configuration.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<TenantBranding<ResolvedTenant>>, DomainError>;

    /// Saves the tenant's branding configuration.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        branding: &TenantBranding<ResolvedTenant>,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port that turns the CSS a tenant wrote into the only form a
/// page may render.
///
/// The adapter parses `raw` with a real CSS parser and writes back only the
/// plain rules [`SanitizedCss`] accepts, dropping everything else. The
/// result is checked again as it becomes a [`SanitizedCss`], so a careless
/// sanitizer still cannot hand a page an import, a `url()` or an attribute
/// selector. Parsing is pure work on the text, so the port is not async.
pub trait CssSanitizer: Send + Sync {
    /// The plain rules kept from `raw`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when nothing renderable is left,
    /// or what is left breaks a rule [`SanitizedCss`] keeps.
    fn sanitize(&self, raw: &RawCss) -> Result<SanitizedCss, DomainError>;
}

/// Dyn-safe port for persisting and retrieving email templates.
#[async_trait]
pub trait EmailTemplateStore: Send + Sync + TenantScoped {
    /// Finds the custom template kept in `slot`: one email, for one locale
    /// or for every locale without one of its own.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        slot: &TemplateSlot,
    ) -> Result<Option<EmailTemplate>, DomainError>;

    /// Every custom template of `template_type`, whatever locale each is
    /// written for, so the mailer picks the one a recipient gets with
    /// [`template_for`](ianua_domain::domains::branding::email_template::template_for).
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn list_for_type(
        &self,
        tenant_id: &ScopedTenant,
        template_type: EmailTemplateType,
    ) -> Result<Vec<EmailTemplate>, DomainError>;

    /// Saves a custom template in its slot, replacing the one there.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        template: &EmailTemplate,
    ) -> Result<(), DomainError>;

    /// One page of the tenant's custom templates, in `sort`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<EmailTemplateSortField>,
        page: &PageRequest,
    ) -> Result<Page<EmailTemplate>, DomainError>;

    /// Deletes the custom template in `slot`. Recipients it reached get the
    /// next template that fits them, or the platform's mail.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        slot: &TemplateSlot,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port keeping the mail provider each tenant's mail goes out
/// through.
#[async_trait]
pub trait TenantMailProviderStore: Send + Sync + TenantScoped {
    /// The tenant's mail provider, or `None` when it never named one and
    /// sends through the platform's own mail.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure, or when the
    /// stored row breaks a rule the provider keeps.
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<TenantMailProvider<ResolvedTenant>>, DomainError>;

    /// Saves the tenant's mail provider, replacing the one kept.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        provider: &TenantMailProvider<ResolvedTenant>,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port rendering an email the way the mailer would, filled with
/// sample values, for a preview or a test send.
///
/// The adapter fills every placeholder with an obvious sample: a made-up
/// name and address, and a link to a host that never resolves, so a
/// preview never carries a link that works. Substitution and escaping are
/// the mailer's own, so what is previewed is what is sent.
#[async_trait]
pub trait TemplateRenderer: Send + Sync {
    /// The `template_type` email of `tenant`, rendered from `custom`, or
    /// from the platform's own when it is inherited, with sample values.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the template cannot be
    /// rendered.
    async fn render_sample(
        &self,
        tenant_id: &ScopedTenant,
        template_type: EmailTemplateType,
        custom: Preference<&EmailTemplate>,
    ) -> Result<RenderedEmail, DomainError>;
}

/// Where the credential of the mail provider `tenant` named is sealed, or,
/// for mail of no tenant, the platform's place, which holds nothing sealed.
#[must_use]
pub fn mail_credential_place(tenant: Option<TenantId>) -> SealedFor {
    let record = tenant.map_or_else(|| "platform".to_owned(), |tenant| tenant.to_string());
    SealedFor::new(
        SealOwner::from(tenant),
        SealedField::MailProviderCredential,
        record,
    )
}

/// Dyn-safe port delivering one rendered email through a named mail
/// provider: the platform's own mail, an SMTP server, SendGrid, SES,
/// Postmark or Mailgun.
///
/// The adapter must:
/// - bound every delivery with a timeout, connecting and in all, so a
///   provider that hangs never holds a request or the mail queue;
/// - resolve an SMTP server's host again on every delivery and refuse an
///   address that is not public, so a tenant's server cannot be pointed
///   inward later;
/// - upgrade an SMTP connection to TLS as the provider says, and never send
///   when the upgrade is not offered;
/// - open the sealed credentials only to deliver, and never log them, the
///   body or the provider's answer;
/// - send from the tenant's address, and under its name, only when the
///   mail's sender is the tenant's; otherwise from the platform's address
///   under the platform's name.
#[async_trait]
pub trait MailProviderTransport: Send + Sync {
    /// Delivers `mail` through `provider`, whose credential is sealed for
    /// `credential`, as [`mail_credential_place`] names it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when an SMTP host no longer
    /// resolves to a public address, and `DomainError::Infrastructure` when
    /// the credential does not open there, or the provider cannot be
    /// reached in time or refuses the mail.
    async fn deliver(
        &self,
        provider: &MailProvider,
        credential: &SealedFor,
        mail: &AddressedMail<'_>,
    ) -> Result<(), DomainError>;
}

/// One rendered mail on its way to a provider: who it goes to, whose
/// address it goes out from, and what it says.
#[derive(Debug, Clone, Copy)]
pub struct AddressedMail<'a> {
    /// The address it goes to.
    pub to: &'a Email,
    /// Whose address it goes out from.
    pub sender: MailSender<'a>,
    /// The name it goes out under, when the tenant set one. Shown only
    /// beside the tenant's own address.
    pub sender_name: Option<&'a Label>,
    /// What it says.
    pub rendered: &'a RenderedEmail,
}

/// Dyn-safe port keeping each tenant's uploaded logo and serving it.
///
/// The image reaching it was checked as it became a [`LogoImage`]: a PNG or
/// a JPEG, within the size and dimensions a logo keeps. The adapter must
/// serve it only with the content type its checked format names, with
/// `X-Content-Type-Options: nosniff`, from a host that serves no page of
/// the platform's own. Uploading again replaces the tenant's logo.
#[async_trait]
pub trait LogoStore: Send + Sync + TenantScoped {
    /// Keeps `logo` as `tenant_id`'s logo, and answers with the public
    /// HTTPS address it is served at.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be kept.
    async fn put(
        &self,
        tenant_id: &ScopedTenant,
        logo: &LogoImage,
    ) -> Result<HttpsUrl, DomainError>;
}

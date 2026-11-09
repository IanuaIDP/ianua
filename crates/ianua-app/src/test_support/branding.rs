//! Fakes for the branding use cases.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::branding::config::{MailSender, TenantBranding};
use ianua_domain::domains::branding::email_template::{
    EmailTemplate, EmailTemplateType, TemplateSlot,
};
use ianua_domain::domains::branding::logo::LogoImage;
use ianua_domain::domains::branding::mail_provider::{
    MailProvider, MailProviderKind, ProviderCheck, TenantMailProvider, TenantMailProviderRow,
};
use ianua_domain::domains::branding::renderer::RenderedEmail;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    Email, HttpsUrl, Preference, RawCss, SanitizedCss, SealedSecret, TenantId,
};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::authentication::SealedFor;
use crate::ports::branding::{
    AddressedMail, BrandingStore, CssSanitizer, EmailTemplateSortField, EmailTemplateStore,
    LogoStore, MailProviderTransport, TemplateRenderer, TenantMailProviderStore,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::listing::page;

/// In-memory branding store for tests, one branding per tenant.
#[derive(Default)]
pub struct FakeBrandingStore {
    /// The stored branding, with the tenant each belongs to.
    pub branding: Mutex<Vec<(TenantId, TenantBranding<ResolvedTenant>)>>,
}

impl TenantScoped for FakeBrandingStore {}

impl FakeBrandingStore {
    /// Creates an empty store.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `branding` for `tenant`.
    #[must_use]
    pub fn holding(tenant: TenantId, branding: TenantBranding<ResolvedTenant>) -> Self {
        Self {
            branding: Mutex::new(vec![(tenant, branding)]),
        }
    }
}

#[async_trait]
impl BrandingStore for FakeBrandingStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<TenantBranding<ResolvedTenant>>, DomainError> {
        Ok(self
            .branding
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, _)| owner == &**tenant_id)
            .map(|(_, branding)| branding.clone()))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        branding: &TenantBranding<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut stored = self.branding.lock().unwrap();
        stored.retain(|(owner, _)| owner != &**tenant_id);
        stored.push((**tenant_id, branding.clone()));
        Ok(())
    }
}

/// In-memory email template store for tests, one template per tenant and
/// email kind.
#[derive(Default)]
pub struct FakeEmailTemplateStore {
    /// Stored templates, with the tenant each belongs to.
    pub templates: Mutex<Vec<(TenantId, EmailTemplate)>>,
}

impl TenantScoped for FakeEmailTemplateStore {}

impl FakeEmailTemplateStore {
    /// Creates an empty store.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Returns the number of stored templates, across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.templates.lock().unwrap().len()
    }
}

/// Whether `entry` is the tenant's template in `slot`.
fn is_kept(entry: &(TenantId, EmailTemplate), tenant: &ScopedTenant, slot: &TemplateSlot) -> bool {
    entry.0 == **tenant
        && entry.1.template_type() == slot.template_type
        && *entry.1.locale() == slot.locale
}

/// The slot `template` is kept in.
fn slot_of(template: &EmailTemplate) -> TemplateSlot {
    TemplateSlot {
        template_type: template.template_type(),
        locale: template.locale().clone(),
    }
}

#[async_trait]
impl EmailTemplateStore for FakeEmailTemplateStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        slot: &TemplateSlot,
    ) -> Result<Option<EmailTemplate>, DomainError> {
        Ok(self
            .templates
            .lock()
            .unwrap()
            .iter()
            .find(|entry| is_kept(entry, tenant_id, slot))
            .map(|(_, template)| template.clone()))
    }

    async fn list_for_type(
        &self,
        tenant_id: &ScopedTenant,
        template_type: EmailTemplateType,
    ) -> Result<Vec<EmailTemplate>, DomainError> {
        Ok(self
            .templates
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, template)| {
                owner == &**tenant_id && template.template_type() == template_type
            })
            .map(|(_, template)| template.clone())
            .collect())
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        template: &EmailTemplate,
    ) -> Result<(), DomainError> {
        let slot = slot_of(template);
        let mut templates = self.templates.lock().unwrap();
        templates.retain(|entry| !is_kept(entry, tenant_id, &slot));
        templates.push((**tenant_id, template.clone()));
        Ok(())
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<EmailTemplateSortField>,
        request: &PageRequest,
    ) -> Result<Page<EmailTemplate>, DomainError> {
        let all: Vec<_> = self
            .templates
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, _)| owner == &**tenant_id)
            .map(|(_, template)| template.clone())
            .collect();
        page(all, sort, request)
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        slot: &TemplateSlot,
    ) -> Result<(), DomainError> {
        self.templates
            .lock()
            .unwrap()
            .retain(|entry| !is_kept(entry, tenant_id, slot));
        Ok(())
    }
}

/// CSS sanitizer for tests that keeps each `... }` block a sanitized
/// stylesheet accepts on its own, and drops the rest.
pub struct FakeCssSanitizer;

impl CssSanitizer for FakeCssSanitizer {
    fn sanitize(&self, raw: &RawCss) -> Result<SanitizedCss, DomainError> {
        let kept: Vec<String> = raw
            .as_str()
            .split_inclusive('}')
            .map(str::trim)
            .filter(|block| SanitizedCss::new(*block).is_ok())
            .map(str::to_owned)
            .collect();
        Ok(SanitizedCss::new(kept.join("\n"))?)
    }
}

impl Fake for Arc<dyn CssSanitizer> {
    fn fake() -> Self {
        Arc::new(FakeCssSanitizer)
    }
}

impl Fake for Arc<dyn BrandingStore> {
    fn fake() -> Self {
        Arc::new(FakeBrandingStore::empty())
    }
}

impl Fake for Arc<dyn EmailTemplateStore> {
    fn fake() -> Self {
        Arc::new(FakeEmailTemplateStore::empty())
    }
}

/// In-memory store of each tenant's mail provider.
#[derive(Default)]
pub struct FakeTenantMailProviderStore {
    providers: Mutex<Vec<(TenantId, TenantMailProvider<ResolvedTenant>)>>,
}

impl TenantScoped for FakeTenantMailProviderStore {}

impl FakeTenantMailProviderStore {
    /// A store where no tenant named a provider.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `provider` for `tenant`.
    #[must_use]
    pub fn holding(tenant: TenantId, provider: TenantMailProvider<ResolvedTenant>) -> Self {
        Self {
            providers: Mutex::new(vec![(tenant, provider)]),
        }
    }

    /// The provider `tenant` keeps, as last saved.
    #[must_use]
    pub fn stored(&self, tenant: TenantId) -> Option<TenantMailProvider<ResolvedTenant>> {
        self.providers
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, _)| *owner == tenant)
            .map(|(_, provider)| provider.clone())
    }
}

#[async_trait]
impl TenantMailProviderStore for FakeTenantMailProviderStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<TenantMailProvider<ResolvedTenant>>, DomainError> {
        Ok(self.stored(**tenant_id))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        provider: &TenantMailProvider<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut providers = self.providers.lock().unwrap();
        providers.retain(|(owner, _)| owner != &**tenant_id);
        providers.push((**tenant_id, provider.clone()));
        Ok(())
    }
}

impl Fake for Arc<dyn TenantMailProviderStore> {
    fn fake() -> Self {
        Arc::new(FakeTenantMailProviderStore::empty())
    }
}

/// Delivers mail by noting which kind of provider took it for whom, and
/// from whose address, or refuses every one.
#[derive(Default)]
pub struct FakeMailProviderTransport {
    delivered: Mutex<Vec<(MailProviderKind, Email)>>,
    senders: Mutex<Vec<Option<Email>>>,
    refusing: bool,
}

impl FakeMailProviderTransport {
    /// A transport whose every provider takes the mail.
    #[must_use]
    pub fn delivering() -> Self {
        Self::default()
    }

    /// A transport whose every provider refuses the mail.
    #[must_use]
    pub fn refusing() -> Self {
        Self {
            refusing: true,
            ..Self::default()
        }
    }

    /// Which kind of provider took each mail, and for whom, in order.
    #[must_use]
    pub fn delivered(&self) -> Vec<(MailProviderKind, Email)> {
        self.delivered.lock().unwrap().clone()
    }

    /// The address each delivered mail went out from: the tenant's own, or
    /// `None` for the platform's, in order.
    #[must_use]
    pub fn senders(&self) -> Vec<Option<Email>> {
        self.senders.lock().unwrap().clone()
    }
}

#[async_trait]
impl MailProviderTransport for FakeMailProviderTransport {
    async fn deliver(
        &self,
        provider: &MailProvider,
        _: &SealedFor,
        mail: &AddressedMail<'_>,
    ) -> Result<(), DomainError> {
        if self.refusing {
            return Err(DomainError::infra_msg("the provider refused the mail"));
        }
        self.delivered
            .lock()
            .unwrap()
            .push((provider.kind(), mail.to.clone()));
        let from = match mail.sender {
            MailSender::Platform => None,
            MailSender::Tenant(address) => Some(address.clone()),
        };
        self.senders.lock().unwrap().push(from);
        Ok(())
    }
}

impl Fake for Arc<dyn MailProviderTransport> {
    fn fake() -> Self {
        Arc::new(FakeMailProviderTransport::delivering())
    }
}

/// Keeps each tenant's logo in memory and serves it at a fixed address.
#[derive(Default)]
pub struct FakeLogoStore {
    logos: Mutex<Vec<(TenantId, LogoImage)>>,
}

impl TenantScoped for FakeLogoStore {}

impl FakeLogoStore {
    /// The logo `tenant` keeps now.
    #[must_use]
    pub fn stored(&self, tenant: TenantId) -> Option<LogoImage> {
        self.logos
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, _)| *owner == tenant)
            .map(|(_, logo)| logo.clone())
    }

    /// Where `tenant`'s logo is served.
    ///
    /// # Panics
    ///
    /// Never: the address is a fixed, valid HTTPS URL.
    #[must_use]
    pub fn served_at(tenant: TenantId) -> HttpsUrl {
        HttpsUrl::new(format!("https://assets.ianua.test/{tenant}/logo"))
            .expect("a fixed HTTPS address")
    }
}

#[async_trait]
impl LogoStore for FakeLogoStore {
    async fn put(
        &self,
        tenant_id: &ScopedTenant,
        logo: &LogoImage,
    ) -> Result<HttpsUrl, DomainError> {
        let mut logos = self.logos.lock().unwrap();
        logos.retain(|(owner, _)| owner != &**tenant_id);
        logos.push((**tenant_id, logo.clone()));
        Ok(Self::served_at(**tenant_id))
    }
}

impl Fake for Arc<dyn LogoStore> {
    fn fake() -> Self {
        Arc::new(FakeLogoStore::default())
    }
}

/// A 400 by 120 PNG logo, as Acme uploads it.
///
/// # Panics
///
/// Never: the bytes are a well-formed PNG header of a logo's size.
#[must_use]
pub fn acme_logo() -> LogoImage {
    let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    bytes.extend_from_slice(&13_u32.to_be_bytes());
    bytes.extend_from_slice(b"IHDR");
    bytes.extend_from_slice(&400_u32.to_be_bytes());
    bytes.extend_from_slice(&120_u32.to_be_bytes());
    bytes.extend_from_slice(&[8, 6, 0, 0, 0]);
    LogoImage::new(bytes).expect("a PNG of a logo's size")
}

/// The subject a [`FakeTemplateRenderer`] gives the platform's own email.
pub const PLATFORM_SUBJECT: &str = "The platform's email";

/// Renders a tenant's template as its own subject, or the platform's as
/// [`PLATFORM_SUBJECT`], with a fixed body.
pub struct FakeTemplateRenderer;

#[async_trait]
impl TemplateRenderer for FakeTemplateRenderer {
    async fn render_sample(
        &self,
        _: &ScopedTenant,
        _: EmailTemplateType,
        custom: Preference<&EmailTemplate>,
    ) -> Result<RenderedEmail, DomainError> {
        let subject = match custom {
            Preference::Own(template) => match template.subject() {
                Preference::Own(subject) => subject.as_str().to_owned(),
                Preference::Inherited => PLATFORM_SUBJECT.to_owned(),
            },
            Preference::Inherited => PLATFORM_SUBJECT.to_owned(),
        };
        Ok(RenderedEmail::text_only(subject, "Hello Sample User"))
    }
}

impl Fake for Arc<dyn TemplateRenderer> {
    fn fake() -> Self {
        Arc::new(FakeTemplateRenderer)
    }
}

/// A SendGrid account, its API key sealed.
///
/// # Panics
///
/// Never: the sealed form is a fixed, valid token.
#[must_use]
pub fn sendgrid_provider() -> MailProvider {
    MailProvider::SendGrid {
        api_key: SealedSecret::new("enc_sendgrid").expect("a sealed form is a token"),
    }
}

/// A tenant's [`sendgrid_provider`], named and tested now, so its mail
/// goes out through it.
///
/// # Panics
///
/// Never: a SendGrid account tested when it was named is a valid row.
#[must_use]
pub fn tested_sendgrid() -> TenantMailProvider<ResolvedTenant> {
    let now = clock::now();
    TenantMailProvider::reconstitute(TenantMailProviderRow {
        provider: sendgrid_provider(),
        check: ProviderCheck::Verified { at: now },
        updated_at: now,
    })
    .expect("a tested SendGrid account is a valid row")
}

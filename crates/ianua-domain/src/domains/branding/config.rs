use std::marker::PhantomData;

use crate::domains::branding::control::BrandingControl;
use crate::domains::branding::events::{BrandingPart, BrandingUpdated};
use crate::domains::branding::logo::LogoImage;
use crate::domains::tenant::custom_domains::registered_domain::RegisteredDomain;
use crate::domains::tenant::custom_domains::verification_status::VerificationStatus;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::types::{Email, HexColor, HttpsUrl, Label, RawCss, SanitizedCss, Setting};

/// A tenant's custom CSS: what they wrote, and the safe form a page renders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomCss {
    source: RawCss,
    rendered: SanitizedCss,
}

impl CustomCss {
    /// The CSS the tenant wrote, and what a sanitizer made of it.
    #[must_use]
    pub fn new(source: RawCss, rendered: SanitizedCss) -> Self {
        Self { source, rendered }
    }

    /// What the tenant wrote, for them to edit. Never placed in a page.
    #[must_use]
    pub fn source(&self) -> &RawCss {
        &self.source
    }

    /// What a page renders.
    #[must_use]
    pub fn rendered(&self) -> &SanitizedCss {
        &self.rendered
    }
}

/// A tenant's look on its login page and in its emails.
///
/// It holds the logo, colors, custom CSS and email sender. Each part is the
/// tenant's own when set and the platform's default when unset. Custom
/// domains live in [`RegisteredDomain`], not here.
#[derive(Debug, Clone)]
pub struct TenantBranding<T: TenantScope> {
    /// Tenant's logo image URL (must be HTTPS).
    logo_url: Setting<HttpsUrl>,

    /// Primary brand color for buttons and links.
    primary_color: Setting<HexColor>,

    /// Background color for the login page.
    background_color: Setting<HexColor>,

    /// Custom CSS for the login page, as written and as rendered.
    custom_css: Setting<CustomCss>,

    /// Display name used as the "From" name in emails
    /// (e.g. `"Acme Security"`).
    email_from_name: Setting<Label>,

    /// Email address used as the "From" address in emails.
    email_from_address: Setting<Email>,

    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// Stored fields of a [`TenantBranding`], read back by repositories.
pub struct TenantBrandingRow {
    /// Tenant's logo image URL.
    pub logo_url: Setting<HttpsUrl>,
    /// Primary brand color for buttons and links.
    pub primary_color: Setting<HexColor>,
    /// Background color for the login page.
    pub background_color: Setting<HexColor>,
    /// Custom CSS for the login page, as written and as rendered.
    pub custom_css: Setting<CustomCss>,
    /// The "From" name used in tenant emails.
    pub email_from_name: Setting<Label>,
    /// The "From" address used in tenant emails.
    pub email_from_address: Setting<Email>,
}

impl<T: TenantScope> TenantBranding<T> {
    /// Creates a branding config with no customization (platform defaults).
    ///
    /// The platform makes it once, as it provisions the tenant. It shows only
    /// the platform's own look, so nobody decides anything by making it.
    #[must_use]
    pub fn default_branding() -> Self {
        Self {
            logo_url: Setting::Unset,
            primary_color: Setting::Unset,
            background_color: Setting::Unset,
            custom_css: Setting::Unset,
            email_from_name: Setting::Unset,
            email_from_address: Setting::Unset,
            raised: Raised::default(),
            _scope: PhantomData,
        }
    }

    /// Rebuilds a tenant's branding from storage.
    ///
    /// # Errors
    ///
    /// - None. Each field is already a checked type and no two fields can
    ///   contradict each other.
    pub fn reconstitute(row: TenantBrandingRow) -> Result<Self, DomainError> {
        Ok(Self {
            logo_url: row.logo_url,
            primary_color: row.primary_color,
            background_color: row.background_color,
            custom_css: row.custom_css,
            email_from_name: row.email_from_name,
            email_from_address: row.email_from_address,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The tenant's logo URL, displayed on the login page.
    #[must_use]
    pub fn logo_url(&self) -> Option<&HttpsUrl> {
        self.logo_url.value()
    }

    /// The primary brand color (hex, e.g. `"#FF5733"`).
    #[must_use]
    pub fn primary_color(&self) -> Option<&HexColor> {
        self.primary_color.value()
    }

    /// The login page background color (hex).
    #[must_use]
    pub fn background_color(&self) -> Option<&HexColor> {
        self.background_color.value()
    }

    /// The custom CSS a login page renders. This is always the sanitized form.
    #[must_use]
    pub fn custom_css(&self) -> Option<&SanitizedCss> {
        self.custom_css.value().map(CustomCss::rendered)
    }

    /// The custom CSS as the tenant wrote it, for them to edit. Never placed
    /// in a page.
    #[must_use]
    pub fn custom_css_source(&self) -> Option<&RawCss> {
        self.custom_css.value().map(CustomCss::source)
    }

    /// The "From" name used in tenant emails.
    #[must_use]
    pub fn email_from_name(&self) -> Option<&Label> {
        self.email_from_name.value()
    }

    /// The "From" address used in tenant emails.
    #[must_use]
    pub fn email_from_address(&self) -> Option<&Email> {
        self.email_from_address.value()
    }

    /// Whether any visual customization has been applied.
    #[must_use]
    pub fn has_customization(&self) -> bool {
        !self.logo_url.is_unset()
            || !self.primary_color.is_unset()
            || !self.background_color.is_unset()
            || !self.custom_css.is_unset()
    }

    /// Shows `logo` on the tenant's pages, or the platform's when unset.
    ///
    /// Raises `branding.updated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change branding.
    pub fn change_logo(
        &mut self,
        logo: Setting<HttpsUrl>,
        by: &BrandingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may_change()?;
        self.logo_url = logo;
        self.settings_changed();
        Ok(())
    }

    /// Shows `logo`, an image the tenant uploaded that the platform now
    /// serves at `served_at`, on the tenant's pages. Raises
    /// `branding.updated`, naming the logo and its format.
    ///
    /// The image was checked as it became a [`LogoImage`]: a PNG or a JPEG,
    /// within the size and dimensions a logo keeps. The branding keeps only
    /// where it is served.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change branding.
    pub fn upload_logo(
        &mut self,
        logo: &LogoImage,
        served_at: HttpsUrl,
        by: &BrandingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may_change()?;
        self.logo_url = Setting::Set(served_at);
        self.raised.raise(BrandingUpdated {
            part: BrandingPart::UploadedLogo(logo.format()),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Colors buttons and links `color`, or the platform's when unset.
    ///
    /// Raises `branding.updated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change branding.
    pub fn change_primary_color(
        &mut self,
        color: Setting<HexColor>,
        by: &BrandingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may_change()?;
        self.primary_color = color;
        self.settings_changed();
        Ok(())
    }

    /// Colors the login page's background `color`, or the platform's when
    /// unset.
    ///
    /// Raises `branding.updated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change branding.
    pub fn change_background_color(
        &mut self,
        color: Setting<HexColor>,
        by: &BrandingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may_change()?;
        self.background_color = color;
        self.settings_changed();
        Ok(())
    }

    /// Styles the login page with `css`, already sanitized, or with none
    /// when unset.
    ///
    /// Raises `branding.updated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change branding.
    pub fn change_custom_css(
        &mut self,
        css: Setting<CustomCss>,
        by: &BrandingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may_change()?;
        self.custom_css = css;
        self.settings_changed();
        Ok(())
    }

    /// Sends the tenant's mail under `name`, or the platform's when unset.
    ///
    /// Raises `branding.updated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change branding.
    pub fn change_sender_name(
        &mut self,
        name: Setting<Label>,
        by: &BrandingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may_change()?;
        self.email_from_name = name;
        self.settings_changed();
        Ok(())
    }

    /// Sends the tenant's mail from `address`, on a domain the tenant has
    /// proved it controls.
    ///
    /// Eve runs a tenant. Without this check she sends password resets as
    /// `security@bank.com`, from our servers and signed by us.
    ///
    /// Raises `branding.updated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change branding.
    /// - [`DomainError::Forbidden`] when `domain` is not verified.
    /// - [`DomainError::Forbidden`] when `address` is not on `domain`.
    pub fn send_from(
        &mut self,
        address: Email,
        domain: &RegisteredDomain<T>,
        by: &BrandingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may_change()?;
        if domain.verification_status() != VerificationStatus::Verified {
            return Err(DomainError::forbidden(message!(
                "branding-mail-is-sent-only-from-a",
                "mail is sent only from a domain the tenant has verified"
            )));
        }
        if !address
            .domain()
            .eq_ignore_ascii_case(domain.domain().as_str())
        {
            return Err(DomainError::forbidden(message!(
                "branding-the-sender-address-must-be-on",
                "the sender address must be on the verified domain"
            )));
        }
        self.email_from_address = Setting::Set(address);
        self.settings_changed();
        Ok(())
    }

    /// Sends the tenant's mail from the platform's own address again.
    ///
    /// Raises `branding.updated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change branding.
    pub fn send_from_platform(&mut self, by: &BrandingControl<'_>) -> Result<(), DomainError> {
        by.ensure_may_change()?;
        self.email_from_address = Setting::Unset;
        self.settings_changed();
        Ok(())
    }

    /// The address mail goes out from, checked against `domain` as it is now.
    ///
    /// It is the tenant's address only while that address is on `domain` and
    /// `domain` is verified. Otherwise it is the platform's address. A domain
    /// can fail verification after the address was set, and mail must then
    /// stop going out under the tenant's name.
    #[must_use]
    pub fn sender_on(&self, domain: &RegisteredDomain<T>) -> MailSender<'_> {
        let Setting::Set(address) = &self.email_from_address else {
            return MailSender::Platform;
        };
        let on_domain = address
            .domain()
            .eq_ignore_ascii_case(domain.domain().as_str());
        if !on_domain || domain.verification_status() != VerificationStatus::Verified {
            return MailSender::Platform;
        }
        MailSender::Tenant(address)
    }

    /// Raises `branding.updated` for the settings. Each change raises it;
    /// [`Raises::take_events`] hands over one per save.
    fn settings_changed(&mut self) {
        self.raised.raise(BrandingUpdated {
            part: BrandingPart::Settings,
            occurred_at: crate::shared::clock::now(),
        });
    }
}

/// However many parts of the branding one save changed, the audit trail
/// records one `branding.updated`, at the first of them.
impl<T: TenantScope> Raises for TenantBranding<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        let mut events = self.raised.take(saved_for);
        events.dedup_by_key(|event| event.event_type());
        events
    }
}

/// Whose address a piece of mail is sent from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailSender<'a> {
    /// The platform's own address.
    Platform,
    /// The tenant's address, on a domain it still proves it controls.
    Tenant(&'a Email),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::{BrandingAction, SystemPermission};
    use crate::domains::branding::fixtures::png;
    use crate::domains::tenant::control::TenantControl;
    use crate::domains::tenant::custom_domains::registered_domain::{
        DomainConnection, DomainVerificationToken, NewDomain,
    };
    use crate::isolation::scope::{ResolvedTenant, TenantScope};
    use crate::shared::config::SlugLimits;
    use crate::shared::events::data::FieldValue;
    use crate::test_support::authority::{anyone_holding, assumed_authority};
    use crate::test_support::builders::label;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{DomainName, Human, HumanAccount, PersonKey, TenantId, TenantSlug, UserId};

    fn editor() -> BrandingControl<'static> {
        BrandingControl::new(anyone_holding(&[SystemPermission::Branding(
            BrandingAction::Update,
        )]))
    }

    fn viewer() -> BrandingControl<'static> {
        BrandingControl::new(anyone_holding(&[SystemPermission::Branding(
            BrandingAction::View,
        )]))
    }

    /// A branding viewer cannot change the logo, colors, CSS or sender
    /// settings; the default appearance and unset sender name remain.
    #[test]
    fn a_viewer_may_not_change_branding() {
        let mut branding = TenantBranding::<ResolvedTenant>::default_branding();
        let sams_logo = Setting::Set(HttpsUrl::new("https://sam.example.com/l.png").unwrap());
        let black = || Setting::Set(HexColor::new("#000000").unwrap());

        let refused = [
            branding.change_logo(sams_logo, &viewer()),
            branding.change_primary_color(black(), &viewer()),
            branding.change_background_color(black(), &viewer()),
            branding.change_custom_css(Setting::Set(custom("a{}", "a{}")), &viewer()),
            branding.change_sender_name(Setting::Set(label("IT Support")), &viewer()),
            branding.send_from_platform(&viewer()),
        ];

        for change in refused {
            assert!(matches!(change, Err(DomainError::Forbidden(_))));
        }
        assert!(!branding.has_customization());
        assert!(branding.email_from_name().is_none());
    }

    /// A branding viewer cannot set a sender address even on a verified
    /// domain, leaving the address unset.
    #[test]
    fn a_viewer_may_not_set_the_sender_address() {
        let mut branding = TenantBranding::<ResolvedTenant>::default_branding();

        let sent = branding.send_from(
            Email::new("noreply@acme.com").unwrap(),
            &domain("acme.com", true),
            &viewer(),
        );

        assert!(matches!(sent, Err(DomainError::Forbidden(_))));
        assert!(branding.email_from_address().is_none());
    }

    /// A new tenant has not branded anything yet. Logo, colour and sender all
    /// read as unset, so every page shows the platform's look.
    #[test]
    fn default_has_no_customization() {
        let branding = TenantBranding::<ResolvedTenant>::default_branding();

        assert!(!branding.has_customization());
        assert!(branding.logo_url().is_none());
        assert!(branding.primary_color().is_none());
        assert!(branding.email_from_address().is_none());
    }

    /// Acme sets a logo, a primary colour and a background colour. They read
    /// back as set and the branding counts as customized.
    #[test]
    fn a_tenant_brands_its_login_page() {
        let mut branding = TenantBranding::<ResolvedTenant>::default_branding();
        let logo = HttpsUrl::new("https://acme.com/logo.png").unwrap();

        branding.change_logo(Setting::Set(logo), &editor()).unwrap();
        branding
            .change_primary_color(Setting::Set(colour("#FF5733")), &editor())
            .unwrap();
        branding
            .change_background_color(Setting::Set(colour("#FFFFFF")), &editor())
            .unwrap();

        assert!(branding.has_customization());
        assert_eq!(
            branding.logo_url().map(HttpsUrl::as_str),
            Some("https://acme.com/logo.png")
        );
        assert_eq!(
            branding.primary_color().map(HexColor::as_str),
            Some("#FF5733")
        );
    }

    fn domain(name: &str, verified: bool) -> RegisteredDomain<ResolvedTenant> {
        let scope = ResolvedTenant::new(
            TenantId::new(),
            TenantSlug::new("acme", &SlugLimits::default()).unwrap(),
        );
        let admin = Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("admin@acme.test").unwrap(),
        );
        let authority = assumed_authority(&admin, *scope.tenant_id(), SystemPermission::all(), &[]);
        let mut domain = RegisteredDomain::register(
            NewDomain {
                domain: DomainName::new(name).unwrap(),
                connection: DomainConnection::SelfManaged,
                dns_challenge_token: DomainVerificationToken::new("token").unwrap(),
            },
            &scope,
            TenantControl::new(authority),
        )
        .unwrap();
        if verified {
            domain.mark_verified().unwrap();
        }
        domain
    }

    fn colour(hex: &str) -> HexColor {
        HexColor::new(hex).unwrap()
    }

    /// Acme has verified `acme.com` and sends from `noreply@acme.com` as
    /// "Acme Security". Both the sender name and address are kept.
    #[test]
    fn mail_is_sent_from_an_address_on_a_verified_domain() {
        let mut branding = TenantBranding::<ResolvedTenant>::default_branding();

        branding
            .change_sender_name(Setting::Set(label("Acme Security")), &editor())
            .unwrap();
        branding
            .send_from(
                Email::new("noreply@acme.com").unwrap(),
                &domain("acme.com", true),
                &editor(),
            )
            .unwrap();

        assert_eq!(
            branding.email_from_name().map(Label::as_str),
            Some("Acme Security")
        );
        assert_eq!(
            branding.email_from_address().map(Email::as_str),
            Some("noreply@acme.com")
        );
    }

    /// After a sender's verified domain fails verification, sender selection
    /// returns to the platform address instead of the tenant address.
    #[test]
    fn mail_goes_out_from_the_platform_once_the_domain_loses_its_proof() {
        let mut branding = TenantBranding::<ResolvedTenant>::default_branding();
        let mut acme = domain("acme.com", true);
        branding
            .send_from(Email::new("noreply@acme.com").unwrap(), &acme, &editor())
            .unwrap();
        assert!(matches!(branding.sender_on(&acme), MailSender::Tenant(_)));

        acme.mark_verification_failed().unwrap();

        assert_eq!(branding.sender_on(&acme), MailSender::Platform);
    }

    /// A tenant has a verified domain but never set a sender address. Its
    /// mail goes out from the platform's address.
    #[test]
    fn mail_goes_out_from_the_platform_when_no_sender_is_set() {
        let branding = TenantBranding::<ResolvedTenant>::default_branding();

        assert_eq!(
            branding.sender_on(&domain("acme.com", true)),
            MailSender::Platform
        );
    }

    /// A sender on an unverified domain and an address outside the verified
    /// domain are both rejected, leaving the sender address unset.
    #[test]
    fn a_sender_off_a_verified_domain_is_refused() {
        let mut branding = TenantBranding::<ResolvedTenant>::default_branding();

        let unverified = branding.send_from(
            Email::new("noreply@acme.com").unwrap(),
            &domain("acme.com", false),
            &editor(),
        );
        let elsewhere = branding.send_from(
            Email::new("security@bank.com").unwrap(),
            &domain("acme.com", true),
            &editor(),
        );

        assert!(unverified.is_err());
        assert!(elsewhere.is_err());
        assert!(branding.email_from_address().is_none());
    }

    fn custom(source: &str, rendered: &str) -> CustomCss {
        CustomCss::new(
            RawCss::new(source).unwrap(),
            SanitizedCss::new(rendered).unwrap(),
        )
    }

    /// A tenant's CSS holds a selector the sanitizer dropped. The page gets
    /// only the sanitized rules, while the editor still shows what the tenant
    /// wrote.
    #[test]
    fn a_page_renders_the_sanitized_css_and_the_tenant_edits_the_source() {
        let mut branding = TenantBranding::<ResolvedTenant>::default_branding();

        let css = custom(
            ".login { padding: 20px; } input[value^=a] { color: red }",
            ".login { padding: 20px; }",
        );

        branding
            .change_custom_css(Setting::Set(css), &editor())
            .unwrap();

        assert_eq!(
            branding.custom_css().map(SanitizedCss::as_str),
            Some(".login { padding: 20px; }")
        );
        assert_eq!(
            branding.custom_css_source().map(RawCss::as_str),
            Some(".login { padding: 20px; } input[value^=a] { color: red }")
        );
        assert!(branding.has_customization());
    }

    /// A tenant sets a logo and then unsets it. With nothing else set, the
    /// branding no longer counts as customized.
    #[test]
    fn clear_all_customization() {
        let mut branding = TenantBranding::<ResolvedTenant>::default_branding();
        let logo = HttpsUrl::new("https://x.com/l.png").unwrap();
        branding.change_logo(Setting::Set(logo), &editor()).unwrap();

        branding.change_logo(Setting::Unset, &editor()).unwrap();

        assert!(!branding.has_customization());
    }

    /// A stored row with some fields set and some unset is read back. Each
    /// field comes back exactly as stored.
    #[test]
    fn reconstitute_preserves_all_fields() {
        let branding = TenantBranding::<ResolvedTenant>::reconstitute(TenantBrandingRow {
            logo_url: Setting::Set(HttpsUrl::new("https://acme.com/logo.png").unwrap()),
            primary_color: Setting::Set(HexColor::new("#ABC").unwrap()),
            background_color: Setting::Unset,
            custom_css: Setting::Unset,
            email_from_name: Setting::Set(label("Acme")),
            email_from_address: Setting::Set(Email::new("no-reply@acme.com").unwrap()),
        })
        .unwrap();

        assert_eq!(
            branding.logo_url().map(HttpsUrl::as_str),
            Some("https://acme.com/logo.png")
        );
        assert_eq!(branding.primary_color().map(HexColor::as_str), Some("#ABC"));
        assert!(branding.background_color().is_none());
        assert_eq!(branding.email_from_name().map(Label::as_str), Some("Acme"));
    }

    /// A tenant unsets its sender name. It reads as none, so mail uses the
    /// platform's name.
    #[test]
    fn an_unset_sender_name_reads_as_none() {
        let mut branding = TenantBranding::<ResolvedTenant>::default_branding();
        branding
            .change_sender_name(Setting::Unset, &editor())
            .unwrap();
        assert!(branding.email_from_name().is_none());
    }

    /// A tenant sets its background to `#101828`. It reads back as that
    /// colour, so the login page shows the same choice as the dashboard.
    #[test]
    fn the_background_colour_reads_back_as_the_one_set() {
        let mut branding = TenantBranding::<ResolvedTenant>::default_branding();
        assert_eq!(branding.background_color(), None);

        branding
            .change_background_color(Setting::Set(colour("#101828")), &editor())
            .unwrap();

        assert_eq!(
            branding.background_color().map(HexColor::as_str),
            Some("#101828")
        );
    }

    /// Four tenants each set only one thing: a logo, a primary colour, a
    /// background or custom CSS. Each one counts as customized on its own.
    #[test]
    fn any_single_customization_counts_as_branding() {
        assert!(!TenantBranding::<ResolvedTenant>::default_branding().has_customization());

        let logo = HttpsUrl::new("https://acme.com/logo.png").unwrap();
        let css = custom("body { margin: 0 }", "body { margin: 0 }");

        let mut with_logo = TenantBranding::<ResolvedTenant>::default_branding();
        with_logo
            .change_logo(Setting::Set(logo), &editor())
            .unwrap();
        assert!(with_logo.has_customization());

        let mut with_primary = TenantBranding::<ResolvedTenant>::default_branding();
        with_primary
            .change_primary_color(Setting::Set(colour("#FF5733")), &editor())
            .unwrap();
        assert!(with_primary.has_customization());

        let mut with_background = TenantBranding::<ResolvedTenant>::default_branding();
        with_background
            .change_background_color(Setting::Set(colour("#101828")), &editor())
            .unwrap();
        assert!(with_background.has_customization());

        let mut with_css = TenantBranding::<ResolvedTenant>::default_branding();
        with_css
            .change_custom_css(Setting::Set(css), &editor())
            .unwrap();
        assert!(with_css.has_customization());
    }

    /// Fay sets Acme's logo, both colours and the sender name in one go.
    /// One `branding.updated` is raised for the save, naming the settings.
    #[test]
    fn several_changes_before_a_save_raise_one_update() {
        let mut branding = TenantBranding::<ResolvedTenant>::default_branding();
        let logo = HttpsUrl::new("https://acme.com/logo.png").unwrap();

        branding.change_logo(Setting::Set(logo), &editor()).unwrap();
        branding
            .change_primary_color(Setting::Set(colour("#FF5733")), &editor())
            .unwrap();
        branding
            .change_background_color(Setting::Set(colour("#FFFFFF")), &editor())
            .unwrap();
        branding
            .change_sender_name(Setting::Set(label("Acme Security")), &editor())
            .unwrap();
        let events = raised(&mut branding);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type().to_string(), "branding.updated");
        assert_eq!(
            events[0].payload().value("part"),
            Some(&FieldValue::Text("settings".to_owned()))
        );
    }

    /// Fay sets Acme's sender address on its verified domain, saves, and
    /// later moves the mail back to the platform's address. Each save
    /// raises its own update.
    #[test]
    fn each_save_raises_its_own_update() {
        let mut branding = TenantBranding::<ResolvedTenant>::default_branding();

        branding
            .send_from(
                Email::new("noreply@acme.com").unwrap(),
                &domain("acme.com", true),
                &editor(),
            )
            .unwrap();
        let first = raised_names(&mut branding);
        branding.send_from_platform(&editor()).unwrap();
        let second = raised_names(&mut branding);

        assert_eq!(first, ["branding.updated"]);
        assert_eq!(second, ["branding.updated"]);
    }

    /// A viewer's logo change and an editor's unverified sender address are
    /// both rejected without raising branding events.
    #[test]
    fn a_refused_branding_change_raises_nothing() {
        let mut branding = TenantBranding::<ResolvedTenant>::default_branding();
        let logo = HttpsUrl::new("https://sam.example.com/l.png").unwrap();

        let swapped = branding.change_logo(Setting::Set(logo), &viewer());
        let sent = branding.send_from(
            Email::new("noreply@acme.com").unwrap(),
            &domain("acme.com", false),
            &editor(),
        );

        assert!(swapped.is_err());
        assert!(sent.is_err());
        assert!(raised_names(&mut branding).is_empty());
    }

    /// Branding read back from storage, or made from the platform's
    /// defaults, has raised nothing.
    #[test]
    fn branding_read_back_from_storage_has_raised_nothing() {
        let mut stored = TenantBranding::<ResolvedTenant>::reconstitute(TenantBrandingRow {
            logo_url: Setting::Unset,
            primary_color: Setting::Unset,
            background_color: Setting::Unset,
            custom_css: Setting::Unset,
            email_from_name: Setting::Set(label("Acme")),
            email_from_address: Setting::Unset,
        })
        .unwrap();
        let mut fresh = TenantBranding::<ResolvedTenant>::default_branding();

        assert!(raised_names(&mut stored).is_empty());
        assert!(raised_names(&mut fresh).is_empty());
    }

    /// Where the platform serves Acme's uploaded logo.
    fn served_logo() -> HttpsUrl {
        HttpsUrl::new("https://assets.ianua.test/acme/logo.png").unwrap()
    }

    /// Fay uploads Acme's logo as a PNG. The sign-in page shows it from
    /// where the platform serves it, and the record names the logo and its
    /// format.
    #[test]
    fn an_uploaded_logo_is_shown_and_named_in_the_record() {
        let mut branding = TenantBranding::<ResolvedTenant>::default_branding();
        let logo = LogoImage::new(png(400, 120)).unwrap();

        branding
            .upload_logo(&logo, served_logo(), &editor())
            .unwrap();

        assert_eq!(branding.logo_url(), Some(&served_logo()));
        let events = raised(&mut branding);
        assert_eq!(events[0].event_type().as_str(), "branding.updated");
        assert_eq!(events[0].payload().get("part"), Some("logo"));
        assert_eq!(events[0].payload().get("format"), Some("png"));
    }

    /// Uploading a logo with only the view right is rejected, leaving the
    /// logo unset and raising no event.
    #[test]
    fn a_viewer_may_not_upload_a_logo() {
        let mut branding = TenantBranding::<ResolvedTenant>::default_branding();
        let logo = LogoImage::new(png(400, 120)).unwrap();

        let result = branding.upload_logo(&logo, served_logo(), &viewer());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(branding.logo_url().is_none());
        assert!(raised_names(&mut branding).is_empty());
    }
}

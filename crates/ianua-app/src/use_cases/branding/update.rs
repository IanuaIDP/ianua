//! Update branding: change the tenant's look and the sender of its mail.
//! Only the fields a request names are changed.

use std::sync::Arc;

use ianua_domain::domains::branding::config::{CustomCss, TenantBranding};
use ianua_domain::domains::branding::control::BrandingControl;
use ianua_domain::domains::tenant::custom_domains::registered_domain::RegisteredDomain;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{DomainName, Email, HexColor, HttpsUrl, Label, RawCss, Setting};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::input::FieldUpdate;
use crate::ports::branding::{BrandingStore, CssSanitizer};
use crate::ports::domain::RegisteredDomainStore;
use crate::use_case::Command;
use crate::use_cases::branding::lookup::current_branding;

/// Fields to update. Each is a [`FieldUpdate`]: `Keep` leaves it unchanged,
/// `Clear` returns it to the platform's, `Set` replaces it.
pub struct UpdateRequest {
    /// Logo URL update.
    pub logo_url: FieldUpdate<HttpsUrl>,
    /// Primary color update.
    pub primary_color: FieldUpdate<HexColor>,
    /// Background color update.
    pub background_color: FieldUpdate<HexColor>,
    /// Custom CSS update, as the tenant wrote it. It is sanitized before
    /// it is kept.
    pub custom_css: FieldUpdate<RawCss>,
    /// Email "From" name update.
    pub email_from_name: FieldUpdate<Label>,
    /// Email "From" address update. A new address must be on a domain the
    /// tenant has verified.
    pub email_from_address: FieldUpdate<Email>,
}

impl UpdateRequest {
    /// Whether every field is left as it is.
    fn changes_nothing(&self) -> bool {
        self.logo_url.is_keep()
            && self.primary_color.is_keep()
            && self.background_color.is_keep()
            && self.custom_css.is_keep()
            && self.email_from_name.is_keep()
            && self.email_from_address.is_keep()
    }

    /// Changes every part of the look this request names on `branding`, as
    /// `by`, with `css` the custom CSS it asks for, already sanitized.
    fn change_looks(
        &self,
        branding: &mut TenantBranding<ResolvedTenant>,
        css: Option<Setting<CustomCss>>,
        by: &BrandingControl<'_>,
    ) -> Result<(), DomainError> {
        if let Some(logo) = self.logo_url.setting() {
            branding.change_logo(logo, by)?;
        }
        if let Some(color) = self.primary_color.setting() {
            branding.change_primary_color(color, by)?;
        }
        if let Some(color) = self.background_color.setting() {
            branding.change_background_color(color, by)?;
        }
        if let Some(css) = css {
            branding.change_custom_css(css, by)?;
        }
        if let Some(name) = self.email_from_name.setting() {
            branding.change_sender_name(name, by)?;
        }
        Ok(())
    }
}

/// The ports [`UpdateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdatePorts {
    /// The tenant's branding.
    pub branding_store: Arc<dyn BrandingStore>,
    /// The tenant's registered domains, for the sender address's domain.
    pub domains: Arc<dyn RegisteredDomainStore>,
    /// Keeps only the plain rules of the CSS the tenant wrote.
    pub css_sanitizer: Arc<dyn CssSanitizer>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes the tenant's visual branding and mail sender.
pub struct UpdateUseCase {
    ports: UpdatePorts,
}

impl UpdateUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: UpdatePorts) -> Self {
        Self { ports }
    }

    /// Sends the tenant's mail from the address `update` names: the
    /// platform's when cleared, the tenant's own on a verified domain when
    /// set.
    async fn change_sender(
        &self,
        ctx: &CallerContext,
        update: &FieldUpdate<Email>,
        branding: &mut TenantBranding<ResolvedTenant>,
        by: &BrandingControl<'_>,
    ) -> Result<(), AppError> {
        let address = match update {
            FieldUpdate::Keep => return Ok(()),
            FieldUpdate::Clear => {
                return branding
                    .send_from_platform(by)
                    .map_err(AppError::from_domain);
            }
            FieldUpdate::Set(address) => address,
        };
        let domain = self.sender_domain(ctx, address).await?;
        branding
            .send_from(address.clone(), &domain, by)
            .map_err(AppError::from_domain)
    }

    /// The tenant's registration of the domain `address` is on.
    async fn sender_domain(
        &self,
        ctx: &CallerContext,
        address: &Email,
    ) -> Result<RegisteredDomain<ResolvedTenant>, AppError> {
        let name = DomainName::new(address.domain())
            .map_err(|error| AppError::from_domain(error.into()))?;
        self.ports
            .domains
            .find_by_tenant_and_name(&ctx.tenant(), &name)
            .await
            .or_internal()?
            .ok_or_else(|| {
                AppError::Forbidden(message!(
                    "branding-mail-is-sent-only-from-a",
                    "mail is sent only from a domain the tenant has verified"
                ))
            })
    }
}

impl Command for UpdateUseCase {
    type Caller = CallerContext;
    type Input = UpdateRequest;
    type Output = Result<(), AppError>;

    /// Changes the tenant's branding and records `branding.updated`.
    ///
    /// Starts from the platform defaults when nothing was saved yet. A
    /// request that changes nothing saves and records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change branding, or
    ///   the new sender address is not on a domain the tenant verified.
    /// - `AppError::Domain` when the sender address has no valid domain, or
    ///   nothing renderable is left of the custom CSS.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: UpdateRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let by = BrandingControl::new(&authority);
        by.ensure_may_change().map_err(AppError::from_domain)?;
        if request.changes_nothing() {
            return Ok(());
        }
        let css = sanitized_css(self.ports.css_sanitizer.as_ref(), &request.custom_css)?;
        let tenant = ctx.tenant();
        let mut branding = current_branding(self.ports.branding_store.as_ref(), &tenant).await?;
        request
            .change_looks(&mut branding, css, &by)
            .map_err(AppError::from_domain)?;
        self.change_sender(ctx, &request.email_from_address, &mut branding, &by)
            .await?;
        self.ports
            .branding_store
            .save(&tenant, &branding)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), branding.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// The custom CSS `update` asks for, kept as written beside what
/// `sanitizer` made of it, or `None` when it leaves the field alone.
///
/// # Errors
///
/// - `AppError::Domain` when nothing renderable is left of the CSS.
fn sanitized_css(
    sanitizer: &dyn CssSanitizer,
    update: &FieldUpdate<RawCss>,
) -> Result<Option<Setting<CustomCss>>, AppError> {
    let raw = match update {
        FieldUpdate::Keep => return Ok(None),
        FieldUpdate::Clear => return Ok(Some(Setting::Unset)),
        FieldUpdate::Set(raw) => raw,
    };
    let rendered = sanitizer.sanitize(raw).map_err(AppError::from_domain)?;
    Ok(Some(Setting::Set(CustomCss::new(raw.clone(), rendered))))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::custom_domains::registered_domain::{
        DomainConnection, DomainProof, DomainVerificationToken, RegisteredDomainRow,
    };
    use ianua_domain::domains::tenant::custom_domains::verification_status::TlsStatus;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{DomainId, SanitizedCss};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::branding::FakeBrandingStore;
    use crate::test_support::domain::FakeDomainStore;
    use crate::test_support::operator::operator_without_grant;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Setup {
        uc: UpdateUseCase,
        store: Arc<FakeBrandingStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn new() -> Self {
            Self::with(UpdatePorts::fakes())
        }

        fn with(ports: UpdatePorts) -> Self {
            let store = Arc::new(FakeBrandingStore::empty());
            let uc = UpdateUseCase::new(UpdatePorts {
                branding_store: store.clone(),
                ..ports
            });
            Self {
                uc,
                store,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn refusing(authorities: FakeTenantAuthorities) -> Self {
            Self::with(UpdatePorts {
                tenant_authorities: Arc::new(authorities),
                ..UpdatePorts::fakes()
            })
        }

        fn update(&self, request: UpdateRequest) -> Result<(), AppError> {
            self.update_as(&test_ctx(), request)
        }

        fn update_as(&self, ctx: &CallerContext, request: UpdateRequest) -> Result<(), AppError> {
            block_on(
                self.uc
                    .execute(ctx, &test_auditor(self.audit.clone()), request),
            )
        }

        fn saved(&self) -> Option<TenantBranding<ResolvedTenant>> {
            block_on(self.store.find(&test_ctx().tenant())).unwrap()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn empty_req() -> UpdateRequest {
        UpdateRequest {
            logo_url: FieldUpdate::Keep,
            primary_color: FieldUpdate::Keep,
            background_color: FieldUpdate::Keep,
            custom_css: FieldUpdate::Keep,
            email_from_name: FieldUpdate::Keep,
            email_from_address: FieldUpdate::Keep,
        }
    }

    fn logo_req() -> UpdateRequest {
        UpdateRequest {
            logo_url: FieldUpdate::Set(HttpsUrl::new("https://acme.com/logo.png").unwrap()),
            ..empty_req()
        }
    }

    fn sender_req(address: &str) -> UpdateRequest {
        UpdateRequest {
            email_from_address: FieldUpdate::Set(Email::new(address).unwrap()),
            ..empty_req()
        }
    }

    fn domain(name: &str, proof: DomainProof) -> RegisteredDomain<ResolvedTenant> {
        RegisteredDomain::reconstitute(RegisteredDomainRow {
            id: DomainId::new(),
            domain: DomainName::new(name).unwrap(),
            connection: DomainConnection::Delegated,
            proof,
            dns_challenge_token: DomainVerificationToken::new("token123").unwrap(),
            tls_status: TlsStatus::NotRequired,
            created_at: clock::now() - time::Duration::hours(1),
        })
        .unwrap()
    }

    fn with_domain(registered: &RegisteredDomain<ResolvedTenant>) -> Setup {
        let domains = Arc::new(FakeDomainStore::empty());
        block_on(domains.save(&test_ctx().tenant(), registered)).unwrap();
        Setup::with(UpdatePorts {
            domains,
            ..UpdatePorts::fakes()
        })
    }

    fn verified() -> DomainProof {
        DomainProof::Verified { at: clock::now() }
    }

    /// Fay sets Acme's logo. It is saved and the change recorded.
    #[test]
    fn update_logo_and_audits() {
        let setup = Setup::new();

        setup.update(logo_req()).unwrap();

        let saved = setup.saved().unwrap();
        assert_eq!(
            saved.logo_url().map(HttpsUrl::as_str),
            Some("https://acme.com/logo.png")
        );
        assert_eq!(setup.recorded(), vec!["branding.updated"]);
    }

    /// Fay sets both colours in one request. Both are saved.
    #[test]
    fn saves_both_requested_colors() {
        let setup = Setup::new();
        let request = UpdateRequest {
            primary_color: FieldUpdate::Set(HexColor::new("#FF5733").unwrap()),
            background_color: FieldUpdate::Set(HexColor::new("#FFFFFF").unwrap()),
            ..empty_req()
        };

        setup.update(request).unwrap();

        let saved = setup.saved().unwrap();
        assert_eq!(saved.primary_color().map(HexColor::as_str), Some("#FF5733"));
        assert_eq!(
            saved.background_color().map(HexColor::as_str),
            Some("#FFFFFF")
        );
    }

    /// Fay set a logo, then clears it. The platform's logo shows again.
    #[test]
    fn clearing_removes_the_custom_logo() {
        let setup = Setup::new();
        setup.update(logo_req()).unwrap();
        let clear = UpdateRequest {
            logo_url: FieldUpdate::Clear,
            ..empty_req()
        };

        setup.update(clear).unwrap();

        assert!(setup.saved().unwrap().logo_url().is_none());
    }

    /// Fay names Acme's mail "Acme Security". The sender name is saved.
    #[test]
    fn update_sender_name() {
        let setup = Setup::new();
        let request = UpdateRequest {
            email_from_name: FieldUpdate::Set(Label::new("name", "Acme Security").unwrap()),
            ..empty_req()
        };

        setup.update(request).unwrap();

        assert_eq!(
            setup.saved().unwrap().email_from_name().map(Label::as_str),
            Some("Acme Security")
        );
    }

    /// Fay sends Acme's mail from an address on acme.com, which Acme has
    /// verified. The address is saved.
    #[test]
    fn a_sender_on_a_verified_domain_is_saved() {
        let setup = with_domain(&domain("acme.com", verified()));

        setup.update(sender_req("noreply@acme.com")).unwrap();

        assert_eq!(
            setup
                .saved()
                .unwrap()
                .email_from_address()
                .map(Email::as_str),
            Some("noreply@acme.com")
        );
    }

    /// A sender on an unregistered domain is forbidden, leaving branding
    /// unsaved.
    #[test]
    fn a_sender_on_an_unregistered_domain_is_refused() {
        let setup = Setup::new();

        let result = setup.update(sender_req("security@bank.com"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.saved().is_none());
    }

    /// Registering a domain without proving it does not permit setting a
    /// sender on that domain, and the refusal records no branding event.
    #[test]
    fn a_sender_on_an_unproved_domain_is_refused() {
        let setup = with_domain(&domain("acme.com", DomainProof::Unproved));

        let result = setup.update(sender_req("noreply@acme.com"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.recorded().is_empty());
    }

    /// Fay clears the sender address. Acme's mail goes out from the
    /// platform's address again.
    #[test]
    fn clearing_the_sender_sends_from_the_platform() {
        let setup = with_domain(&domain("acme.com", verified()));
        setup.update(sender_req("noreply@acme.com")).unwrap();
        let clear = UpdateRequest {
            email_from_address: FieldUpdate::Clear,
            ..empty_req()
        };

        setup.update(clear).unwrap();

        assert!(setup.saved().unwrap().email_from_address().is_none());
    }

    /// Acme never saved branding. Fay's first colour starts from the
    /// platform defaults, so only that colour is set.
    #[test]
    fn creates_default_branding_if_none_exists() {
        let setup = Setup::new();
        let request = UpdateRequest {
            primary_color: FieldUpdate::Set(HexColor::new("#ABC").unwrap()),
            ..empty_req()
        };

        setup.update(request).unwrap();

        let saved = setup.saved().unwrap();
        assert_eq!(saved.primary_color().map(HexColor::as_str), Some("#ABC"));
        assert!(saved.logo_url().is_none());
    }

    fn css_req(css: &str) -> UpdateRequest {
        UpdateRequest {
            custom_css: FieldUpdate::Set(RawCss::new(css).unwrap()),
            ..empty_req()
        }
    }

    /// Fay sets custom CSS. What she wrote is kept for editing and its
    /// sanitized form is what pages render.
    #[test]
    fn update_custom_css() {
        let setup = Setup::new();
        let css = ".login { padding: 20px; }";

        setup.update(css_req(css)).unwrap();

        let saved = setup.saved().unwrap();
        assert_eq!(saved.custom_css_source().map(RawCss::as_str), Some(css));
        assert_eq!(saved.custom_css().map(SanitizedCss::as_str), Some(css));
    }

    /// CSS containing a rule that loads a remote URL is kept as editable
    /// source, while only the sanitizer's plain rule is saved for rendering.
    #[test]
    fn custom_css_renders_only_what_the_sanitizer_kept() {
        let setup = Setup::new();
        let css = ".login { padding: 20px; } input[value^=a] { background-color: url(https://eve.example/a); }";

        setup.update(css_req(css)).unwrap();

        let saved = setup.saved().unwrap();
        assert_eq!(saved.custom_css_source().map(RawCss::as_str), Some(css));
        assert_eq!(
            saved.custom_css().map(SanitizedCss::as_str),
            Some(".login { padding: 20px; }")
        );
    }

    /// A stylesheet containing only an import is refused because sanitizing
    /// leaves nothing renderable, and no branding is saved.
    #[test]
    fn custom_css_with_nothing_renderable_is_refused() {
        let setup = Setup::new();

        let result = setup.update(css_req("@import url(https://eve.example/x.css);"));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(setup.saved().is_none());
    }

    /// A request that changes nothing saves and records nothing.
    #[test]
    fn no_changes_is_noop() {
        let setup = Setup::new();

        setup.update(empty_req()).unwrap();

        assert!(setup.saved().is_none());
        assert!(setup.recorded().is_empty());
    }

    /// Without the branding update right, changing the logo is forbidden
    /// and no branding is saved.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let setup = Setup::refusing(FakeTenantAuthorities::holding(&[]));

        let result = setup.update(logo_req());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.saved().is_none());
    }

    /// A signed-out session cannot change the tenant's logo.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::refusing(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = setup.update(logo_req());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator without an impersonation grant cannot change a tenant's
    /// logo, and no branding is saved.
    #[test]
    fn an_operator_without_a_grant_is_refused() {
        let setup = Setup::new();

        let result = setup.update_as(&operator_without_grant(), logo_req());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.saved().is_none());
    }
}

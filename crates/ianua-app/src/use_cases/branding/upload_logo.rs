//! Upload logo: keep an image the tenant uploaded and show it on its
//! sign-in pages and in its mail.
//!
//! The image was checked as it became a [`LogoImage`]: a PNG or a JPEG read
//! from its own bytes, at most half a mebibyte, each side between 16 and
//! 4096 pixels. The platform keeps and serves it; the branding keeps only
//! where.

use std::sync::Arc;

use ianua_domain::domains::branding::control::BrandingControl;
use ianua_domain::domains::branding::logo::LogoImage;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::HttpsUrl;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::branding::{BrandingStore, LogoStore};
use crate::use_case::Command;
use crate::use_cases::branding::lookup::current_branding;

/// The ports [`UploadLogoUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UploadLogoPorts {
    /// The tenant's branding.
    pub branding_store: Arc<dyn BrandingStore>,
    /// Keeps and serves the tenant's logo.
    pub logo_store: Arc<dyn LogoStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Puts an uploaded logo on the tenant's pages.
pub struct UploadLogoUseCase {
    ports: UploadLogoPorts,
}

impl UploadLogoUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: UploadLogoPorts) -> Self {
        Self { ports }
    }
}

impl Command for UploadLogoUseCase {
    type Caller = CallerContext;
    type Input = LogoImage;
    type Output = Result<HttpsUrl, AppError>;

    /// Keeps `logo` as the tenant's, shows it on its pages in place of any
    /// logo before, records `branding.updated` naming the logo and its
    /// format, and returns where it is served. Starts from the platform
    /// defaults when nothing was saved yet.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change branding.
    /// - `AppError::Internal` when the logo or the branding cannot be kept,
    ///   or on audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        logo: LogoImage,
    ) -> Result<HttpsUrl, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let by = BrandingControl::new(&authority);
        by.ensure_may_change().map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let mut branding = current_branding(self.ports.branding_store.as_ref(), &tenant).await?;
        let served_at = self
            .ports
            .logo_store
            .put(&tenant, &logo)
            .await
            .or_internal()?;
        branding
            .upload_logo(&logo, served_at.clone(), &by)
            .map_err(AppError::from_domain)?;

        self.ports
            .branding_store
            .save(&tenant, &branding)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), branding.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(served_at)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{BrandingAction, SystemPermission};
    use ianua_domain::domains::branding::logo::LogoFormat;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::branding::{FakeBrandingStore, FakeLogoStore, acme_logo};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Setup {
        uc: UploadLogoUseCase,
        branding: Arc<FakeBrandingStore>,
        logos: Arc<FakeLogoStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn as_caller(authorities: FakeTenantAuthorities) -> Self {
            let branding = Arc::new(FakeBrandingStore::empty());
            let logos = Arc::new(FakeLogoStore::default());
            Self {
                uc: UploadLogoUseCase::new(UploadLogoPorts {
                    branding_store: branding.clone(),
                    logo_store: logos.clone(),
                    tenant_authorities: Arc::new(authorities),
                }),
                branding,
                logos,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn upload(&self) -> Result<HttpsUrl, AppError> {
            let auditor = test_auditor(self.audit.clone());
            block_on(self.uc.execute(&test_ctx(), &auditor, acme_logo()))
        }

        fn shown_logo(&self) -> Option<HttpsUrl> {
            let stored = block_on(self.branding.find(&test_ctx().tenant())).unwrap();
            stored.and_then(|branding| branding.logo_url().cloned())
        }
    }

    /// Fay uploads Acme's logo. It is kept, the sign-in page shows it from
    /// where it is served, and the upload is recorded with its format.
    #[test]
    fn an_uploaded_logo_is_kept_shown_and_recorded() {
        let setup = Setup::as_caller(FakeTenantAuthorities::holding_everything());

        let served_at = setup.upload().unwrap();

        let tenant_id = test_ctx().tenant_id();
        assert_eq!(served_at, FakeLogoStore::served_at(tenant_id));
        assert_eq!(setup.shown_logo(), Some(served_at));
        let kept = setup.logos.stored(tenant_id).unwrap();
        assert_eq!(kept.format(), LogoFormat::Png);
        let recorded = setup.audit.payload_of("branding.updated");
        assert_eq!(recorded.get("part"), Some("logo"));
        assert_eq!(recorded.get("format"), Some("png"));
    }

    /// A caller with only the branding view right cannot upload a logo;
    /// no image, branding URL or audit event is saved.
    #[test]
    fn a_caller_who_may_only_view_branding_is_refused() {
        let setup = Setup::as_caller(FakeTenantAuthorities::holding(&[
            SystemPermission::Branding(BrandingAction::View),
        ]));

        let result = setup.upload();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.logos.stored(test_ctx().tenant_id()).is_none());
        assert!(setup.shown_logo().is_none());
        assert!(setup.audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot upload a logo, and no image is stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::as_caller(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = setup.upload();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(setup.logos.stored(test_ctx().tenant_id()).is_none());
    }
}

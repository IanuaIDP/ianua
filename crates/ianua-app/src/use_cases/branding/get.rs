//! Get branding: the tenant's look on its sign-in page and in its mail.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{BrandingAction, SystemPermission};
use ianua_domain::domains::branding::config::TenantBranding;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::branding::BrandingStore;
use crate::use_case::Query;
use crate::use_cases::branding::lookup::current_branding;

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// The tenant's branding.
    pub branding_store: Arc<dyn BrandingStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads the tenant's branding configuration.
pub struct GetUseCase {
    ports: GetPorts,
}

impl GetUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<TenantBranding<ResolvedTenant>, AppError>;

    /// The tenant's branding, or the platform defaults when none was set.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view branding.
    /// - `AppError::Internal` when the store fails.
    async fn execute(
        &self,
        ctx: &CallerContext,
        (): (),
    ) -> Result<TenantBranding<ResolvedTenant>, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Branding(BrandingAction::View))
            .map_err(AppError::from_domain)?;
        current_branding(self.ports.branding_store.as_ref(), &ctx.tenant()).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::branding::config::TenantBrandingRow;
    use ianua_domain::types::{HexColor, HttpsUrl, Setting};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::branding::FakeBrandingStore;
    use crate::test_support::operator::operator_without_grant;
    use crate::test_support::{block_on, test_ctx};

    fn make_uc(store: Arc<FakeBrandingStore>) -> GetUseCase {
        GetUseCase::new(GetPorts {
            branding_store: store,
            ..GetPorts::fakes()
        })
    }

    fn refusing(authorities: FakeTenantAuthorities) -> GetUseCase {
        GetUseCase::new(GetPorts {
            tenant_authorities: Arc::new(authorities),
            ..GetPorts::fakes()
        })
    }

    /// Acme never changed its branding. Ann sees the platform defaults, not
    /// an error.
    #[test]
    fn returns_default_when_none_configured() {
        let uc = make_uc(Arc::new(FakeBrandingStore::empty()));

        let branding = block_on(uc.execute(&test_ctx(), ())).unwrap();

        assert!(!branding.has_customization());
    }

    /// Acme set its logo and colour. Ann sees them.
    #[test]
    fn returns_configured_branding() {
        let branding = TenantBranding::reconstitute(TenantBrandingRow {
            logo_url: Setting::Set(HttpsUrl::new("https://acme.com/logo.png").unwrap()),
            primary_color: Setting::Set(HexColor::new("#FF5733").unwrap()),
            background_color: Setting::Unset,
            custom_css: Setting::Unset,
            email_from_name: Setting::Unset,
            email_from_address: Setting::Unset,
        })
        .unwrap();
        let uc = make_uc(Arc::new(FakeBrandingStore::holding(
            test_ctx().tenant_id(),
            branding,
        )));

        let found = block_on(uc.execute(&test_ctx(), ())).unwrap();

        assert!(found.has_customization());
        assert_eq!(
            found.logo_url().map(HttpsUrl::as_str),
            Some("https://acme.com/logo.png")
        );
    }

    /// Reading the tenant's branding requires the view right.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let uc = refusing(FakeTenantAuthorities::holding(&[]));

        let result = block_on(uc.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read the tenant's branding.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let uc = refusing(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = block_on(uc.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator without an impersonation grant cannot read a tenant's
    /// branding.
    #[test]
    fn an_operator_without_a_grant_is_refused() {
        let uc = make_uc(Arc::new(FakeBrandingStore::empty()));

        let result = block_on(uc.execute(&operator_without_grant(), ()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}

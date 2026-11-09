//! Get mail provider: which provider a tenant named for its mail, whether
//! a test send through it worked, and which one its mail goes out through
//! now.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{BrandingAction, SystemPermission};
use ianua_domain::domains::branding::mail_provider::TenantMailProvider;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::branding::TenantMailProviderStore;
use crate::use_case::Query;
use crate::use_cases::branding::lookup::current_mail_provider;

/// The ports [`GetMailProviderUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetMailProviderPorts {
    /// Where each tenant's mail provider is kept.
    pub provider_store: Arc<dyn TenantMailProviderStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads the caller's tenant's mail provider.
pub struct GetMailProviderUseCase {
    ports: GetMailProviderPorts,
}

impl GetMailProviderUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetMailProviderPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetMailProviderUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<TenantMailProvider<ResolvedTenant>, AppError>;

    /// The mail provider of the tenant `ctx` acts in, or the platform's own
    /// mail when it never named one. Its credentials stay sealed; the API
    /// shows the kind, where it points and how its test went.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view branding.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        (): (),
    ) -> Result<TenantMailProvider<ResolvedTenant>, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Branding(BrandingAction::View))
            .map_err(AppError::from_domain)?;
        current_mail_provider(self.ports.provider_store.as_ref(), &ctx.tenant()).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::branding::mail_provider::MailProvider;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::{block_on, test_ctx};

    fn read(
        authorities: FakeTenantAuthorities,
    ) -> Result<TenantMailProvider<ResolvedTenant>, AppError> {
        let uc = GetMailProviderUseCase::new(GetMailProviderPorts {
            tenant_authorities: Arc::new(authorities),
            ..GetMailProviderPorts::fakes()
        });
        block_on(uc.execute(&test_ctx(), ()))
    }

    /// Acme never named a provider. Ann sees the platform's own mail.
    #[test]
    fn a_tenant_that_named_none_uses_the_platforms_mail() {
        let provider = read(FakeTenantAuthorities::holding(&[
            SystemPermission::Branding(BrandingAction::View),
        ]))
        .unwrap();

        assert_eq!(*provider.provider(), MailProvider::Platform);
    }

    /// Reading the tenant's mail provider requires the branding view right.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let result = read(FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read the tenant's mail provider.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = read(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

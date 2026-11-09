//! List service providers: the SAML apps of the caller's tenant, a page at
//! a time.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{FederationAction, SystemPermission};
use ianua_domain::domains::federation::service_provider::SamlServiceProvider;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest};
use crate::ports::federation::SamlServiceProviderStore;
use crate::use_case::Query;

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// The tenant's SAML apps.
    pub service_providers: Arc<dyn SamlServiceProviderStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tenant's SAML apps.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = PageRequest;
    type Output = Result<Page<SamlServiceProvider<ResolvedTenant>>, AppError>;

    /// One page of the tenant's apps, newest first, for a caller who may
    /// view federation.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not view federation.
    /// - `AppError::Domain` when the page's cursor came from another list.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        page: PageRequest,
    ) -> Result<Page<SamlServiceProvider<ResolvedTenant>>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Federation(FederationAction::View))
            .map_err(AppError::from_domain)?;
        self.ports
            .service_providers
            .list(&ctx.tenant(), &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::types::SamlServiceProviderId;

    use super::*;
    use crate::listing::Limit;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::federation::{FakeSamlServiceProviderStore, test_service_provider};
    use crate::test_support::{block_on, test_ctx};

    fn list(
        authorities: FakeTenantAuthorities,
        page: PageRequest,
    ) -> Result<Page<SamlServiceProvider<ResolvedTenant>>, AppError> {
        let apps = [
            test_service_provider(SamlServiceProviderId::new(), ConnectionStatus::Active),
            test_service_provider(SamlServiceProviderId::new(), ConnectionStatus::Disabled),
        ];
        let use_case = ListUseCase::new(ListPorts {
            service_providers: Arc::new(FakeSamlServiceProviderStore::holding(
                &test_ctx().tenant(),
                apps,
            )),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), page))
    }

    /// Sam may view federation. He asks for one app at a time, and sees one
    /// of Acme's two, with a cursor to the other.
    #[test]
    fn a_page_of_apps_points_to_the_next() {
        let view = [SystemPermission::Federation(FederationAction::View)];
        let one = PageRequest::first(Limit::new(1).unwrap());

        let page = list(FakeTenantAuthorities::holding(&view), one).unwrap();

        assert_eq!(page.items.len(), 1);
        assert!(page.has_next());
    }

    /// Without federation-viewing rights, a caller cannot list Acme's SAML apps.
    #[test]
    fn a_caller_without_the_right_is_refused() {
        let result = list(FakeTenantAuthorities::holding(&[]), PageRequest::default());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session receives an authentication error instead of
    /// the tenant's SAML app list.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            PageRequest::default(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

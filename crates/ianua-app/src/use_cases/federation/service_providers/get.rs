//! Get service provider: one SAML app of the caller's tenant.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{FederationAction, SystemPermission};
use ianua_domain::domains::federation::service_provider::SamlServiceProvider;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::SamlServiceProviderId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::federation::SamlServiceProviderStore;
use crate::use_case::Query;
use crate::use_cases::federation::idp::lookup::existing_service_provider;

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// The tenant's SAML apps.
    pub service_providers: Arc<dyn SamlServiceProviderStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one SAML app.
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
    type Input = SamlServiceProviderId;
    type Output = Result<SamlServiceProvider<ResolvedTenant>, AppError>;

    /// The app with `id`, for a caller who may view federation.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not view federation.
    /// - `AppError::NotFound` if the app doesn't exist.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        id: SamlServiceProviderId,
    ) -> Result<SamlServiceProvider<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Federation(FederationAction::View))
            .map_err(AppError::from_domain)?;
        existing_service_provider(self.ports.service_providers.as_ref(), &ctx.tenant(), &id).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::federation::{FakeSamlServiceProviderStore, test_service_provider};
    use crate::test_support::{block_on, test_ctx};

    fn get(
        authorities: FakeTenantAuthorities,
        id: SamlServiceProviderId,
    ) -> Result<SamlServiceProvider<ResolvedTenant>, AppError> {
        let app = test_service_provider(salesforce(), ConnectionStatus::Active);
        let use_case = GetUseCase::new(GetPorts {
            service_providers: Arc::new(FakeSamlServiceProviderStore::holding(
                &test_ctx().tenant(),
                [app],
            )),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), id))
    }

    fn salesforce() -> SamlServiceProviderId {
        SamlServiceProviderId::from_uuid(uuid::Uuid::from_u128(7))
    }

    /// Sam may view federation. He opens Salesforce and sees it.
    #[test]
    fn a_viewer_reads_the_app() {
        let view = [SystemPermission::Federation(FederationAction::View)];

        let app = get(FakeTenantAuthorities::holding(&view), salesforce()).unwrap();

        assert_eq!(app.name().as_str(), "Salesforce");
    }

    /// Sam names an app Acme does not have. It is not found.
    #[test]
    fn an_unknown_app_is_not_found() {
        let result = get(
            FakeTenantAuthorities::holding_everything(),
            SamlServiceProviderId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller without federation-viewing rights cannot read Salesforce's
    /// SAML configuration.
    #[test]
    fn a_caller_without_the_right_is_refused() {
        let result = get(FakeTenantAuthorities::holding(&[]), salesforce());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read a configured SAML app.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = get(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            salesforce(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

//! Read the tenant's random label and readable-name consent, its primary
//! domain, and the issuer it set for its tokens.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{SystemPermission, TenantSettingsAction};
use ianua_domain::domains::tenant::access::auth_config::TokenIssuer;
use ianua_domain::domains::tenant::hosts::{PlatformLabel, ReadableAddress};
use ianua_domain::message;
use ianua_domain::types::{DomainName, TenantId, TenantSlug};

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::organization::OrganizationStore;
use crate::ports::tenant::TenantStore;
use crate::services::lookup::existing_tenant;
use crate::use_case::Query;

/// The names a tenant is reached on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantHostnames {
    /// The tenant's identifier, never used as a platform DNS label.
    pub tenant_id: TenantId,
    /// The permanent opaque platform label.
    pub platform_label: PlatformLabel,
    /// Whether the tenant opted into publishing its readable name.
    pub readable_address: ReadableAddress,
    /// Its organization's slug, the second label of its readable subdomain.
    pub organization_slug: TenantSlug,
    /// The tenant's slug, the first label of its readable subdomain.
    pub tenant_slug: TenantSlug,
    /// The domain of its own it set as primary, if any.
    pub primary_domain: Option<DomainName>,
    /// The issuer it set for its tokens, or the platform's.
    pub jwt_issuer: TokenIssuer,
}

/// The ports [`GetHostnameConfigUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetHostnameConfigPorts {
    /// Loads the address settings used to construct platform hostnames.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Organizations, for the slug in the readable subdomain.
    pub organization_store: Arc<dyn OrganizationStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads the names the caller's tenant is reached on.
pub struct GetHostnameConfigUseCase {
    ports: GetHostnameConfigPorts,
}

impl GetHostnameConfigUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetHostnameConfigPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetHostnameConfigUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<TenantHostnames, AppError>;

    /// The names the tenant `ctx` acts in is reached on.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view the tenant's
    ///   settings.
    /// - `AppError::NotFound` if the tenant or its organization doesn't
    ///   exist.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(&self, ctx: &CallerContext, (): ()) -> Result<TenantHostnames, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::TenantSettings(TenantSettingsAction::View))
            .map_err(AppError::from_domain)?;
        let tenant = existing_tenant(self.ports.tenant_store.as_ref(), &ctx.tenant_id()).await?;
        let organization = self
            .ports
            .organization_store
            .find_by_id(tenant.organization_id())
            .await
            .or_internal()?
            .or_not_found(message!(
                "authentication-organization-not-found",
                "organization not found"
            ))?;
        Ok(TenantHostnames {
            tenant_id: *tenant.id(),
            platform_label: tenant.platform_label().clone(),
            readable_address: tenant.readable_address(),
            organization_slug: organization.slug().clone(),
            tenant_slug: tenant.slug().clone(),
            primary_domain: tenant.primary_domain().cloned(),
            jwt_issuer: tenant.auth_config().jwt_issuer().clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::MtlsAction;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::organization::{org_store_with, test_org};
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{block_on, test_ctx};

    fn reading(authorities: FakeTenantAuthorities) -> GetHostnameConfigUseCase {
        let tenant = test_tenant_for_ctx();
        let organization = test_org(*tenant.organization_id(), "globex");
        GetHostnameConfigUseCase::new(GetHostnameConfigPorts {
            tenant_store: Arc::new(FakeTenantStore::holding(tenant)),
            organization_store: org_store_with([organization]),
            tenant_authorities: Arc::new(authorities),
        })
    }

    fn settings_viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::TenantSettings(
            TenantSettingsAction::View,
        )])
    }

    /// Ann reads the names her tenant is reached on: its own slug under its
    /// organization's, and no domain of its own yet.
    #[test]
    fn returns_the_names_the_tenant_is_reached_on() {
        let uc = reading(settings_viewer());

        let names = block_on(uc.execute(&test_ctx(), ())).unwrap();

        assert_eq!(names.tenant_id, test_ctx().tenant_id());
        assert_eq!(names.organization_slug.as_str(), "globex");
        assert_eq!(names.tenant_slug.as_str(), "acme");
        assert_eq!(names.primary_domain, None);
    }

    /// A tenant whose organization is gone has no readable subdomain, so it
    /// is not found rather than answered with half a name.
    #[test]
    fn a_tenant_without_its_organization_is_not_found() {
        let uc = GetHostnameConfigUseCase::new(GetHostnameConfigPorts {
            tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
            tenant_authorities: Arc::new(settings_viewer()),
            ..GetHostnameConfigPorts::fakes()
        });

        let result = block_on(uc.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// The mutual-TLS view right does not permit reading the tenant's hostname
    /// settings.
    #[test]
    fn a_caller_without_the_settings_right_is_refused() {
        let uc = reading(FakeTenantAuthorities::holding(&[SystemPermission::Mtls(
            MtlsAction::View,
        )]));

        let result = block_on(uc.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read the tenant's hostname settings.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let uc = reading(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = block_on(uc.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

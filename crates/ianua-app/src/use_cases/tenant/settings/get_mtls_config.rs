//! Read a tenant's mutual TLS trust anchor: whether client certificates are
//! asked for, and which certificate authorities may sign them.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{MtlsAction, SystemPermission};
use ianua_domain::domains::tenant::access::network_security::MtlsConfig;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::tenant::TenantStore;
use crate::services::lookup::existing_tenant;
use crate::use_case::Query;

/// The ports [`GetMtlsConfigUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetMtlsConfigPorts {
    /// Loads the client-certificate settings for the caller's workspace.
    pub tenant_store: Arc<dyn TenantStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads the caller's tenant's mutual TLS trust anchor.
pub struct GetMtlsConfigUseCase {
    ports: GetMtlsConfigPorts,
}

impl GetMtlsConfigUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetMtlsConfigPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetMtlsConfigUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<MtlsConfig, AppError>;

    /// The mutual TLS trust anchor of the tenant `ctx` acts in.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view mutual TLS.
    /// - `AppError::NotFound` if the tenant doesn't exist.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(&self, ctx: &CallerContext, (): ()) -> Result<MtlsConfig, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Mtls(MtlsAction::View))
            .map_err(AppError::from_domain)?;
        let tenant = existing_tenant(self.ports.tenant_store.as_ref(), &ctx.tenant_id()).await?;
        Ok(tenant.mtls().clone())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::TenantSettingsAction;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{block_on, test_ctx};

    fn reading(authorities: FakeTenantAuthorities) -> GetMtlsConfigUseCase {
        GetMtlsConfigUseCase::new(GetMtlsConfigPorts {
            tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
            tenant_authorities: Arc::new(authorities),
        })
    }

    /// Ann, who may view mutual TLS, reads her tenant's trust anchor and sees
    /// what it stores.
    #[test]
    fn returns_the_tenants_trust_anchor() {
        let uc = reading(FakeTenantAuthorities::holding(&[SystemPermission::Mtls(
            MtlsAction::View,
        )]));

        let config = block_on(uc.execute(&test_ctx(), ())).unwrap();

        let stored = test_tenant_for_ctx();
        assert_eq!(config.mode(), stored.mtls().mode());
        assert_eq!(config.trusted_ca_certs(), stored.mtls().trusted_ca_certs());
    }

    /// A tenant that no longer exists is not found.
    #[test]
    fn a_missing_tenant_is_not_found() {
        let uc = GetMtlsConfigUseCase::new(GetMtlsConfigPorts::fakes());

        let result = block_on(uc.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// The tenant-settings view right alone does not permit reading the
    /// mutual-TLS trust anchor.
    #[test]
    fn a_caller_with_only_the_settings_right_is_refused() {
        let uc = reading(FakeTenantAuthorities::holding(&[
            SystemPermission::TenantSettings(TenantSettingsAction::View),
        ]));

        let result = block_on(uc.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read the tenant's mutual-TLS settings.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let uc = reading(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = block_on(uc.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

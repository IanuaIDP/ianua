//! Read a tenant's authentication configuration.
//!
//! Everything about how a tenant's users sign in: which methods are allowed,
//! how strong a password has to be, whether MFA is demanded, how long sessions
//! last, when an account locks, and when a sign-in must clear more than a
//! password.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{AuthConfigAction, SystemPermission};
use ianua_domain::domains::tenant::access::auth_config::TenantAuthConfig;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::tenant::TenantStore;
use crate::services::lookup::existing_tenant;
use crate::use_case::Query;

/// The ports [`GetAuthConfigUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetAuthConfigPorts {
    /// Loads the sign-in settings for the caller's workspace.
    pub tenant_store: Arc<dyn TenantStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads the caller's tenant's sign-in settings.
pub struct GetAuthConfigUseCase {
    ports: GetAuthConfigPorts,
}

impl GetAuthConfigUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetAuthConfigPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetAuthConfigUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<TenantAuthConfig, AppError>;

    /// The sign-in settings of the tenant `ctx` acts in.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view sign-in
    ///   settings.
    /// - `AppError::NotFound` if the tenant doesn't exist.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(&self, ctx: &CallerContext, (): ()) -> Result<TenantAuthConfig, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::AuthConfig(AuthConfigAction::View))
            .map_err(AppError::from_domain)?;
        let tenant = existing_tenant(self.ports.tenant_store.as_ref(), &ctx.tenant_id()).await?;
        Ok(tenant.auth_config().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::operator::operator_without_grant;
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{block_on, test_ctx};

    fn reading(ports: GetAuthConfigPorts) -> GetAuthConfigUseCase {
        GetAuthConfigUseCase::new(GetAuthConfigPorts {
            tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
            ..ports
        })
    }

    fn refusing(authorities: FakeTenantAuthorities) -> GetAuthConfigUseCase {
        reading(GetAuthConfigPorts {
            tenant_authorities: Arc::new(authorities),
            ..GetAuthConfigPorts::fakes()
        })
    }

    /// Ann reads her tenant's sign-in settings and sees what it stores.
    #[test]
    fn returns_the_tenants_settings() {
        let uc = reading(GetAuthConfigPorts::fakes());

        let config = block_on(uc.execute(&test_ctx(), ())).unwrap();

        assert_eq!(&config, test_tenant_for_ctx().auth_config());
    }

    /// A tenant that no longer exists is not found.
    #[test]
    fn a_missing_tenant_is_not_found() {
        let uc = GetAuthConfigUseCase::new(GetAuthConfigPorts::fakes());

        let result = block_on(uc.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Reading the tenant's sign-in settings requires the authentication-config
    /// view right.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let uc = refusing(FakeTenantAuthorities::holding(&[]));

        let result = block_on(uc.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read the tenant's sign-in settings.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let uc = refusing(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = block_on(uc.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator without an impersonation grant cannot read a tenant's
    /// sign-in settings.
    #[test]
    fn an_operator_without_a_grant_is_refused() {
        let uc = reading(GetAuthConfigPorts::fakes());

        let result = block_on(uc.execute(&operator_without_grant(), ()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}

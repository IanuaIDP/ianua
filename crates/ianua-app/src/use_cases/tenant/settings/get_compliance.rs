//! Read a tenant's compliance posture: where its data must stay, how long
//! its audit trail is kept, and whether operators may act as its users.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{ComplianceAction, SystemPermission};
use ianua_domain::domains::tenant::compliance::CompliancePosture;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::tenant::TenantStore;
use crate::services::lookup::existing_tenant;
use crate::use_case::Query;

/// The ports [`GetComplianceUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetCompliancePorts {
    /// Loads the compliance settings for the caller's workspace.
    pub tenant_store: Arc<dyn TenantStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads the caller's tenant's compliance posture.
pub struct GetComplianceUseCase {
    ports: GetCompliancePorts,
}

impl GetComplianceUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetCompliancePorts) -> Self {
        Self { ports }
    }
}

impl Query for GetComplianceUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<CompliancePosture, AppError>;

    /// The compliance posture of the tenant `ctx` acts in.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view the compliance
    ///   posture.
    /// - `AppError::NotFound` if the tenant doesn't exist.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(&self, ctx: &CallerContext, (): ()) -> Result<CompliancePosture, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Compliance(ComplianceAction::View))
            .map_err(AppError::from_domain)?;
        let tenant = existing_tenant(self.ports.tenant_store.as_ref(), &ctx.tenant_id()).await?;
        Ok(tenant.compliance().clone())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::TenantSettingsAction;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{block_on, test_ctx};

    fn reading(authorities: FakeTenantAuthorities) -> GetComplianceUseCase {
        GetComplianceUseCase::new(GetCompliancePorts {
            tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
            tenant_authorities: Arc::new(authorities),
        })
    }

    /// Ann, who may view the compliance posture, reads her tenant's and sees
    /// what it stores.
    #[test]
    fn returns_the_tenants_posture() {
        let uc = reading(FakeTenantAuthorities::holding(&[
            SystemPermission::Compliance(ComplianceAction::View),
        ]));

        let posture = block_on(uc.execute(&test_ctx(), ())).unwrap();

        assert_eq!(&posture, test_tenant_for_ctx().compliance());
    }

    /// A tenant that no longer exists is not found.
    #[test]
    fn a_missing_tenant_is_not_found() {
        let uc = GetComplianceUseCase::new(GetCompliancePorts::fakes());

        let result = block_on(uc.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// The tenant-settings view right alone does not permit reading the
    /// compliance posture.
    #[test]
    fn a_caller_with_only_the_settings_right_is_refused() {
        let uc = reading(FakeTenantAuthorities::holding(&[
            SystemPermission::TenantSettings(TenantSettingsAction::View),
        ]));

        let result = block_on(uc.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read the tenant's compliance posture.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let uc = reading(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = block_on(uc.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

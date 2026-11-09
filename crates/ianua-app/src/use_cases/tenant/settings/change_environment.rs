//! Change environment: label a tenant as the production, staging or
//! development stage of its product.

use std::sync::Arc;

use ianua_domain::domains::tenant::control::{TenantArea, TenantControl};
use ianua_domain::domains::tenant::environment::TenantEnvironment;
use ianua_domain::shared::events::raised::RaisesComplete as _;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::tenant::TenantStore;
use crate::services::lookup::existing_tenant;
use crate::use_case::Command;

/// The ports [`ChangeEnvironmentUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeEnvironmentPorts {
    /// Loads and saves the workspace's environment designation.
    pub tenant_store: Arc<dyn TenantStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Relabels the caller's tenant with the stage of the product it serves.
pub struct ChangeEnvironmentUseCase {
    ports: ChangeEnvironmentPorts,
}

impl ChangeEnvironmentUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: ChangeEnvironmentPorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangeEnvironmentUseCase {
    type Caller = CallerContext;
    type Input = TenantEnvironment;
    type Output = Result<(), AppError>;

    /// Labels the tenant `ctx` acts in as serving `environment` and records
    /// `tenant.environment_changed` with both labels.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change the tenant's
    ///   settings.
    /// - `AppError::Domain` when the tenant is closed.
    /// - `AppError::NotFound` if the tenant doesn't exist.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        environment: TenantEnvironment,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        TenantControl::new(&authority)
            .ensure_may(&ctx.tenant_id(), TenantArea::Profile)
            .map_err(AppError::from_domain)?;
        let mut tenant =
            existing_tenant(self.ports.tenant_store.as_ref(), &ctx.tenant_id()).await?;
        tenant
            .change_environment(TenantControl::new(&authority), environment)
            .map_err(AppError::from_domain)?;
        self.ports.tenant_store.save(&tenant).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), tenant.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::domains::tenant::status::{Archival, PlatformHold, TenantStatus};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::operator::operator_without_grant;
    use crate::test_support::tenant::{
        FakeTenantStore, tenant_for_ctx_standing, test_tenant_for_ctx,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Setup {
        uc: ChangeEnvironmentUseCase,
        tenants: Arc<FakeTenantStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn over(tenant: Tenant, authorities: FakeTenantAuthorities) -> Self {
            let tenants = Arc::new(FakeTenantStore::holding(tenant));
            Self {
                uc: ChangeEnvironmentUseCase::new(ChangeEnvironmentPorts {
                    tenant_store: tenants.clone(),
                    tenant_authorities: Arc::new(authorities),
                }),
                tenants,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn new() -> Self {
            Self::over(
                test_tenant_for_ctx(),
                FakeTenantAuthorities::holding_everything(),
            )
        }

        fn change_as(&self, ctx: &CallerContext) -> Result<(), AppError> {
            block_on(self.uc.execute(
                ctx,
                &test_auditor(self.audit.clone()),
                TenantEnvironment::Staging,
            ))
        }

        fn change(&self) -> Result<(), AppError> {
            self.change_as(&test_ctx())
        }

        fn stored(&self) -> TenantEnvironment {
            block_on(self.tenants.find_by_id(&test_ctx().tenant_id()))
                .unwrap()
                .unwrap()
                .environment()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann labels Acme's second tenant as staging. The label is saved and
    /// the change recorded.
    #[test]
    fn the_environment_is_saved_and_recorded() {
        let setup = Setup::new();

        setup.change().unwrap();

        assert_eq!(setup.stored(), TenantEnvironment::Staging);
        assert_eq!(setup.recorded(), vec!["tenant.environment_changed"]);
    }

    /// A tenant that does not exist is not found.
    #[test]
    fn an_unknown_tenant_is_not_found() {
        let uc = ChangeEnvironmentUseCase::new(ChangeEnvironmentPorts::fakes());

        let result = block_on(uc.execute(
            &test_ctx(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            TenantEnvironment::Staging,
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A suspended tenant takes no changes, and nothing is recorded.
    #[test]
    fn a_suspended_tenant_is_refused() {
        let tenant = tenant_for_ctx_standing(
            TenantStatus::Suspended,
            PlatformHold::Free,
            Archival::NotArchived,
        );
        let setup = Setup::over(tenant, FakeTenantAuthorities::holding_everything());

        let result = setup.change();

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(setup.recorded().is_empty());
    }

    /// A caller without settings-update rights cannot relabel production as
    /// staging. The production label stays and no event is recorded.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let setup = Setup::over(test_tenant_for_ctx(), FakeTenantAuthorities::holding(&[]));

        let result = setup.change();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.stored(), TenantEnvironment::Production);
        assert!(setup.recorded().is_empty());
    }

    /// A signed-out session cannot change the tenant's environment label.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::over(
            test_tenant_for_ctx(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = setup.change();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator without an impersonation grant cannot relabel the tenant.
    #[test]
    fn an_operator_without_a_grant_is_refused() {
        let setup = Setup::new();

        let result = setup.change_as(&operator_without_grant());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}

//! Activate tenant: finish provisioning by hand and make the tenant
//! operational.
//!
//! The tenant's setup activates it once its database, keys and starting
//! roles exist. This is an operator's override for when it cannot;
//! the organization never activates its own tenant, since nothing here proves
//! provisioning finished.

use std::sync::Arc;

use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActedBy, TenantId};

use crate::acting::OperatorAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::OperatorCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::tenant::TenantStore;
use crate::services::lookup::existing_tenant;
use crate::use_case::Command;

/// The ports [`ActivateTenantUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ActivateTenantPorts {
    /// Loads and saves the transition out of provisioning.
    pub tenant_store: Arc<dyn TenantStore>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Activates a provisioned tenant, for the platform.
pub struct ActivateTenantUseCase {
    ports: ActivateTenantPorts,
}

impl ActivateTenantUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: ActivateTenantPorts) -> Self {
        Self { ports }
    }
}

impl Command for ActivateTenantUseCase {
    type Caller = OperatorCaller;
    type Input = TenantId;
    type Output = Result<(), AppError>;

    /// Activates the provisioning tenant `tenant_id` for the platform and
    /// records `tenant.status_changed` with the operator as its actor.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the operator or key no longer
    ///   exists.
    /// - `AppError::Forbidden` when the key no longer works or the operator
    ///   is disabled.
    /// - `AppError::NotFound` if the tenant doesn't exist.
    /// - `AppError::Domain` if the tenant is not being provisioned.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &OperatorCaller,
        auditor: &RequestAuditor,
        tenant_id: TenantId,
    ) -> Result<(), AppError> {
        let authority = self.ports.operator_authorities.authority(caller).await?;
        let mut tenant = existing_tenant(self.ports.tenant_store.as_ref(), &tenant_id).await?;
        tenant
            .activate(ActedBy::Platform)
            .map_err(AppError::from_domain)?;
        self.ports.tenant_store.save(&tenant).await.or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), tenant.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::domains::tenant::status::{Archival, PlatformHold, TenantStatus};

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, Refusal};
    use crate::test_support::operator::test_operator_caller;
    use crate::test_support::tenant::{FakeTenantStore, tenant_for_ctx_standing};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    struct Setup {
        uc: ActivateTenantUseCase,
        tenants: Arc<FakeTenantStore>,
        audit: Arc<FakeEventDispatcher>,
        tenant_id: TenantId,
    }

    impl Setup {
        fn over(tenant: Tenant, authorities: FakeOperatorAuthorities) -> Self {
            let tenant_id = *tenant.id();
            let tenants = Arc::new(FakeTenantStore::holding(tenant));
            Self {
                uc: ActivateTenantUseCase::new(ActivateTenantPorts {
                    tenant_store: tenants.clone(),
                    operator_authorities: Arc::new(authorities),
                }),
                tenants,
                audit: Arc::new(FakeEventDispatcher::new()),
                tenant_id,
            }
        }

        fn standing(status: TenantStatus) -> Self {
            let tenant = tenant_for_ctx_standing(status, PlatformHold::Free, Archival::NotArchived);
            Self::over(tenant, FakeOperatorAuthorities::admitting())
        }

        fn activate(&self, tenant_id: TenantId) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &test_operator_caller(),
                &test_auditor(self.audit.clone()),
                tenant_id,
            ))
        }

        fn status(&self) -> TenantStatus {
            block_on(self.tenants.find_by_id(&self.tenant_id))
                .unwrap()
                .unwrap()
                .status()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// The tenant's setup stalled, and Bob, an operator, activates
    /// the tenant by hand. It is active and the change recorded.
    #[test]
    fn activate_provisioning_tenant_and_audits() {
        let setup = Setup::standing(TenantStatus::Provisioning);

        setup.activate(setup.tenant_id).unwrap();

        assert_eq!(setup.status(), TenantStatus::Active);
        assert_eq!(setup.recorded(), vec!["tenant.status_changed"]);
    }

    /// An active tenant cannot be activated again, and nothing is recorded.
    #[test]
    fn activate_active_tenant_returns_domain_error() {
        let setup = Setup::standing(TenantStatus::Active);

        let result = setup.activate(setup.tenant_id);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(setup.recorded().is_empty());
    }

    /// A suspended tenant comes back through reactivation, not activation.
    #[test]
    fn activate_suspended_tenant_returns_domain_error() {
        let setup = Setup::standing(TenantStatus::Suspended);

        let result = setup.activate(setup.tenant_id);

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Bob names a tenant that does not exist. It is not found.
    #[test]
    fn activate_unknown_tenant_returns_not_found() {
        let setup = Setup::standing(TenantStatus::Provisioning);

        let result = setup.activate(TenantId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.recorded().is_empty());
    }

    /// An operator denied platform authority cannot activate a tenant.
    /// The tenant stays provisioning.
    #[test]
    fn a_disabled_operator_is_refused() {
        let tenant = tenant_for_ctx_standing(
            TenantStatus::Provisioning,
            PlatformHold::Free,
            Archival::NotArchived,
        );
        let setup = Setup::over(
            tenant,
            FakeOperatorAuthorities::refusing(Refusal::Forbidden),
        );

        let result = setup.activate(setup.tenant_id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.status(), TenantStatus::Provisioning);
    }

    /// An unauthenticated operator cannot activate a tenant.
    #[test]
    fn a_signed_out_operator_is_refused() {
        let tenant = tenant_for_ctx_standing(
            TenantStatus::Provisioning,
            PlatformHold::Free,
            Archival::NotArchived,
        );
        let setup = Setup::over(
            tenant,
            FakeOperatorAuthorities::refusing(Refusal::SignedOut),
        );

        let result = setup.activate(setup.tenant_id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

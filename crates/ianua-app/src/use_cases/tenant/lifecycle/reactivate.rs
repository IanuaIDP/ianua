//! Reactivate tenant: bring a suspended tenant back to active.

use std::sync::Arc;

use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::TenantId;

use crate::acting::{OperatorAuthorities, OrgActors};
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::tenant::TenantStore;
use crate::use_case::Command;
use crate::use_cases::tenant::lifecycle::steward::{Acting, StewardSources, TenantSteward};

/// The ports [`ReactivateTenantUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ReactivateTenantPorts {
    /// Loads and saves the return of a suspended workspace to active use.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Reactivates a suspended tenant.
pub struct ReactivateTenantUseCase {
    ports: ReactivateTenantPorts,
}

impl ReactivateTenantUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: ReactivateTenantPorts) -> Self {
        Self { ports }
    }
}

impl Command for ReactivateTenantUseCase {
    type Caller = TenantSteward;
    type Input = TenantId;
    type Output = Result<(), AppError>;

    /// Brings the suspended tenant `tenant_id` back to active and records
    /// `tenant.status_changed`. A tenant the platform holds comes back only
    /// through the platform.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the member may not change the
    ///   organization's tenants or the platform holds the tenant, or the
    ///   operator is disabled.
    /// - `AppError::NotFound` if the tenant doesn't exist, or belongs to
    ///   another organization than the member's.
    /// - `AppError::Domain` if the tenant is not suspended.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &TenantSteward,
        auditor: &RequestAuditor,
        tenant_id: TenantId,
    ) -> Result<(), AppError> {
        let sources = StewardSources {
            org_actors: self.ports.org_actors.as_ref(),
            operator_authorities: self.ports.operator_authorities.as_ref(),
        };
        let acting = Acting::resolve(sources, caller).await?;
        let mut tenant = acting
            .reached_tenant(self.ports.tenant_store.as_ref(), &tenant_id)
            .await?;
        acting.decide(|by| tenant.reactivate(by))?;
        self.ports.tenant_store.save(&tenant).await.or_internal()?;
        auditor
            .dispatch_by(&acting.actor(), tenant.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::domains::tenant::status::{Archival, PlatformHold, TenantStatus};

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, FakeOrgActors, Refusal};
    use crate::test_support::operator::test_operator_caller;
    use crate::test_support::tenant::{
        FakeTenantStore, archived_tenant_for_ctx, tenant_for_ctx_standing,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: ReactivateTenantUseCase,
        tenants: Arc<FakeTenantStore>,
        audit: Arc<FakeEventDispatcher>,
        tenant_id: TenantId,
    }

    impl Setup {
        fn over(tenant: Tenant, ports: ReactivateTenantPorts) -> Self {
            let tenant_id = *tenant.id();
            let tenants = Arc::new(FakeTenantStore::holding(tenant));
            Self {
                uc: ReactivateTenantUseCase::new(ReactivateTenantPorts {
                    tenant_store: tenants.clone(),
                    ..ports
                }),
                tenants,
                audit: Arc::new(FakeEventDispatcher::new()),
                tenant_id,
            }
        }

        fn standing(status: TenantStatus, hold: PlatformHold) -> Self {
            let tenant = tenant_for_ctx_standing(status, hold, Archival::NotArchived);
            Self::over(tenant, ReactivateTenantPorts::fakes())
        }

        fn suspended_with(ports: ReactivateTenantPorts) -> Self {
            let tenant = tenant_for_ctx_standing(
                TenantStatus::Suspended,
                PlatformHold::Free,
                Archival::NotArchived,
            );
            Self::over(tenant, ports)
        }

        /// Runs the transition with the supplied member or platform authority.
        fn reactivate_as(&self, caller: &TenantSteward) -> Result<(), AppError> {
            block_on(
                self.uc
                    .execute(caller, &test_auditor(self.audit.clone()), self.tenant_id),
            )
        }

        fn reactivate(&self) -> Result<(), AppError> {
            self.reactivate_as(&TenantSteward::Member(test_org_caller()))
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

    /// Ann brings Acme's suspended tenant back. It is active and the change
    /// recorded.
    #[test]
    fn reactivate_suspended_tenant_and_audits() {
        let setup = Setup::standing(TenantStatus::Suspended, PlatformHold::Free);

        setup.reactivate().unwrap();

        assert_eq!(setup.status(), TenantStatus::Active);
        assert_eq!(setup.recorded(), vec!["tenant.status_changed"]);
    }

    /// A member cannot reactivate a tenant held by the platform. The tenant
    /// stays suspended.
    #[test]
    fn a_tenant_the_platform_holds_is_not_brought_back_by_a_member() {
        let setup = Setup::standing(TenantStatus::Suspended, PlatformHold::Held);

        let result = setup.reactivate();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.status(), TenantStatus::Suspended);
    }

    /// Bob, an operator, brings back a tenant the platform holds.
    #[test]
    fn the_platform_brings_back_a_tenant_it_holds() {
        let setup = Setup::standing(TenantStatus::Suspended, PlatformHold::Held);

        setup
            .reactivate_as(&TenantSteward::Platform(test_operator_caller()))
            .unwrap();

        assert_eq!(setup.status(), TenantStatus::Active);
    }

    /// An active tenant cannot be reactivated, and nothing is recorded.
    #[test]
    fn reactivate_active_tenant_returns_domain_error() {
        let setup = Setup::standing(TenantStatus::Active, PlatformHold::Free);

        let result = setup.reactivate();

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(setup.recorded().is_empty());
    }

    /// A tenant still being provisioned cannot be reactivated.
    #[test]
    fn reactivate_provisioning_tenant_returns_domain_error() {
        let setup = Setup::standing(TenantStatus::Provisioning, PlatformHold::Free);

        let result = setup.reactivate();

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// An archived tenant comes back through restore, not reactivation.
    #[test]
    fn reactivate_archived_tenant_returns_domain_error() {
        let setup = Setup::over(
            archived_tenant_for_ctx(1, PlatformHold::Free),
            ReactivateTenantPorts::fakes(),
        );

        let result = setup.reactivate();

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Ann names a tenant that does not exist. It is not found.
    #[test]
    fn reactivate_unknown_tenant_returns_not_found() {
        let setup = Setup::standing(TenantStatus::Suspended, PlatformHold::Free);

        let result = block_on(setup.uc.execute(
            &TenantSteward::Member(test_org_caller()),
            &test_auditor(setup.audit.clone()),
            TenantId::new(),
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.recorded().is_empty());
    }

    /// A member without tenant-update rights cannot reactivate the tenant.
    /// The tenant stays suspended.
    #[test]
    fn a_member_without_the_right_is_refused() {
        let setup = Setup::suspended_with(ReactivateTenantPorts {
            org_actors: Arc::new(FakeOrgActors::in_role(OrgRole::Member)),
            ..ReactivateTenantPorts::fakes()
        });

        let result = setup.reactivate();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.status(), TenantStatus::Suspended);
    }

    /// A signed-out member cannot reactivate the tenant.
    #[test]
    fn a_signed_out_member_is_refused() {
        let setup = Setup::suspended_with(ReactivateTenantPorts {
            org_actors: Arc::new(FakeOrgActors::refusing(Refusal::SignedOut)),
            ..ReactivateTenantPorts::fakes()
        });

        let result = setup.reactivate();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator denied platform authority cannot reactivate the tenant.
    #[test]
    fn a_disabled_operator_is_refused() {
        let setup = Setup::suspended_with(ReactivateTenantPorts {
            operator_authorities: Arc::new(FakeOperatorAuthorities::refusing(Refusal::Forbidden)),
            ..ReactivateTenantPorts::fakes()
        });

        let result = setup.reactivate_as(&TenantSteward::Platform(test_operator_caller()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}

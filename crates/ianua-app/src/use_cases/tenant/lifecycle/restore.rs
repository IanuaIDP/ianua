//! Restore tenant: bring an archived tenant back to active before it is
//! deleted.

use std::sync::Arc;

use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::TenantId;

use crate::acting::{OperatorAuthorities, OrgActors};
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::tenant::TenantStore;
use crate::use_case::Command;
use crate::use_cases::tenant::lifecycle::steward::{Acting, StewardSources, TenantSteward};

/// The ports [`RestoreTenantUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RestoreTenantPorts {
    /// Loads and saves the recovery of an archived workspace.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Restores an archived tenant.
pub struct RestoreTenantUseCase {
    ports: RestoreTenantPorts,
}

impl RestoreTenantUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: RestoreTenantPorts) -> Self {
        Self { ports }
    }
}

impl Command for RestoreTenantUseCase {
    type Caller = TenantSteward;
    type Input = TenantId;
    type Output = Result<(), AppError>;

    /// Brings the archived tenant `tenant_id` back to active, ends its wait
    /// before deletion, and records `tenant.status_changed`. A tenant the
    /// platform archived comes back only through the platform.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the member may not restore the
    ///   organization's tenants or the platform holds the tenant, or the
    ///   operator is disabled.
    /// - `AppError::NotFound` if the tenant doesn't exist, or belongs to
    ///   another organization than the member's.
    /// - `AppError::Domain` if the tenant is not archived.
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
        acting.decide(|by| tenant.restore(by))?;
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
        uc: RestoreTenantUseCase,
        tenants: Arc<FakeTenantStore>,
        audit: Arc<FakeEventDispatcher>,
        tenant_id: TenantId,
    }

    impl Setup {
        fn over(tenant: Tenant, ports: RestoreTenantPorts) -> Self {
            let tenant_id = *tenant.id();
            let tenants = Arc::new(FakeTenantStore::holding(tenant));
            Self {
                uc: RestoreTenantUseCase::new(RestoreTenantPorts {
                    tenant_store: tenants.clone(),
                    ..ports
                }),
                tenants,
                audit: Arc::new(FakeEventDispatcher::new()),
                tenant_id,
            }
        }

        fn archived(hold: PlatformHold) -> Self {
            Self::over(
                archived_tenant_for_ctx(1, hold),
                RestoreTenantPorts::fakes(),
            )
        }

        fn archived_with(ports: RestoreTenantPorts) -> Self {
            Self::over(archived_tenant_for_ctx(1, PlatformHold::Free), ports)
        }

        /// Runs the transition with the supplied member or platform authority.
        fn restore_as(&self, caller: &TenantSteward) -> Result<(), AppError> {
            block_on(
                self.uc
                    .execute(caller, &test_auditor(self.audit.clone()), self.tenant_id),
            )
        }

        fn restore(&self) -> Result<(), AppError> {
            self.restore_as(&TenantSteward::Member(test_org_caller()))
        }

        fn stored(&self) -> Tenant {
            block_on(self.tenants.find_by_id(&self.tenant_id))
                .unwrap()
                .unwrap()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann restores Acme's tenant, archived yesterday. It is active again,
    /// no longer waiting to be deleted, and the change is recorded.
    #[test]
    fn an_archived_tenant_is_restored_and_recorded() {
        let setup = Setup::archived(PlatformHold::Free);

        setup.restore().unwrap();

        assert_eq!(setup.stored().status(), TenantStatus::Active);
        assert!(setup.stored().deletable_from().is_none());
        assert_eq!(setup.recorded(), vec!["tenant.status_changed"]);
    }

    /// A member cannot restore a tenant held by the platform. The tenant
    /// stays archived and no status change is recorded.
    #[test]
    fn a_tenant_the_platform_holds_is_not_restored_by_a_member() {
        let setup = Setup::archived(PlatformHold::Held);

        let result = setup.restore();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.stored().status(), TenantStatus::Archived);
        assert!(setup.recorded().is_empty());
    }

    /// Bob, an operator, restores a tenant the platform archived. It is
    /// active again and no longer held.
    #[test]
    fn the_platform_restores_a_tenant_it_holds() {
        let setup = Setup::archived(PlatformHold::Held);

        setup
            .restore_as(&TenantSteward::Platform(test_operator_caller()))
            .unwrap();

        assert_eq!(setup.stored().status(), TenantStatus::Active);
        assert_eq!(setup.stored().hold(), PlatformHold::Free);
    }

    /// A suspended tenant comes back through reactivation, not restore, and
    /// nothing is recorded.
    #[test]
    fn a_tenant_that_is_not_archived_is_not_restored() {
        let tenant = tenant_for_ctx_standing(
            TenantStatus::Suspended,
            PlatformHold::Free,
            Archival::NotArchived,
        );
        let setup = Setup::over(tenant, RestoreTenantPorts::fakes());

        let result = setup.restore();

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(setup.recorded().is_empty());
    }

    /// Ann names a tenant that does not exist. It is not found.
    #[test]
    fn an_unknown_tenant_is_not_found() {
        let setup = Setup::archived(PlatformHold::Free);

        let result = block_on(setup.uc.execute(
            &TenantSteward::Member(test_org_caller()),
            &test_auditor(setup.audit.clone()),
            TenantId::new(),
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.recorded().is_empty());
    }

    /// A member without tenant-restore rights cannot restore the tenant.
    /// The tenant stays archived.
    #[test]
    fn a_member_without_the_right_is_refused() {
        let setup = Setup::archived_with(RestoreTenantPorts {
            org_actors: Arc::new(FakeOrgActors::in_role(OrgRole::Member)),
            ..RestoreTenantPorts::fakes()
        });

        let result = setup.restore();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.stored().status(), TenantStatus::Archived);
    }

    /// A signed-out member cannot restore the tenant.
    #[test]
    fn a_signed_out_member_is_refused() {
        let setup = Setup::archived_with(RestoreTenantPorts {
            org_actors: Arc::new(FakeOrgActors::refusing(Refusal::SignedOut)),
            ..RestoreTenantPorts::fakes()
        });

        let result = setup.restore();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator denied platform authority cannot restore the tenant.
    /// The tenant stays archived.
    #[test]
    fn a_disabled_operator_is_refused() {
        let setup = Setup::archived_with(RestoreTenantPorts {
            operator_authorities: Arc::new(FakeOperatorAuthorities::refusing(Refusal::Forbidden)),
            ..RestoreTenantPorts::fakes()
        });

        let result = setup.restore_as(&TenantSteward::Platform(test_operator_caller()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.stored().status(), TenantStatus::Archived);
    }
}

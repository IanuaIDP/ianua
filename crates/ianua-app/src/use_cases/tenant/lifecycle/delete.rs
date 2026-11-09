//! Delete tenant: wipe an archived tenant for good, once its grace has
//! passed, and take it off its organization.

use std::sync::Arc;

use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::TenantId;

use crate::acting::{OperatorAuthorities, OrgActors};
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrganizationStore;
use crate::ports::tenant::TenantStore;
use crate::use_case::Command;
use crate::use_cases::tenant::lifecycle::steward::{StewardPorts, TenantSteward};

/// The ports [`DeleteTenantUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeleteTenantPorts {
    /// Loads and saves the deleted workspace's lifecycle state.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Organizations, which lose the tenant.
    pub org_store: Arc<dyn OrganizationStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

impl StewardPorts for DeleteTenantPorts {
    fn org_actors(&self) -> &dyn OrgActors {
        self.org_actors.as_ref()
    }

    fn operator_authorities(&self) -> &dyn OperatorAuthorities {
        self.operator_authorities.as_ref()
    }
}

/// Deletes an archived tenant.
pub struct DeleteTenantUseCase {
    ports: DeleteTenantPorts,
}

impl DeleteTenantUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: DeleteTenantPorts) -> Self {
        Self { ports }
    }
}

impl Command for DeleteTenantUseCase {
    type Caller = TenantSteward;
    type Input = TenantId;
    type Output = Result<(), AppError>;

    /// Deletes the archived tenant `tenant_id`, takes it off its
    /// organization so it no longer counts against the plan, and records
    /// `tenant.status_changed` and `tenant.deleted`. This cannot be undone.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without tenant-deletion rights or for a disabled operator.
    /// - `AppError::NotFound` for a missing tenant/organization or a tenant outside the member's organization.
    /// - `AppError::Domain` for an unarchived tenant; `Conflict` before its archival grace ends; `Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &TenantSteward,
        auditor: &RequestAuditor,
        tenant_id: TenantId,
    ) -> Result<(), AppError> {
        let acting = self.ports.acting(caller).await?;
        let mut tenant = acting
            .reached_tenant(self.ports.tenant_store.as_ref(), &tenant_id)
            .await?;
        acting.decide(|by| tenant.delete(by))?;
        let mut organization = acting
            .organization(self.ports.org_store.as_ref(), tenant.organization_id())
            .await?;
        acting.decide_for_organization(|by| organization.remove_tenant(&tenant_id, by))?;
        self.ports.tenant_store.save(&tenant).await.or_internal()?;
        self.ports
            .org_store
            .save(&organization)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&acting.actor(), tenant.take_events())
            .await
            .or_internal()?;
        self.ports
            .org_store
            .invalidate(organization.id())
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
    use crate::test_support::organization::{FakeOrganizationStore, org_store_with, test_org};
    use crate::test_support::tenant::{
        FakeTenantStore, archived_tenant_for_ctx, tenant_for_ctx_standing,
    };
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_org_caller,
    };

    struct Setup {
        uc: DeleteTenantUseCase,
        tenants: Arc<FakeTenantStore>,
        orgs: Arc<FakeOrganizationStore>,
        audit: Arc<FakeEventDispatcher>,
        tenant_id: TenantId,
    }

    impl Setup {
        fn over(tenant: Tenant, ports: DeleteTenantPorts) -> Self {
            let tenant_id = *tenant.id();
            let tenants = Arc::new(FakeTenantStore::holding(tenant));
            let orgs = org_store_with([test_org(test_ctx().organization_id(), "acme")]);
            Self {
                uc: DeleteTenantUseCase::new(DeleteTenantPorts {
                    tenant_store: tenants.clone(),
                    org_store: orgs.clone(),
                    ..ports
                }),
                tenants,
                orgs,
                audit: Arc::new(FakeEventDispatcher::new()),
                tenant_id,
            }
        }

        fn past_its_grace() -> Self {
            Self::past_its_grace_with(DeleteTenantPorts::fakes())
        }

        fn past_its_grace_with(ports: DeleteTenantPorts) -> Self {
            Self::over(archived_tenant_for_ctx(31, PlatformHold::Free), ports)
        }

        /// Requests deletion with the supplied caller's authority.
        fn delete_as(&self, caller: &TenantSteward) -> Result<(), AppError> {
            block_on(
                self.uc
                    .execute(caller, &test_auditor(self.audit.clone()), self.tenant_id),
            )
        }

        fn delete(&self) -> Result<(), AppError> {
            self.delete_as(&TenantSteward::Member(test_org_caller()))
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

    /// Ann deletes a tenant archived 31 days ago. It is deleted, both changes
    /// are recorded, and the organization no longer lists it.
    #[test]
    fn delete_archived_tenant_and_audits() {
        let setup = Setup::past_its_grace();

        setup.delete().unwrap();

        let organization = setup.orgs.stored(&test_ctx().organization_id()).unwrap();
        assert_eq!(setup.status(), TenantStatus::Deleted);
        assert!(!organization.owns_tenant(&setup.tenant_id));
        assert_eq!(
            setup.recorded(),
            vec!["tenant.status_changed", "tenant.deleted"]
        );
    }

    /// Bob, an operator, deletes the tenant for the platform.
    #[test]
    fn the_platform_deletes_an_archived_tenant() {
        let setup = Setup::past_its_grace();

        setup
            .delete_as(&TenantSteward::Platform(test_operator_caller()))
            .unwrap();

        assert_eq!(setup.status(), TenantStatus::Deleted);
    }

    /// A tenant archived yesterday cannot be deleted within its grace period.
    /// The request conflicts and the tenant stays archived.
    #[test]
    fn a_tenant_inside_its_grace_is_kept() {
        let setup = Setup::over(
            archived_tenant_for_ctx(1, PlatformHold::Free),
            DeleteTenantPorts::fakes(),
        );

        let result = setup.delete();

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(setup.status(), TenantStatus::Archived);
    }

    /// An active tenant cannot be deleted, and nothing is recorded.
    #[test]
    fn delete_active_tenant_returns_domain_error() {
        let tenant = tenant_for_ctx_standing(
            TenantStatus::Active,
            PlatformHold::Free,
            Archival::NotArchived,
        );
        let setup = Setup::over(tenant, DeleteTenantPorts::fakes());

        let result = setup.delete();

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(setup.recorded().is_empty());
    }

    /// A suspended tenant must be archived before it is deleted.
    #[test]
    fn delete_suspended_tenant_returns_domain_error() {
        let tenant = tenant_for_ctx_standing(
            TenantStatus::Suspended,
            PlatformHold::Free,
            Archival::NotArchived,
        );
        let setup = Setup::over(tenant, DeleteTenantPorts::fakes());

        let result = setup.delete();

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Ann names a tenant that does not exist. It is not found.
    #[test]
    fn delete_unknown_tenant_returns_not_found() {
        let setup = Setup::past_its_grace();

        let result = block_on(setup.uc.execute(
            &TenantSteward::Member(test_org_caller()),
            &test_auditor(setup.audit.clone()),
            TenantId::new(),
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.recorded().is_empty());
    }

    /// A member without tenant-deletion rights cannot delete the tenant.
    /// The tenant stays archived.
    #[test]
    fn a_member_without_the_right_is_refused() {
        let setup = Setup::past_its_grace_with(DeleteTenantPorts {
            org_actors: Arc::new(FakeOrgActors::in_role(OrgRole::Member)),
            ..DeleteTenantPorts::fakes()
        });

        let result = setup.delete();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.status(), TenantStatus::Archived);
    }

    /// A signed-out member cannot delete the tenant.
    #[test]
    fn a_signed_out_member_is_refused() {
        let setup = Setup::past_its_grace_with(DeleteTenantPorts {
            org_actors: Arc::new(FakeOrgActors::refusing(Refusal::SignedOut)),
            ..DeleteTenantPorts::fakes()
        });

        let result = setup.delete();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator denied platform authority cannot delete the tenant.
    /// The tenant stays archived.
    #[test]
    fn a_disabled_operator_is_refused() {
        let setup = Setup::past_its_grace_with(DeleteTenantPorts {
            operator_authorities: Arc::new(FakeOperatorAuthorities::refusing(Refusal::Forbidden)),
            ..DeleteTenantPorts::fakes()
        });

        let result = setup.delete_as(&TenantSteward::Platform(test_operator_caller()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.status(), TenantStatus::Archived);
    }
}

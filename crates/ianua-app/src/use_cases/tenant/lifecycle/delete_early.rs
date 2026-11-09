//! Delete tenant early: the platform wipes an archived tenant before its
//! grace has run, for abuse or a legal order, and says why on the record.

use std::sync::Arc;

use ianua_domain::domains::tenant::lifecycle::EarlyDeletion;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::TenantId;

use crate::acting::OperatorAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::OperatorCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrganizationStore;
use crate::ports::tenant::TenantStore;
use crate::use_case::Command;
use crate::use_cases::tenant::lifecycle::steward::Acting;

/// Which tenant the platform deletes early, and why.
pub struct DeleteTenantEarlyRequest {
    /// The archived tenant.
    pub tenant_id: TenantId,
    /// Why the grace is cut short, with the platform's note.
    pub reason: EarlyDeletion,
}

/// The ports [`DeleteTenantEarlyUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeleteTenantEarlyPorts {
    /// Loads and saves the operator's early deletion of an archived workspace.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Organizations, which lose the tenant.
    pub org_store: Arc<dyn OrganizationStore>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Deletes an archived tenant before its grace has run, for the platform.
pub struct DeleteTenantEarlyUseCase {
    ports: DeleteTenantEarlyPorts,
}

impl DeleteTenantEarlyUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: DeleteTenantEarlyPorts) -> Self {
        Self { ports }
    }
}

impl Command for DeleteTenantEarlyUseCase {
    type Caller = OperatorCaller;
    type Input = DeleteTenantEarlyRequest;
    type Output = Result<(), AppError>;

    /// Deletes the archived tenant `request.tenant_id` at once, takes it off
    /// its organization, and records `tenant.status_changed`,
    /// `tenant.deleted` and `tenant.deleted_early` with the reason and note.
    /// This cannot be undone.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the operator or key no longer
    ///   exists.
    /// - `AppError::Forbidden` when the key no longer works or the operator
    ///   is disabled.
    /// - `AppError::NotFound` if the tenant or its organization doesn't
    ///   exist.
    /// - `AppError::Domain` if the tenant is not archived.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &OperatorCaller,
        auditor: &RequestAuditor,
        request: DeleteTenantEarlyRequest,
    ) -> Result<(), AppError> {
        let acting = Acting::Platform(self.ports.operator_authorities.authority(caller).await?);
        let mut tenant = acting
            .reached_tenant(self.ports.tenant_store.as_ref(), &request.tenant_id)
            .await?;
        acting.decide(|by| tenant.delete_early(by, request.reason))?;
        let mut organization = acting
            .organization(self.ports.org_store.as_ref(), tenant.organization_id())
            .await?;
        acting.decide_for_organization(|by| organization.remove_tenant(&request.tenant_id, by))?;
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
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::domains::tenant::status::{Archival, PlatformHold, TenantStatus};
    use ianua_domain::types::Text;

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, Refusal};
    use crate::test_support::operator::test_operator_caller;
    use crate::test_support::organization::{FakeOrganizationStore, org_store_with, test_org};
    use crate::test_support::tenant::{
        FakeTenantStore, archived_tenant_for_ctx, tenant_for_ctx_standing,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Setup {
        uc: DeleteTenantEarlyUseCase,
        tenants: Arc<FakeTenantStore>,
        orgs: Arc<FakeOrganizationStore>,
        audit: Arc<FakeEventDispatcher>,
        tenant_id: TenantId,
    }

    impl Setup {
        fn over(tenant: Tenant, authorities: FakeOperatorAuthorities) -> Self {
            let tenant_id = *tenant.id();
            let tenants = Arc::new(FakeTenantStore::holding(tenant));
            let orgs = org_store_with([test_org(test_ctx().organization_id(), "acme")]);
            Self {
                uc: DeleteTenantEarlyUseCase::new(DeleteTenantEarlyPorts {
                    tenant_store: tenants.clone(),
                    org_store: orgs.clone(),
                    operator_authorities: Arc::new(authorities),
                }),
                tenants,
                orgs,
                audit: Arc::new(FakeEventDispatcher::new()),
                tenant_id,
            }
        }

        fn archived_today() -> Self {
            Self::over(
                archived_tenant_for_ctx(0, PlatformHold::Held),
                FakeOperatorAuthorities::admitting(),
            )
        }

        fn delete_early(&self, tenant_id: TenantId) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &test_operator_caller(),
                &test_auditor(self.audit.clone()),
                DeleteTenantEarlyRequest {
                    tenant_id,
                    reason: phishing(),
                },
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

    fn phishing() -> EarlyDeletion {
        EarlyDeletion::Abuse(Text::new("note", "sent phishing mail to bank customers").unwrap())
    }

    /// Bob, an operator, wipes a tenant sending phishing mail on the day it
    /// was archived. It is deleted at once, the organization no longer
    /// lists it, and the record says why the grace was cut short.
    #[test]
    fn the_platform_deletes_an_archived_tenant_inside_its_grace() {
        let setup = Setup::archived_today();

        setup.delete_early(setup.tenant_id).unwrap();

        let organization = setup.orgs.stored(&test_ctx().organization_id()).unwrap();
        assert_eq!(setup.status(), TenantStatus::Deleted);
        assert!(!organization.owns_tenant(&setup.tenant_id));
        assert_eq!(
            setup.recorded(),
            vec![
                "tenant.status_changed",
                "tenant.deleted",
                "tenant.deleted_early"
            ]
        );
    }

    /// Early deletion requires an archived tenant. An active tenant stays
    /// active and no deletion is recorded.
    #[test]
    fn an_active_tenant_is_not_deleted_early() {
        let tenant = tenant_for_ctx_standing(
            TenantStatus::Active,
            PlatformHold::Free,
            Archival::NotArchived,
        );
        let setup = Setup::over(tenant, FakeOperatorAuthorities::admitting());

        let result = setup.delete_early(setup.tenant_id);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(setup.status(), TenantStatus::Active);
        assert!(setup.recorded().is_empty());
    }

    /// Bob names a tenant that does not exist. It is not found.
    #[test]
    fn an_unknown_tenant_is_not_found() {
        let setup = Setup::archived_today();

        let result = setup.delete_early(TenantId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// An operator denied platform authority cannot delete the tenant early.
    /// The tenant stays archived.
    #[test]
    fn a_disabled_operator_is_refused() {
        let setup = Setup::over(
            archived_tenant_for_ctx(0, PlatformHold::Held),
            FakeOperatorAuthorities::refusing(Refusal::Forbidden),
        );

        let result = setup.delete_early(setup.tenant_id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.status(), TenantStatus::Archived);
    }

    /// An unauthenticated operator cannot delete the tenant early. The tenant
    /// stays archived.
    #[test]
    fn a_signed_out_operator_is_refused() {
        let setup = Setup::over(
            archived_tenant_for_ctx(0, PlatformHold::Held),
            FakeOperatorAuthorities::refusing(Refusal::SignedOut),
        );

        let result = setup.delete_early(setup.tenant_id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(setup.status(), TenantStatus::Archived);
    }
}

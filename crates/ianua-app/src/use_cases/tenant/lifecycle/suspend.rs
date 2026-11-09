//! Suspend tenant: freeze a tenant, so nothing done in its name is served.

use std::sync::Arc;

use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::TenantId;

use crate::acting::{OperatorAuthorities, OrgActors};
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::shared::SessionStore;
use crate::ports::tenant::TenantStore;
use crate::use_case::Command;
use crate::use_cases::tenant::lifecycle::steward::{
    Acting, StewardSources, TenantSteward, sign_out_tenant,
};

/// The ports [`SuspendTenantUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SuspendTenantPorts {
    /// Loads and saves the pause of a workspace's active access.
    pub tenant_store: Arc<dyn TenantStore>,
    /// The tenant's sessions, every one of which is revoked.
    pub session_store: Arc<dyn SessionStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Pauses access to the workspace and revokes its sessions.
pub struct SuspendTenantUseCase {
    ports: SuspendTenantPorts,
}

impl SuspendTenantUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: SuspendTenantPorts) -> Self {
        Self { ports }
    }
}

impl Command for SuspendTenantUseCase {
    type Caller = TenantSteward;
    type Input = TenantId;
    type Output = Result<(), AppError>;

    /// Suspends the tenant `tenant_id`, signs every session in it out, and
    /// records `tenant.status_changed`.
    ///
    /// When the platform suspends it, the platform holds it, and only the
    /// platform brings it back.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the member may not change the
    ///   organization's tenants, or the operator is disabled.
    /// - `AppError::NotFound` if the tenant doesn't exist, or belongs to
    ///   another organization than the member's.
    /// - `AppError::Domain` if the tenant is not active.
    /// - `AppError::Internal` on persistence failure, including sessions
    ///   that could not be revoked.
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
        acting.decide(|by| tenant.suspend(by))?;
        self.ports.tenant_store.save(&tenant).await.or_internal()?;
        sign_out_tenant(self.ports.session_store.as_ref(), &tenant).await?;
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
    use crate::test_support::authentication::{FakeSessionStore, RevocationSwitch};
    use crate::test_support::operator::test_operator_caller;
    use crate::test_support::tenant::{
        FakeTenantStore, archived_tenant_for_ctx, tenant_for_ctx_standing, test_tenant,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: SuspendTenantUseCase,
        tenants: Arc<FakeTenantStore>,
        sessions: Arc<FakeSessionStore>,
        audit: Arc<FakeEventDispatcher>,
        tenant_id: TenantId,
    }

    impl Setup {
        fn over(tenant: Tenant, ports: SuspendTenantPorts) -> Self {
            let tenant_id = *tenant.id();
            let tenants = Arc::new(FakeTenantStore::holding(tenant));
            let sessions = Arc::new(FakeSessionStore::empty());
            Self {
                uc: SuspendTenantUseCase::new(SuspendTenantPorts {
                    tenant_store: tenants.clone(),
                    session_store: sessions.clone(),
                    ..ports
                }),
                tenants,
                sessions,
                audit: Arc::new(FakeEventDispatcher::new()),
                tenant_id,
            }
        }

        fn standing(status: TenantStatus) -> Self {
            let tenant = tenant_for_ctx_standing(status, PlatformHold::Free, Archival::NotArchived);
            Self::over(tenant, SuspendTenantPorts::fakes())
        }

        fn active_with(ports: SuspendTenantPorts) -> Self {
            let tenant = tenant_for_ctx_standing(
                TenantStatus::Active,
                PlatformHold::Free,
                Archival::NotArchived,
            );
            Self::over(tenant, ports)
        }

        /// Runs the transition with the supplied member or platform authority.
        fn suspend_as(&self, caller: &TenantSteward) -> Result<(), AppError> {
            block_on(
                self.uc
                    .execute(caller, &test_auditor(self.audit.clone()), self.tenant_id),
            )
        }

        fn suspend(&self) -> Result<(), AppError> {
            self.suspend_as(&TenantSteward::Member(test_org_caller()))
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

    /// Ann, an owner of Acme, suspends its active tenant. It is suspended,
    /// left free for Acme to bring back, and the change recorded.
    #[test]
    fn suspend_active_tenant_and_audits() {
        let setup = Setup::standing(TenantStatus::Active);

        setup.suspend().unwrap();

        assert_eq!(setup.stored().status(), TenantStatus::Suspended);
        assert_eq!(setup.stored().hold(), PlatformHold::Free);
        assert_eq!(setup.recorded(), vec!["tenant.status_changed"]);
    }

    /// Bob, an operator, suspends the tenant for the platform. The platform
    /// holds it, so only the platform brings it back.
    #[test]
    fn the_platform_suspends_and_holds_the_tenant() {
        let setup = Setup::standing(TenantStatus::Active);

        setup
            .suspend_as(&TenantSteward::Platform(test_operator_caller()))
            .unwrap();

        assert_eq!(setup.stored().status(), TenantStatus::Suspended);
        assert_eq!(setup.stored().hold(), PlatformHold::Held);
    }

    /// Ann suspends the tenant. Every session in it is revoked, so nobody
    /// stays signed in to a frozen tenant.
    #[test]
    fn suspend_revokes_all_tenant_sessions() {
        let setup = Setup::standing(TenantStatus::Active);

        setup.suspend().unwrap();

        assert_eq!(
            *setup.sessions.revoke_all_by_tenant_count.lock().unwrap(),
            1
        );
    }

    /// A tenant still being provisioned cannot be suspended, and nothing is
    /// recorded.
    #[test]
    fn suspend_provisioning_tenant_returns_domain_error() {
        let setup = Setup::standing(TenantStatus::Provisioning);

        let result = setup.suspend();

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(setup.recorded().is_empty());
    }

    /// A tenant already suspended cannot be suspended again.
    #[test]
    fn suspend_already_suspended_returns_domain_error() {
        let setup = Setup::standing(TenantStatus::Suspended);

        let result = setup.suspend();

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// An archived tenant cannot be suspended.
    #[test]
    fn suspend_archived_tenant_returns_domain_error() {
        let setup = Setup::over(
            archived_tenant_for_ctx(1, PlatformHold::Free),
            SuspendTenantPorts::fakes(),
        );

        let result = setup.suspend();

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Ann names a tenant that does not exist. It is not found.
    #[test]
    fn suspend_unknown_tenant_returns_not_found() {
        let setup = Setup::standing(TenantStatus::Active);

        let result = block_on(setup.uc.execute(
            &TenantSteward::Member(test_org_caller()),
            &test_auditor(setup.audit.clone()),
            TenantId::new(),
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.recorded().is_empty());
    }

    /// A member cannot suspend another organization's tenant. The tenant is
    /// not found and stays provisioning.
    #[test]
    fn another_organizations_tenant_is_not_found() {
        let setup = Setup::over(
            test_tenant("globex", "globex.com"),
            SuspendTenantPorts::fakes(),
        );

        let result = setup.suspend();

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(setup.stored().status(), TenantStatus::Provisioning);
    }

    /// A member without tenant-update rights cannot suspend the tenant.
    /// The tenant stays active.
    #[test]
    fn a_member_without_the_right_is_refused() {
        let setup = Setup::active_with(SuspendTenantPorts {
            org_actors: Arc::new(FakeOrgActors::in_role(OrgRole::Member)),
            ..SuspendTenantPorts::fakes()
        });

        let result = setup.suspend();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.stored().status(), TenantStatus::Active);
    }

    /// A signed-out member cannot suspend the tenant.
    #[test]
    fn a_signed_out_member_is_refused() {
        let setup = Setup::active_with(SuspendTenantPorts {
            org_actors: Arc::new(FakeOrgActors::refusing(Refusal::SignedOut)),
            ..SuspendTenantPorts::fakes()
        });

        let result = setup.suspend();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator denied platform authority cannot suspend the tenant.
    /// The tenant stays active.
    #[test]
    fn a_disabled_operator_is_refused() {
        let setup = Setup::active_with(SuspendTenantPorts {
            operator_authorities: Arc::new(FakeOperatorAuthorities::refusing(Refusal::Forbidden)),
            ..SuspendTenantPorts::fakes()
        });

        let result = setup.suspend_as(&TenantSteward::Platform(test_operator_caller()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.stored().status(), TenantStatus::Active);
    }

    /// A suspension whose sessions could not be revoked reports the failure
    /// instead of claiming it signed everyone out, and records nothing.
    #[test]
    fn suspend_fails_when_sessions_cannot_be_revoked() {
        let tenant = tenant_for_ctx_standing(
            TenantStatus::Active,
            PlatformHold::Free,
            Archival::NotArchived,
        );
        let setup = Setup::over(tenant, SuspendTenantPorts::fakes());
        let uc = SuspendTenantUseCase::new(SuspendTenantPorts {
            tenant_store: setup.tenants.clone(),
            session_store: Arc::new(FakeSessionStore::empty().failing_revocation()),
            ..SuspendTenantPorts::fakes()
        });

        let result = block_on(uc.execute(
            &TenantSteward::Member(test_org_caller()),
            &test_auditor(setup.audit.clone()),
            setup.tenant_id,
        ));

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert!(setup.recorded().is_empty());
    }
}

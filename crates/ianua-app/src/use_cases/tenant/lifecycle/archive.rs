//! Archive tenant: close a tenant and start the wait before it may be
//! deleted.

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

/// The ports [`ArchiveTenantUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ArchiveTenantPorts {
    /// Loads and saves the transition that removes this workspace from active use.
    pub tenant_store: Arc<dyn TenantStore>,
    /// The tenant's sessions, every one of which is revoked.
    pub session_store: Arc<dyn SessionStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Removes the workspace from active use and revokes its sessions.
pub struct ArchiveTenantUseCase {
    ports: ArchiveTenantPorts,
}

impl ArchiveTenantUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: ArchiveTenantPorts) -> Self {
        Self { ports }
    }
}

impl Command for ArchiveTenantUseCase {
    type Caller = TenantSteward;
    type Input = TenantId;
    type Output = Result<(), AppError>;

    /// Archives the tenant `tenant_id`, signs every session in it out, and
    /// records `tenant.status_changed`. It may be restored until it is
    /// deleted, once its grace has passed.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the member may not delete the
    ///   organization's tenants, archives a tenant still provisioning, or
    ///   the operator is disabled.
    /// - `AppError::NotFound` if the tenant doesn't exist, or belongs to
    ///   another organization than the member's.
    /// - `AppError::Domain` unless the tenant is provisioning, active or
    ///   suspended.
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
        acting.decide(|by| tenant.archive(by))?;
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
        FakeTenantStore, archived_tenant_for_ctx, tenant_for_ctx_standing,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: ArchiveTenantUseCase,
        tenants: Arc<FakeTenantStore>,
        sessions: Arc<FakeSessionStore>,
        audit: Arc<FakeEventDispatcher>,
        tenant_id: TenantId,
    }

    impl Setup {
        fn over(tenant: Tenant, ports: ArchiveTenantPorts) -> Self {
            let tenant_id = *tenant.id();
            let tenants = Arc::new(FakeTenantStore::holding(tenant));
            let sessions = Arc::new(FakeSessionStore::empty());
            Self {
                uc: ArchiveTenantUseCase::new(ArchiveTenantPorts {
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
            Self::over(tenant, ArchiveTenantPorts::fakes())
        }

        /// Runs the transition with the supplied member or platform authority.
        fn archive_as(&self, caller: &TenantSteward) -> Result<(), AppError> {
            block_on(
                self.uc
                    .execute(caller, &test_auditor(self.audit.clone()), self.tenant_id),
            )
        }

        fn archive(&self) -> Result<(), AppError> {
            self.archive_as(&TenantSteward::Member(test_org_caller()))
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

    /// Ann archives Acme's active tenant. It is archived, its grace starts,
    /// and the change is recorded.
    #[test]
    fn archive_active_tenant_and_audits() {
        let setup = Setup::standing(TenantStatus::Active);

        setup.archive().unwrap();

        assert_eq!(setup.stored().status(), TenantStatus::Archived);
        assert!(setup.stored().deletable_from().is_some());
        assert_eq!(setup.recorded(), vec!["tenant.status_changed"]);
    }

    /// A suspended tenant can be archived too.
    #[test]
    fn archive_suspended_tenant_succeeds() {
        let setup = Setup::standing(TenantStatus::Suspended);

        setup.archive().unwrap();

        assert_eq!(setup.stored().status(), TenantStatus::Archived);
    }

    /// Bob, an operator, archives the tenant for the platform. The platform
    /// holds it, so Acme cannot restore it on its own.
    #[test]
    fn the_platform_archives_and_holds_the_tenant() {
        let setup = Setup::standing(TenantStatus::Active);

        setup
            .archive_as(&TenantSteward::Platform(test_operator_caller()))
            .unwrap();

        assert_eq!(setup.stored().hold(), PlatformHold::Held);
    }

    /// Ann archives the tenant. Every session in it is revoked.
    #[test]
    fn archive_revokes_all_tenant_sessions() {
        let setup = Setup::standing(TenantStatus::Active);

        setup.archive().unwrap();

        assert_eq!(
            *setup.sessions.revoke_all_by_tenant_count.lock().unwrap(),
            1
        );
    }

    /// An organization member cannot archive a provisioning tenant.
    /// The request is refused and no status change is recorded.
    #[test]
    fn a_member_archiving_a_provisioning_tenant_is_refused() {
        let setup = Setup::standing(TenantStatus::Provisioning);

        let result = setup.archive();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.recorded().is_empty());
    }

    /// An archived tenant cannot be archived again.
    #[test]
    fn archive_already_archived_returns_domain_error() {
        let setup = Setup::over(
            archived_tenant_for_ctx(1, PlatformHold::Free),
            ArchiveTenantPorts::fakes(),
        );

        let result = setup.archive();

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Ann names a tenant that does not exist. It is not found.
    #[test]
    fn archive_unknown_tenant_returns_not_found() {
        let setup = Setup::standing(TenantStatus::Active);

        let result = block_on(setup.uc.execute(
            &TenantSteward::Member(test_org_caller()),
            &test_auditor(setup.audit.clone()),
            TenantId::new(),
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.recorded().is_empty());
    }

    /// A member without tenant-deletion rights cannot archive the tenant.
    /// The tenant stays active.
    #[test]
    fn a_member_without_the_right_is_refused() {
        let tenant = tenant_for_ctx_standing(
            TenantStatus::Active,
            PlatformHold::Free,
            Archival::NotArchived,
        );
        let setup = Setup::over(
            tenant,
            ArchiveTenantPorts {
                org_actors: Arc::new(FakeOrgActors::in_role(OrgRole::Member)),
                ..ArchiveTenantPorts::fakes()
            },
        );

        let result = setup.archive();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.stored().status(), TenantStatus::Active);
    }

    /// A signed-out member cannot archive the tenant.
    #[test]
    fn a_signed_out_member_is_refused() {
        let tenant = tenant_for_ctx_standing(
            TenantStatus::Active,
            PlatformHold::Free,
            Archival::NotArchived,
        );
        let setup = Setup::over(
            tenant,
            ArchiveTenantPorts {
                org_actors: Arc::new(FakeOrgActors::refusing(Refusal::SignedOut)),
                ..ArchiveTenantPorts::fakes()
            },
        );

        let result = setup.archive();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator denied platform authority cannot archive the tenant.
    /// The tenant stays active.
    #[test]
    fn a_disabled_operator_is_refused() {
        let tenant = tenant_for_ctx_standing(
            TenantStatus::Active,
            PlatformHold::Free,
            Archival::NotArchived,
        );
        let setup = Setup::over(
            tenant,
            ArchiveTenantPorts {
                operator_authorities: Arc::new(FakeOperatorAuthorities::refusing(
                    Refusal::Forbidden,
                )),
                ..ArchiveTenantPorts::fakes()
            },
        );

        let result = setup.archive_as(&TenantSteward::Platform(test_operator_caller()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.stored().status(), TenantStatus::Active);
    }

    /// A tenant archived while its sessions could not be revoked would keep
    /// serving signed-in users; the archive reports the failure instead of
    /// claiming it signed everyone out.
    #[test]
    fn archive_fails_when_sessions_cannot_be_revoked() {
        let setup = Setup::standing(TenantStatus::Active);
        let uc = ArchiveTenantUseCase::new(ArchiveTenantPorts {
            tenant_store: setup.tenants.clone(),
            session_store: Arc::new(FakeSessionStore::empty().failing_revocation()),
            ..ArchiveTenantPorts::fakes()
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

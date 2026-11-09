//! Get tenant: one tenant, for someone acting in it, a member of its
//! organization, or the platform.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{SystemPermission, TenantSettingsAction};
use ianua_domain::domains::organization::members::permission::{OrgPermission, TenantAction};
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::domains::tenant::setup::SetupStanding;
use ianua_domain::message;
use ianua_domain::types::{OrganizationId, TenantId};

use crate::acting::{OperatorAuthorities, OrgActors, TenantAuthorities};
use crate::context::{CallerContext, OperatorCaller, OrgCaller};
use crate::error::AppError;
use crate::ports::tenant::{TenantSetupStore, TenantStore};
use crate::services::lookup::existing_tenant;
use crate::use_case::Query;
use crate::use_cases::tenant::lifecycle::reading::lookup::read_tenant;

/// Who asks for a tenant, and so which one they may see.
pub enum TenantViewer {
    /// Someone acting in a tenant, for that tenant.
    Tenant(CallerContext),
    /// A member, for one of their organization's tenants.
    Organization {
        /// The member asking.
        caller: OrgCaller,
        /// The tenant they ask for.
        tenant_id: TenantId,
    },
    /// An operator, for any tenant.
    Platform {
        /// The operator asking.
        caller: OperatorCaller,
        /// The tenant they ask for.
        tenant_id: TenantId,
    },
}

/// A tenant as it is read, with how its setup stands: a tenant whose setup
/// failed stays provisioning, and only this tells it apart from one still
/// being set up.
pub struct TenantRead {
    /// The workspace record whose provisioning progress accompanies it.
    pub tenant: Tenant,
    /// How its setup stands.
    pub setup: SetupStanding,
}

/// The ports [`GetTenantUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetTenantPorts {
    /// Loads the workspace's current lifecycle and settings.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Each tenant's setup, read while it is still provisioning.
    pub setup_store: Arc<dyn TenantSetupStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Reads one tenant.
pub struct GetTenantUseCase {
    ports: GetTenantPorts,
}

impl GetTenantUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetTenantPorts) -> Self {
        Self { ports }
    }

    /// The tenant `viewer` asks for, once they may see it.
    async fn visible_tenant(&self, viewer: &TenantViewer) -> Result<Tenant, AppError> {
        let store = self.ports.tenant_store.as_ref();
        match viewer {
            TenantViewer::Tenant(ctx) => {
                self.ports
                    .tenant_authorities
                    .authority(ctx)
                    .await?
                    .ensure_holds(SystemPermission::TenantSettings(TenantSettingsAction::View))
                    .map_err(AppError::from_domain)?;
                existing_tenant(store, &ctx.tenant_id()).await
            }
            TenantViewer::Organization { caller, tenant_id } => {
                self.organizations_tenant(caller, tenant_id).await
            }
            TenantViewer::Platform { caller, tenant_id } => {
                self.ports.operator_authorities.authority(caller).await?;
                existing_tenant(store, tenant_id).await
            }
        }
    }

    /// The tenant `tenant_id` of `caller`'s organization, once they may view
    /// its tenants.
    async fn organizations_tenant(
        &self,
        caller: &OrgCaller,
        tenant_id: &TenantId,
    ) -> Result<Tenant, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        actor
            .control()?
            .ensure_may(
                organization.id(),
                OrgPermission::Tenants(TenantAction::View),
            )
            .map_err(AppError::from_domain)?;
        let tenant = existing_tenant(self.ports.tenant_store.as_ref(), tenant_id).await?;
        ensure_of(&tenant, organization.id())?;
        Ok(tenant)
    }
}

impl Query for GetTenantUseCase {
    type Caller = TenantViewer;
    type Input = ();
    type Output = Result<TenantRead, AppError>;

    /// The tenant `viewer` asks for, with how its setup stands.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when someone in the tenant may not view its
    ///   settings, a member may not view the organization's tenants, or the
    ///   operator is disabled.
    /// - `AppError::NotFound` if the tenant doesn't exist, or belongs to
    ///   another organization than the member's.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(&self, viewer: &TenantViewer, (): ()) -> Result<TenantRead, AppError> {
        let tenant = self.visible_tenant(viewer).await?;
        read_tenant(self.ports.setup_store.as_ref(), tenant).await
    }
}

/// Refuses, as not found, a tenant of another organization than
/// `organization`.
fn ensure_of(tenant: &Tenant, organization: &OrganizationId) -> Result<(), AppError> {
    if tenant.organization_id() != organization {
        return Err(AppError::NotFound(message!(
            "app-tenant-not-found",
            "tenant not found"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::setup::{SetupStep, TenantSetup};
    use ianua_domain::types::UntrustedText;

    use super::*;
    use crate::test_support::acting::{
        FakeOperatorAuthorities, FakeOrgActors, FakeTenantAuthorities, Refusal,
    };
    use crate::test_support::operator::{operator_without_grant, test_operator_caller};
    use crate::test_support::tenant::{
        FakeTenantSetupStore, FakeTenantStore, test_tenant, test_tenant_for_ctx,
    };
    use crate::test_support::{block_on, test_ctx, test_org_caller};

    fn reading(ports: GetTenantPorts) -> GetTenantUseCase {
        GetTenantUseCase::new(GetTenantPorts {
            tenant_store: Arc::new(FakeTenantStore::holding_all([
                test_tenant_for_ctx(),
                test_tenant("globex", "globex.com"),
            ])),
            ..ports
        })
    }

    /// Reads through the supplied viewer's authority.
    fn get(uc: &GetTenantUseCase, viewer: &TenantViewer) -> Result<TenantRead, AppError> {
        block_on(uc.execute(viewer, ()))
    }

    fn member_asking_for(tenant_id: TenantId) -> TenantViewer {
        TenantViewer::Organization {
            caller: test_org_caller(),
            tenant_id,
        }
    }

    /// Ann, an admin of Acme's tenant, reads it.
    #[test]
    fn a_tenant_caller_reads_their_tenant() {
        let uc = reading(GetTenantPorts::fakes());

        let read = get(&uc, &TenantViewer::Tenant(test_ctx())).unwrap();

        assert_eq!(*read.tenant.id(), test_ctx().tenant_id());
    }

    /// Ann, an owner of Acme, reads one of its tenants from the
    /// organization view. It is still being set up.
    #[test]
    fn a_member_reads_their_organizations_tenant() {
        let uc = reading(GetTenantPorts::fakes());

        let read = get(&uc, &member_asking_for(test_ctx().tenant_id())).unwrap();

        assert_eq!(*read.tenant.id(), test_ctx().tenant_id());
        assert_eq!(read.setup, SetupStanding::Running);
    }

    /// Acme's tenant is provisioning and its signing key failed for good.
    /// Ann reads it: it says the setup failed at that step, not that it is
    /// still being set up.
    #[test]
    fn a_tenant_whose_setup_failed_says_so() {
        let tenant = test_tenant_for_ctx();
        let mut setup = TenantSetup::begin(&tenant).unwrap();
        setup
            .fail(SetupStep::SigningKey, UntrustedText::record("no key store"))
            .unwrap();
        let setups = Arc::new(FakeTenantSetupStore::empty());
        block_on(setups.save(&setup)).unwrap();
        let uc = reading(GetTenantPorts {
            setup_store: setups,
            ..GetTenantPorts::fakes()
        });

        let read = get(&uc, &member_asking_for(test_ctx().tenant_id())).unwrap();

        assert_eq!(read.setup, SetupStanding::Failed(SetupStep::SigningKey));
    }

    /// Bob, an operator, reads any tenant.
    #[test]
    fn the_platform_reads_any_tenant() {
        let uc = reading(GetTenantPorts::fakes());
        let viewer = TenantViewer::Platform {
            caller: test_operator_caller(),
            tenant_id: test_ctx().tenant_id(),
        };

        assert!(get(&uc, &viewer).is_ok());
    }

    /// A tenant that does not exist is not found.
    #[test]
    fn an_unknown_tenant_is_not_found() {
        let uc = reading(GetTenantPorts::fakes());

        let result = get(&uc, &member_asking_for(TenantId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A member querying another organization's tenant receives not found.
    #[test]
    fn another_organizations_tenant_is_not_found() {
        let globex = test_tenant("globex", "globex.com");
        let globex_id = *globex.id();
        let uc = GetTenantUseCase::new(GetTenantPorts {
            tenant_store: Arc::new(FakeTenantStore::holding(globex)),
            ..GetTenantPorts::fakes()
        });

        let result = get(&uc, &member_asking_for(globex_id));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A tenant caller without settings-view rights cannot read the tenant.
    #[test]
    fn a_tenant_caller_without_the_view_right_is_refused() {
        let uc = reading(GetTenantPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..GetTenantPorts::fakes()
        });

        let result = get(&uc, &TenantViewer::Tenant(test_ctx()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out tenant session cannot read the tenant.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let uc = reading(GetTenantPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..GetTenantPorts::fakes()
        });

        let result = get(&uc, &TenantViewer::Tenant(test_ctx()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator without an impersonation grant cannot read a tenant through
    /// the tenant-scoped entry point.
    #[test]
    fn an_operator_without_a_grant_is_refused() {
        let uc = reading(GetTenantPorts::fakes());

        let result = get(&uc, &TenantViewer::Tenant(operator_without_grant()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A caller denied organization membership cannot read its tenant.
    #[test]
    fn a_member_the_organization_turns_away_is_refused() {
        let uc = reading(GetTenantPorts {
            org_actors: Arc::new(FakeOrgActors::refusing(Refusal::Forbidden)),
            ..GetTenantPorts::fakes()
        });

        let result = get(&uc, &member_asking_for(test_ctx().tenant_id()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An operator denied platform authority cannot read a tenant.
    #[test]
    fn a_disabled_operator_is_refused() {
        let uc = reading(GetTenantPorts {
            operator_authorities: Arc::new(FakeOperatorAuthorities::refusing(Refusal::Forbidden)),
            ..GetTenantPorts::fakes()
        });
        let viewer = TenantViewer::Platform {
            caller: test_operator_caller(),
            tenant_id: test_ctx().tenant_id(),
        };

        assert!(matches!(get(&uc, &viewer), Err(AppError::Forbidden(_))));
    }
}

//! Provision tenant: make a new tenant for an organization.
//!
//! A tenant starts with no primary domain. It proves a domain once it
//! exists, then makes that one primary.

use std::sync::Arc;

use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::tenant::compliance_limits::ComplianceLimits;
use ianua_domain::domains::tenant::hosts::PlatformLabel;
use ianua_domain::domains::tenant::lifecycle::{ProvisionTenantParams, Tenant};
use ianua_domain::domains::tenant::provisioning::infrastructure::TenantResidency;
use ianua_domain::message;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{
    DisplayName, Email, Locale, OrganizationId, TenantId, TenantSlug, Timezone,
};

use crate::acting::{OperatorAuthorities, OrgActors};
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrConflict, OrInternal};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::organization::OrganizationStore;
use crate::ports::runtime::SecureRandom;
use crate::ports::tenant::TenantStore;
use crate::use_case::Command;
use crate::use_cases::tenant::lifecycle::steward::{Acting, StewardPorts, TenantSteward};

/// What a caller is told when the organization already has a tenant under
/// the slug.
const SLUG_TAKEN: &str = "slug already taken";

/// Parameters for provisioning a new tenant.
pub struct ProvisionTenantRequest {
    /// The organization that owns this tenant. A member names their own.
    pub organization_id: OrganizationId,
    /// URL-safe slug for subdomains and API paths.
    pub slug: TenantSlug,
    /// Tenant name shown in admin UIs.
    pub display_name: DisplayName,
    /// Contact email for tenant notifications.
    pub contact_email: Email,
    /// Default timezone.
    pub timezone: Timezone,
    /// Default locale.
    pub locale: Locale,
    /// Where this tenant's data should live.
    ///
    /// Named at creation because it decides what gets provisioned. Moving
    /// a tenant afterwards is a data migration, not a settings change, so
    /// there is no later opportunity to leave this undecided.
    pub residency: TenantResidency,
}

/// The ports [`ProvisionTenantUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ProvisionTenantPorts {
    /// Supplies independent randomness for the tenant's address.
    pub random: Arc<dyn SecureRandom>,
    /// Persists the new workspace under its owning organization.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Organizations, which gain the tenant.
    pub org_store: Arc<dyn OrganizationStore>,
    /// Plan limits.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

impl StewardPorts for ProvisionTenantPorts {
    fn org_actors(&self) -> &dyn OrgActors {
        self.org_actors.as_ref()
    }

    fn operator_authorities(&self) -> &dyn OperatorAuthorities {
        self.operator_authorities.as_ref()
    }
}

/// Provisions a new tenant.
pub struct ProvisionTenantUseCase {
    compliance_limits: ComplianceLimits,
    ports: ProvisionTenantPorts,
}

impl ProvisionTenantUseCase {
    /// A use case under the deployment's `compliance_limits`, writing
    /// through `ports`.
    #[must_use]
    pub fn new(compliance_limits: ComplianceLimits, ports: ProvisionTenantPorts) -> Self {
        Self {
            compliance_limits,
            ports,
        }
    }

    /// Refuses `tenant` when the plan `organization` is on has no room for
    /// it, or does not cover its residency. The plan is the one on record,
    /// never one the request names.
    async fn ensure_plan_covers(
        &self,
        organization: &Organization,
        tenant: &Tenant,
    ) -> Result<(), AppError> {
        let limits = organization.limits();
        self.ports
            .limit_enforcer
            .check_org_limit(&limits, organization.id(), ResourceKind::Tenants)
            .await
            .map_err(AppError::from_domain)?;
        limits
            .permits_residency(tenant.residency())
            .map_err(AppError::from_domain)
    }

    /// Refuses a slug another tenant of the same organization already has.
    /// Another organization's tenant under the slug does not stand in the
    /// way: slugs are unique only within an organization.
    async fn ensure_slug_free(&self, tenant: &Tenant) -> Result<(), AppError> {
        let taken = self
            .ports
            .tenant_store
            .slug_exists_in_org(tenant.slug(), tenant.organization_id())
            .await
            .or_internal()?;
        if taken {
            return Err(AppError::Conflict(SLUG_TAKEN.to_owned().into()));
        }
        Ok(())
    }

    /// Saves the new `tenant`, then `organization` holding it. A slug taken
    /// meanwhile by another request is refused by the store, and is a
    /// conflict.
    async fn keep(&self, tenant: &Tenant, organization: &Organization) -> Result<(), AppError> {
        self.ports
            .tenant_store
            .save(tenant)
            .await
            .or_conflict(message!("tenant-slug-already-taken", SLUG_TAKEN))?;
        self.ports.org_store.save(organization).await.or_internal()
    }

    /// The new tenant `req` asks for, made as `acting` decides.
    fn new_tenant(&self, acting: &Acting, req: ProvisionTenantRequest) -> Result<Tenant, AppError> {
        let params = ProvisionTenantParams {
            id: TenantId::new(),
            platform_label: PlatformLabel::generate(&mut self.ports.random.as_ref())
                .map_err(AppError::from_domain)?,
            organization_id: req.organization_id,
            slug: req.slug,
            display_name: req.display_name,
            contact_email: req.contact_email,
            timezone: req.timezone,
            locale: req.locale,
            residency: req.residency,
        };
        acting.decide(|by| Tenant::provision(params, &self.compliance_limits, by))
    }
}

impl Command for ProvisionTenantUseCase {
    type Caller = TenantSteward;
    type Input = ProvisionTenantRequest;
    type Output = Result<TenantId, AppError>;

    /// Provisions a new tenant for a member of its organization or for the
    /// platform, adds it to the organization, and records
    /// `tenant.provisioned` and `organization.tenant_created`.
    ///
    /// The domain decides first whether the caller may make the tenant, so
    /// a caller who may not learns nothing of the plan or of which slugs
    /// the organization already holds. The plan's checks then run before
    /// anything is saved: a residency the plan does not cover must fail
    /// here, not after the tenant row exists and its setup is already
    /// trying to build it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` for a full/incompatible plan, missing tenant-creation rights or a disabled operator.
    /// - `AppError::NotFound` for a missing/foreign organization; `Domain` for residency outside the platform's declaration.
    /// - `AppError::Conflict` for a taken slug, including concurrent creation, or a full tenant allowance.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &TenantSteward,
        auditor: &RequestAuditor,
        req: ProvisionTenantRequest,
    ) -> Result<TenantId, AppError> {
        let acting = self.ports.acting(caller).await?;
        let mut organization = acting
            .organization(self.ports.org_store.as_ref(), &req.organization_id)
            .await?;
        let mut tenant = self.new_tenant(&acting, req)?;
        acting.decide_for_organization(|by| organization.add_tenant(&tenant, by))?;
        self.ensure_plan_covers(&organization, &tenant).await?;
        self.ensure_slug_free(&tenant).await?;
        self.keep(&tenant, &organization).await?;
        let mut events = tenant.take_events();
        events.extend(organization.take_events());
        auditor
            .dispatch_by(&acting.actor(), events)
            .await
            .or_internal()?;
        self.ports
            .org_store
            .invalidate(organization.id())
            .await
            .or_internal()?;
        Ok(*tenant.id())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::tenant::provisioning::infrastructure::{
        DeploymentRegion, IsolationLevel, Placement,
    };
    use ianua_domain::domains::tenant::status::TenantStatus;

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, FakeOrgActors, Refusal};
    use crate::test_support::operator::test_operator_caller;
    use crate::test_support::organization::{FakeOrganizationStore, org_store_with, test_org};
    use crate::test_support::tenant::{FakeTenantStore, cfg, test_residency, test_tenant_in};
    use crate::test_support::{
        FakeEventDispatcher, ReadBeforeWrite, RejectingLimitEnforcer, block_on, test_auditor,
        test_ctx, test_org_caller,
    };

    struct Setup {
        uc: ProvisionTenantUseCase,
        tenants: Arc<FakeTenantStore>,
        orgs: Arc<FakeOrganizationStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn with(ports: ProvisionTenantPorts) -> Self {
            let tenants = Arc::new(FakeTenantStore::empty());
            let orgs = org_store_with([test_org(test_ctx().organization_id(), "acme")]);
            Self {
                uc: ProvisionTenantUseCase::new(
                    ComplianceLimits::default(),
                    ProvisionTenantPorts {
                        tenant_store: tenants.clone(),
                        org_store: orgs.clone(),
                        ..ports
                    },
                ),
                tenants,
                orgs,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn new() -> Self {
            Self::with(ProvisionTenantPorts::fakes())
        }

        /// Requests the new workspace with the supplied caller's authority.
        fn provision_as(
            &self,
            caller: &TenantSteward,
            req: ProvisionTenantRequest,
        ) -> Result<TenantId, AppError> {
            block_on(
                self.uc
                    .execute(caller, &test_auditor(self.audit.clone()), req),
            )
        }

        fn provision(&self, req: ProvisionTenantRequest) -> Result<TenantId, AppError> {
            self.provision_as(&TenantSteward::Member(test_org_caller()), req)
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn request(slug: &str) -> ProvisionTenantRequest {
        let c = cfg();
        ProvisionTenantRequest {
            organization_id: test_ctx().organization_id(),
            slug: TenantSlug::new(slug, &c.slug).unwrap(),
            display_name: DisplayName::new("Acme Corp", &c.display_name).unwrap(),
            contact_email: Email::new("admin@acme.com").unwrap(),
            timezone: Timezone::new("UTC").unwrap(),
            locale: Locale::new("en-US").unwrap(),
            residency: test_residency(),
        }
    }

    /// Ann, an owner of Acme, makes a tenant. It is saved still being
    /// provisioned, Acme lists it, and its making is recorded for the
    /// tenant and for Acme.
    #[test]
    fn provision_creates_tenant_and_audits() {
        let setup = Setup::new();

        let id = setup.provision(request("acme")).unwrap();

        let tenant = block_on(setup.tenants.find_by_id(&id)).unwrap().unwrap();
        let organization = setup.orgs.stored(&test_ctx().organization_id()).unwrap();
        assert_eq!(tenant.status(), TenantStatus::Provisioning);
        assert!(tenant.primary_domain().is_none());
        assert!(organization.owns_tenant(&id));
        assert_eq!(
            setup.recorded(),
            vec!["tenant.provisioned", "organization.tenant_created"]
        );
    }

    /// Bob, an operator, makes a tenant for Acme on the platform's behalf.
    #[test]
    fn the_platform_provisions_for_an_organization() {
        let setup = Setup::new();

        let id = setup
            .provision_as(
                &TenantSteward::Platform(test_operator_caller()),
                request("acme"),
            )
            .unwrap();

        assert!(block_on(setup.tenants.find_by_id(&id)).unwrap().is_some());
    }

    /// A slug already used within the organization causes a conflict.
    /// Only the existing tenant remains stored.
    #[test]
    fn provision_rejects_duplicate_slug() {
        let setup = Setup::new();
        let held = test_tenant_in(test_ctx().organization_id(), "acme", "acme.test");
        block_on(setup.tenants.save(&held)).unwrap();

        let result = setup.provision(request("acme"));

        assert!(
            matches!(&result, Err(AppError::Conflict(message)) if message == SLUG_TAKEN),
            "{result:?}"
        );
        assert_eq!(setup.tenants.count(), 1);
    }

    /// Globex already has a tenant called `production`. Ann makes Acme's
    /// own `production`: slugs are unique only within an organization, so
    /// it is made beside Globex's.
    #[test]
    fn another_organizations_slug_does_not_stand_in_the_way() {
        let setup = Setup::new();
        let globex = test_tenant_in(OrganizationId::new(), "production", "globex.test");
        block_on(setup.tenants.save(&globex)).unwrap();

        let id = setup.provision(request("production")).unwrap();

        let made = block_on(setup.tenants.find_by_id(&id)).unwrap().unwrap();
        assert_eq!(made.organization_id(), &test_ctx().organization_id());
        assert_eq!(setup.tenants.count(), 2);
    }

    /// A slug that appears free during the read but is taken at save time
    /// causes a conflict. Only the winning tenant stays and no event is recorded.
    #[test]
    fn a_slug_taken_meanwhile_is_a_conflict() {
        let live = Arc::new(FakeTenantStore::empty());
        let bobs = test_tenant_in(test_ctx().organization_id(), "production", "acme.test");
        block_on(live.save(&bobs)).unwrap();
        let racing = ReadBeforeWrite::new(FakeTenantStore::empty(), Arc::clone(&live));
        let uc = ProvisionTenantUseCase::new(
            ComplianceLimits::default(),
            ProvisionTenantPorts {
                tenant_store: Arc::new(racing),
                org_store: org_store_with([test_org(test_ctx().organization_id(), "acme")]),
                ..ProvisionTenantPorts::fakes()
            },
        );
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = block_on(uc.execute(
            &TenantSteward::Member(test_org_caller()),
            &test_auditor(audit.clone()),
            request("production"),
        ));

        assert!(
            matches!(&result, Err(AppError::Conflict(message)) if message == SLUG_TAKEN),
            "{result:?}"
        );
        assert_eq!(live.count(), 1);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Bob names an organization that does not exist. It is not found and
    /// nothing is recorded.
    #[test]
    fn provision_rejects_nonexistent_organization() {
        let setup = Setup::new();
        let elsewhere = ProvisionTenantRequest {
            organization_id: OrganizationId::new(),
            ..request("acme")
        };

        let result =
            setup.provision_as(&TenantSteward::Platform(test_operator_caller()), elsewhere);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.recorded().is_empty());
    }

    /// A member cannot provision for another organization. The organization
    /// is not found and no tenant is saved.
    #[test]
    fn a_member_cannot_provision_for_another_organization() {
        let setup = Setup::new();
        let elsewhere = ProvisionTenantRequest {
            organization_id: OrganizationId::new(),
            ..request("acme")
        };

        let result = setup.provision(elsewhere);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(setup.tenants.count(), 0);
    }

    /// Acme is on the Free plan, which holds one tenant, and already has
    /// it. Bob's second one for Acme is refused by the organization itself,
    /// whatever the limit check said, and only the first is kept.
    #[test]
    fn a_full_organization_takes_no_more_tenants() {
        let setup = Setup::new();
        let platform = || TenantSteward::Platform(test_operator_caller());
        setup.provision_as(&platform(), request("acme")).unwrap();

        let result = setup.provision_as(&platform(), request("globex"));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(setup.tenants.count(), 1);
    }

    /// A plan-limit refusal prevents provisioning. No tenant is saved and no
    /// creation event is recorded.
    #[test]
    fn provision_rejects_when_plan_limit_reached() {
        let setup = Setup::with(ProvisionTenantPorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..ProvisionTenantPorts::fakes()
        });

        let result = setup.provision(request("acme"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.tenants.count(), 0);
        assert!(setup.recorded().is_empty());
    }

    /// A member without tenant-creation rights cannot provision a tenant.
    /// No tenant is saved.
    #[test]
    fn a_member_without_the_right_is_refused() {
        let setup = Setup::with(ProvisionTenantPorts {
            org_actors: Arc::new(FakeOrgActors::in_role(OrgRole::Member)),
            ..ProvisionTenantPorts::fakes()
        });

        let result = setup.provision(request("acme"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.tenants.count(), 0);
    }

    /// A member without tenant-creation rights receives a forbidden response
    /// even for a taken slug. Only the existing tenant remains stored.
    #[test]
    fn a_member_without_the_right_learns_nothing_of_taken_slugs() {
        let setup = Setup::with(ProvisionTenantPorts {
            org_actors: Arc::new(FakeOrgActors::in_role(OrgRole::Member)),
            ..ProvisionTenantPorts::fakes()
        });
        let held = test_tenant_in(test_ctx().organization_id(), "globex", "globex.test");
        block_on(setup.tenants.save(&held)).unwrap();

        let result = setup.provision(request("globex"));

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(setup.tenants.count(), 1);
    }

    /// The organization's plan refuses dedicated-cluster residency.
    /// No tenant is saved and no creation event is recorded.
    #[test]
    fn the_plan_on_record_decides_what_a_tenant_may_be() {
        let setup = Setup::new();
        let dedicated = ProvisionTenantRequest {
            residency: TenantResidency::new(
                Placement::Platform {
                    region: DeploymentRegion::EuCentral1,
                },
                IsolationLevel::DedicatedCluster,
            )
            .unwrap(),
            ..request("acme")
        };

        let result = setup.provision(dedicated);

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(setup.tenants.count(), 0);
        assert!(setup.recorded().is_empty());
    }

    /// A signed-out member cannot provision a tenant.
    #[test]
    fn a_signed_out_member_is_refused() {
        let setup = Setup::with(ProvisionTenantPorts {
            org_actors: Arc::new(FakeOrgActors::refusing(Refusal::SignedOut)),
            ..ProvisionTenantPorts::fakes()
        });

        let result = setup.provision(request("acme"));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator denied platform authority cannot provision a tenant.
    #[test]
    fn a_disabled_operator_is_refused() {
        let setup = Setup::with(ProvisionTenantPorts {
            operator_authorities: Arc::new(FakeOperatorAuthorities::refusing(Refusal::Forbidden)),
            ..ProvisionTenantPorts::fakes()
        });

        let result = setup.provision_as(
            &TenantSteward::Platform(test_operator_caller()),
            request("acme"),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}

//! Moving an organization through its life: suspending it, lifting a
//! suspension, closing it for good.
//!
//! An owner may pause their own organization and switch it back on, or
//! close it. The platform may do all three, and only the platform lifts a
//! suspension the platform made. A suspended or closed organization's
//! sessions all end at once; a suspended one lets its owners sign in again
//! to settle what caused it.
//!
//! Closing an organization archives every tenant of it still in service or
//! still being set up, held by the platform, so nothing is served in its
//! name and the data is removed once the archive grace has passed. A tenant
//! still provisioning is archived too: its setup then finds it archived and
//! is refused the step that would activate it, and the teardown after the
//! grace removes whatever the setup made.

use std::sync::Arc;

use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::status::OrganizationStatus;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::domains::tenant::status::TenantStatus;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActedBy, OrganizationId};

use crate::acting::{OperatorAuthorities, OrgActors};
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgSessionStore, OrganizationStore};
use crate::ports::tenant::TenantStore;
use crate::use_case::Command;
use crate::use_cases::organization::sign_in::sessions::sign_out::sign_out_organization;
use crate::use_cases::organization::steward::{OrganizationSteward, StewardSources, Stewarding};

/// Which organization moves to which status.
pub struct StatusChange {
    /// The organization that moves.
    pub organization_id: OrganizationId,
    /// The status it moves to.
    pub to: OrganizationStatus,
}

/// The ports [`ChangeOrganizationStatusUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeOrganizationStatusPorts {
    /// Loads and saves the lifecycle transition on the owning account.
    pub organizations: Arc<dyn OrganizationStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
    /// Members' sessions, ended when the organization is taken out of
    /// service.
    pub org_sessions: Arc<dyn OrgSessionStore>,
    /// Tenants, archived when their organization closes.
    pub tenants: Arc<dyn TenantStore>,
}

/// Suspends, reactivates or closes an organization.
pub struct ChangeOrganizationStatusUseCase {
    ports: ChangeOrganizationStatusPorts,
}

impl ChangeOrganizationStatusUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: ChangeOrganizationStatusPorts) -> Self {
        Self { ports }
    }

    /// Ends every session of `organization` when its new status takes it
    /// out of service.
    async fn sign_out_when_out_of_service(
        &self,
        organization: &Organization,
    ) -> Result<(), AppError> {
        match organization.status() {
            OrganizationStatus::Active => Ok(()),
            OrganizationStatus::Suspended | OrganizationStatus::Closed => {
                sign_out_organization(self.ports.org_sessions.as_ref(), organization.id()).await
            }
        }
    }

    /// Archives every tenant of `organization` still in service or being set
    /// up once it is closed, held by the platform, and hands back what they
    /// raised. An organization still open archives nothing.
    async fn archived_tenants(
        &self,
        organization: &Organization,
    ) -> Result<Vec<DomainEvent>, AppError> {
        if organization.status() != OrganizationStatus::Closed {
            return Ok(Vec::new());
        }
        let store = self.ports.tenants.as_ref();
        let mut events = Vec::new();
        for id in organization.tenant_ids() {
            let Some(mut tenant) = store.find_by_id(id).await.or_internal()? else {
                continue;
            };
            if !is_left_open(&tenant) {
                continue;
            }
            tenant
                .archive(ActedBy::Platform)
                .map_err(AppError::from_domain)?;
            store.save(&tenant).await.or_internal()?;
            events.extend(tenant.take_events());
        }
        Ok(events)
    }
}

impl Command for ChangeOrganizationStatusUseCase {
    type Caller = OrganizationSteward;
    type Input = StatusChange;
    type Output = Result<(), AppError>;

    /// Moves the organization to `change.to`, saves it, ends its sessions
    /// when it leaves service, and records `organization.status_changed`.
    /// Closing it also archives every tenant still in service or still
    /// provisioning, held by the platform, and records
    /// `tenant.status_changed` for each; suspending leaves its tenants' own
    /// status as it is.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the member may not suspend or close the
    ///   organization, lifts a suspension the platform made, or the
    ///   operator may not act now.
    /// - `AppError::NotFound` when there is no such organization, or a
    ///   member names another than their own.
    /// - `AppError::Domain` when the organization is already in that status
    ///   or is closed.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        steward: &OrganizationSteward,
        auditor: &RequestAuditor,
        change: StatusChange,
    ) -> Result<(), AppError> {
        let sources = StewardSources {
            org_actors: self.ports.org_actors.as_ref(),
            operators: self.ports.operator_authorities.as_ref(),
            organizations: self.ports.organizations.as_ref(),
        };
        let mut stewarding = Stewarding::resolve(sources, steward, &change.organization_id).await?;
        stewarding
            .change_organization(|organization, by| organization.change_status(change.to, by))?;
        let organization = stewarding.organization();
        self.ports
            .organizations
            .save(organization)
            .await
            .or_internal()?;
        self.sign_out_when_out_of_service(organization).await?;
        let archived = self.archived_tenants(organization).await?;
        let mut events = stewarding.organization_raised();
        events.extend(archived);
        auditor
            .dispatch_by(&stewarding.audit_actor(), events)
            .await
            .or_internal()
    }
}

/// Whether `tenant` still serves anything or is being set up, so closing its
/// organization archives it. One archived or deleted is left as it is.
fn is_left_open(tenant: &Tenant) -> bool {
    matches!(
        tenant.status(),
        TenantStatus::Provisioning | TenantStatus::Active | TenantStatus::Suspended
    )
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::tenant::status::PlatformHold;
    use ianua_domain::types::{ActedBy, OperatorId};

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, FakeOrgActors, Refusal};
    use crate::test_support::notifications::operator_caller;
    use crate::test_support::organization::{FakeOrganizationStore, org_store_with, test_org};
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_in};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: ChangeOrganizationStatusUseCase,
        orgs: Arc<FakeOrganizationStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn with(ports: ChangeOrganizationStatusPorts, orgs: Arc<FakeOrganizationStore>) -> Self {
            Self {
                uc: ChangeOrganizationStatusUseCase::new(ChangeOrganizationStatusPorts {
                    organizations: orgs.clone(),
                    ..ports
                }),
                orgs,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn members_as(actors: FakeOrgActors) -> Self {
            let ports = ChangeOrganizationStatusPorts {
                org_actors: Arc::new(actors),
                ..ChangeOrganizationStatusPorts::fakes()
            };
            Self::with(ports, Arc::new(FakeOrganizationStore::empty()))
        }

        fn platform_over(organization: Organization) -> Self {
            Self::with(
                ChangeOrganizationStatusPorts::fakes(),
                org_store_with([organization]),
            )
        }

        fn change(
            &self,
            steward: &OrganizationSteward,
            organization_id: OrganizationId,
            to: OrganizationStatus,
        ) -> Result<(), AppError> {
            block_on(self.uc.execute(
                steward,
                &test_auditor(self.audit.clone()),
                StatusChange {
                    organization_id,
                    to,
                },
            ))
        }

        fn as_owner(&self, to: OrganizationStatus) -> Result<(), AppError> {
            let caller = test_org_caller();
            let id = caller.organization_id();
            self.change(&OrganizationSteward::Member(caller), id, to)
        }

        fn as_platform(&self, id: OrganizationId, to: OrganizationStatus) -> Result<(), AppError> {
            let steward = OrganizationSteward::Platform(operator_caller(OperatorId::new()));
            self.change(&steward, id, to)
        }

        fn status_of(&self, id: &OrganizationId) -> Option<OrganizationStatus> {
            self.orgs
                .stored(id)
                .map(|organization| organization.status())
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn acme_in(status: OrganizationStatus) -> Organization {
        let mut acme = test_org(OrganizationId::new(), "acme");
        if status != OrganizationStatus::Active {
            acme.change_status(status, ActedBy::Platform).unwrap();
        }
        acme
    }

    /// Olivia, Acme's owner, suspends Acme. It is saved suspended, every
    /// session ends at once, and the change is recorded.
    #[test]
    fn an_owner_suspends_their_organization() {
        let setup = Setup::members_as(FakeOrgActors::in_role(OrgRole::Owner));

        setup.as_owner(OrganizationStatus::Suspended).unwrap();

        let id = test_org_caller().organization_id();
        assert_eq!(setup.status_of(&id), Some(OrganizationStatus::Suspended));
        assert_eq!(setup.recorded(), vec!["organization.status_changed"]);
    }

    /// Olivia closes Acme for good. It is saved closed and every session
    /// ends.
    #[test]
    fn an_owner_closes_their_organization() {
        let setup = Setup::members_as(FakeOrgActors::in_role(OrgRole::Owner));

        setup.as_owner(OrganizationStatus::Closed).unwrap();

        let id = test_org_caller().organization_id();
        assert_eq!(setup.status_of(&id), Some(OrganizationStatus::Closed));
        assert!(
            setup
                .recorded()
                .contains(&"organization.status_changed".to_owned())
        );
    }

    /// A plain member cannot suspend the organization, and no status change
    /// is recorded.
    #[test]
    fn a_plain_member_is_refused() {
        let setup = Setup::members_as(FakeOrgActors::in_role(OrgRole::Member));

        let result = setup.as_owner(OrganizationStatus::Suspended);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.recorded().is_empty());
    }

    /// An owner's key without the suspend right cannot suspend the organization.
    #[test]
    fn a_key_without_the_suspend_right_is_refused() {
        let setup = Setup::members_as(FakeOrgActors::through_key(OrgRole::Owner, Vec::new()));

        let result = setup.as_owner(OrganizationStatus::Suspended);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller must authenticate before closing an organization.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::members_as(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = setup.as_owner(OrganizationStatus::Closed);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents closing the organization.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let setup = Setup::members_as(FakeOrgActors::refusing(Refusal::Forbidden));

        let result = setup.as_owner(OrganizationStatus::Closed);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An owner's attempt to close another organization returns not found.
    #[test]
    fn an_owner_naming_another_organization_finds_none() {
        let setup = Setup::members_as(FakeOrgActors::in_role(OrgRole::Owner));
        let steward = OrganizationSteward::Member(test_org_caller());

        let result = setup.change(&steward, OrganizationId::new(), OrganizationStatus::Closed);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Bob, an operator, suspends Acme over an unpaid bill. It is saved
    /// suspended and the change recorded.
    #[test]
    fn the_platform_suspends_an_organization() {
        let acme = acme_in(OrganizationStatus::Active);
        let id = *acme.id();
        let setup = Setup::platform_over(acme);

        setup
            .as_platform(id, OrganizationStatus::Suspended)
            .unwrap();

        assert_eq!(setup.status_of(&id), Some(OrganizationStatus::Suspended));
        assert_eq!(setup.recorded(), vec!["organization.status_changed"]);
    }

    /// Bob lifts the suspension the platform made. Acme is active again.
    #[test]
    fn the_platform_reactivates_a_suspended_organization() {
        let acme = acme_in(OrganizationStatus::Suspended);
        let id = *acme.id();
        let setup = Setup::platform_over(acme);

        setup.as_platform(id, OrganizationStatus::Active).unwrap();

        assert_eq!(setup.status_of(&id), Some(OrganizationStatus::Active));
    }

    /// Reactivating an active organization is refused without a status-change
    /// record.
    #[test]
    fn reactivating_an_active_organization_is_refused() {
        let acme = acme_in(OrganizationStatus::Active);
        let id = *acme.id();
        let setup = Setup::platform_over(acme);

        let result = setup.as_platform(id, OrganizationStatus::Active);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(setup.recorded().is_empty());
    }

    /// Even an operator cannot reactivate a closed organization; it stays closed.
    #[test]
    fn a_closed_organization_cannot_be_reactivated() {
        let acme = acme_in(OrganizationStatus::Closed);
        let id = *acme.id();
        let setup = Setup::platform_over(acme);

        let result = setup.as_platform(id, OrganizationStatus::Active);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(setup.status_of(&id), Some(OrganizationStatus::Closed));
    }

    /// Closing an already closed organization is refused for an operator too.
    #[test]
    fn closing_twice_is_refused() {
        let acme = acme_in(OrganizationStatus::Closed);
        let id = *acme.id();
        let setup = Setup::platform_over(acme);

        let result = setup.as_platform(id, OrganizationStatus::Closed);

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Bob names an organization that does not exist. It is not found and
    /// nothing is recorded.
    #[test]
    fn an_unknown_organization_is_not_found() {
        let setup = Setup::platform_over(acme_in(OrganizationStatus::Active));

        let result = setup.as_platform(OrganizationId::new(), OrganizationStatus::Suspended);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.recorded().is_empty());
    }

    /// Refused operator authority prevents suspension and leaves Acme active.
    #[test]
    fn an_operator_turned_away_is_refused() {
        let acme = acme_in(OrganizationStatus::Active);
        let id = *acme.id();
        let ports = ChangeOrganizationStatusPorts {
            operator_authorities: Arc::new(FakeOperatorAuthorities::refusing(Refusal::Forbidden)),
            ..ChangeOrganizationStatusPorts::fakes()
        };
        let setup = Setup::with(ports, org_store_with([acme]));

        let result = setup.as_platform(id, OrganizationStatus::Suspended);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.status_of(&id), Some(OrganizationStatus::Active));
    }

    /// Bob, an operator, closes Acme, whose production tenant is live. The
    /// tenant is archived and held by the platform, so nothing is served in
    /// Acme's name any more, and both changes are recorded.
    #[test]
    fn closing_archives_the_tenants_in_service() {
        let mut acme = test_org(OrganizationId::new(), "acme");
        let id = *acme.id();
        let mut production = test_tenant_in(id, "production", "acme.test");
        production.activate(ActedBy::Platform).unwrap();
        let _activated = production.take_events();
        acme.add_tenant(&production, ActedBy::Platform).unwrap();
        let _added = acme.take_events();
        let tenants = Arc::new(FakeTenantStore::holding(production));
        let ports = ChangeOrganizationStatusPorts {
            tenants: tenants.clone(),
            ..ChangeOrganizationStatusPorts::fakes()
        };
        let setup = Setup::with(ports, org_store_with([acme]));

        setup.as_platform(id, OrganizationStatus::Closed).unwrap();

        let archived = tenants.tenants.lock().unwrap()[0].status();
        assert_eq!(archived, TenantStatus::Archived);
        assert_eq!(
            setup.recorded(),
            vec!["organization.status_changed", "tenant.status_changed"]
        );
    }

    /// Closing Acme while its staging tenant is provisioning archives that
    /// tenant and places it under a platform hold.
    #[test]
    fn closing_archives_a_tenant_still_provisioning() {
        let mut acme = test_org(OrganizationId::new(), "acme");
        let id = *acme.id();
        let staging = test_tenant_in(id, "staging", "acme.test");
        acme.add_tenant(&staging, ActedBy::Platform).unwrap();
        let _added = acme.take_events();
        let tenants = Arc::new(FakeTenantStore::holding(staging));
        let ports = ChangeOrganizationStatusPorts {
            tenants: tenants.clone(),
            ..ChangeOrganizationStatusPorts::fakes()
        };
        let setup = Setup::with(ports, org_store_with([acme]));

        setup.as_platform(id, OrganizationStatus::Closed).unwrap();

        let stored = tenants.tenants.lock().unwrap()[0].clone();
        assert_eq!(stored.status(), TenantStatus::Archived);
        assert_eq!(stored.hold(), PlatformHold::Held);
    }

    /// Olivia suspends Acme for a week. Its live tenant keeps its own
    /// status, ready for when Acme is back.
    #[test]
    fn suspending_leaves_the_tenants_as_they_are() {
        let mut acme = test_org(OrganizationId::new(), "acme");
        let id = *acme.id();
        let mut production = test_tenant_in(id, "production", "acme.test");
        production.activate(ActedBy::Platform).unwrap();
        acme.add_tenant(&production, ActedBy::Platform).unwrap();
        let tenants = Arc::new(FakeTenantStore::holding(production));
        let ports = ChangeOrganizationStatusPorts {
            tenants: tenants.clone(),
            ..ChangeOrganizationStatusPorts::fakes()
        };
        let setup = Setup::with(ports, org_store_with([acme]));

        setup
            .as_platform(id, OrganizationStatus::Suspended)
            .unwrap();

        let kept = tenants.tenants.lock().unwrap()[0].status();
        assert_eq!(kept, TenantStatus::Active);
    }
}

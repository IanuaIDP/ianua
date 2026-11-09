//! Remove domain: delete one of the tenant's registered domains, and the
//! zone of a delegated one.

use std::sync::Arc;

use ianua_domain::domains::tenant::control::{TenantArea, TenantControl};
use ianua_domain::domains::tenant::custom_domains::registered_domain::{
    DomainConnection, RegisteredDomain,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::DomainId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::domain::{DnsZoneWriter, RegisteredDomainStore};
use crate::ports::tenant::TenantStore;
use crate::services::lookup::existing_tenant;
use crate::use_case::Command;
use crate::use_cases::domain::lookup::{existing_domain, scope_of};
use crate::use_cases::domain::primary::released_primary;

/// The ports [`RemoveDomainUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RemoveDomainPorts {
    /// Loads and deletes the registration.
    pub domain_store: Arc<dyn RegisteredDomainStore>,
    /// Closes the zone of a delegated domain.
    pub dns_zones: Arc<dyn DnsZoneWriter>,
    /// Loads the tenant the domain is removed from, and saves it once it
    /// lets go of the domain as its primary one.
    pub tenants: Arc<dyn TenantStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Removes a domain registration from the caller's tenant.
pub struct RemoveDomainUseCase {
    ports: RemoveDomainPorts,
}

impl RemoveDomainUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RemoveDomainPorts) -> Self {
        Self { ports }
    }
}

impl Command for RemoveDomainUseCase {
    type Caller = CallerContext;
    type Input = DomainId;
    type Output = Result<(), AppError>;

    /// Removes the registration, and its zone if it held one, and records
    /// `tenant.domain_removed`. When it was the tenant's primary domain, the
    /// tenant lets go of it and `tenant.primary_domain_changed` is recorded
    /// too, so no tenant goes on routing a name it no longer holds.
    ///
    /// The zone goes first. Deleting the registration while still answering
    /// for the name would leave us authoritative for a hostname nothing in
    /// the control plane remembers. Closing the zone first means the worst
    /// case is a registration for a name we no longer answer, which is what
    /// the tenant asked for anyway.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not delete the tenant's
    ///   domains.
    /// - `AppError::NotFound` if the tenant has no such domain.
    /// - `AppError::Internal` if the zone cannot be closed, or on persistence
    ///   or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        domain_id: DomainId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        TenantControl::new(&authority)
            .ensure_may(&caller.tenant_id(), TenantArea::DomainRemoval)
            .map_err(AppError::from_domain)?;
        let mut tenant = existing_tenant(self.ports.tenants.as_ref(), &caller.tenant_id()).await?;
        let mut domain = existing_domain(
            self.ports.domain_store.as_ref(),
            &caller.tenant(),
            &domain_id,
        )
        .await?;
        domain
            .remove(&scope_of(&tenant), TenantControl::new(&authority))
            .map_err(AppError::from_domain)?;

        remove(&self.ports, caller, &domain).await?;
        let released =
            released_primary(self.ports.tenants.as_ref(), &mut tenant, domain.domain()).await?;
        let events = domain
            .take_events(&caller.tenant())
            .into_iter()
            .chain(released)
            .collect();
        auditor
            .dispatch_by(&caller.actor(), events)
            .await
            .or_internal()
    }
}

/// Closes the zone `domain` holds, if it holds one, then deletes the
/// registration.
///
/// # Errors
///
/// - `AppError::NotFound` when the registration was deleted meanwhile.
/// - `AppError::Internal` if the zone cannot be closed, or on persistence
///   failure.
async fn remove(
    ports: &RemoveDomainPorts,
    caller: &CallerContext,
    domain: &RegisteredDomain<ResolvedTenant>,
) -> Result<(), AppError> {
    close_zone(ports, caller, domain).await?;
    let deleted = ports
        .domain_store
        .delete(&caller.tenant(), domain.id())
        .await
        .or_internal()?;
    if !deleted {
        return Err(AppError::NotFound(message!(
            "domain-domain-not-found",
            "domain not found"
        )));
    }
    Ok(())
}

/// Closes the zone `domain` holds, if it holds one.
///
/// A wildcard holds no zone of its own, it lives inside its parent's. So
/// removing one leaves that zone alone; deleting it would take the parent
/// hostname down with every record the tenant put in it.
async fn close_zone(
    ports: &RemoveDomainPorts,
    caller: &CallerContext,
    domain: &RegisteredDomain<ResolvedTenant>,
) -> Result<(), AppError> {
    let holds_a_zone =
        domain.connection() == DomainConnection::Delegated && !domain.domain().is_wildcard();
    if !holds_a_zone {
        return Ok(());
    }
    ports
        .dns_zones
        .delete_zone(&caller.tenant_id(), domain.domain())
        .await
        .or_internal()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{DomainAction, SystemPermission};
    use ianua_domain::domains::tenant::custom_domains::dns_zone::DelegationLabel;
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::types::DomainName;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::domain::{DomainSeed, FakeDnsZoneWriter, FakeDomainStore};
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx, test_tenant_with_id};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        use_case: RemoveDomainUseCase,
        domains: Arc<FakeDomainStore>,
        zones: Arc<FakeDnsZoneWriter>,
        tenants: Arc<FakeTenantStore>,
        audit: Arc<FakeEventDispatcher>,
        id: DomainId,
    }

    fn fixture_with(
        domain: RegisteredDomain<ResolvedTenant>,
        authorities: FakeTenantAuthorities,
    ) -> Fixture {
        fixture_in(test_tenant_for_ctx(), domain, authorities)
    }

    fn fixture_in(
        tenant: Tenant,
        domain: RegisteredDomain<ResolvedTenant>,
        authorities: FakeTenantAuthorities,
    ) -> Fixture {
        let id = *domain.id();
        let name = domain.domain().clone();
        let domains = Arc::new(FakeDomainStore::holding(test_ctx().tenant_id(), [domain]));
        let zones = Arc::new(FakeDnsZoneWriter::with_nameservers(vec![
            DomainName::new("ns1.ianua.test").unwrap(),
        ]));
        block_on(zones.create_zone(
            &test_ctx().tenant_id(),
            &name,
            &DelegationLabel::for_registration(&id),
        ))
        .unwrap();
        let tenants = Arc::new(FakeTenantStore::holding(tenant));
        let use_case = RemoveDomainUseCase::new(RemoveDomainPorts {
            domain_store: domains.clone(),
            dns_zones: zones.clone(),
            tenants: tenants.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        Fixture {
            use_case,
            domains,
            zones,
            tenants,
            audit: Arc::new(FakeEventDispatcher::new()),
            id,
        }
    }

    fn fixture(domain: RegisteredDomain<ResolvedTenant>) -> Fixture {
        fixture_with(domain, FakeTenantAuthorities::holding_everything())
    }

    fn remove(f: &Fixture, id: DomainId) -> Result<(), AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), id),
        )
    }

    /// Ann removes `acme.test` from Acme. It is gone and the removal is
    /// recorded.
    #[test]
    fn a_removed_domain_is_deleted_and_recorded() {
        let f = fixture(DomainSeed::verified("acme.test").build());

        remove(&f, f.id).unwrap();

        assert_eq!(f.domains.count(), 0);
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            vec!["tenant.domain_removed"]
        );
    }

    /// Ann removes `acme.test`, Acme's primary domain. Acme lets go of it
    /// as its primary domain, so it no longer routes a name it does not
    /// hold, and both changes are recorded.
    #[test]
    fn removing_the_primary_domain_lets_the_tenant_go_of_it() {
        let ctx = test_ctx();
        let acme = test_tenant_with_id(ctx.tenant_id(), ctx.organization_id(), "acme", "acme.test");
        let f = fixture_in(
            acme,
            DomainSeed::verified("acme.test").build(),
            FakeTenantAuthorities::holding_everything(),
        );

        remove(&f, f.id).unwrap();

        let tenant = block_on(f.tenants.find_by_id(&ctx.tenant_id()))
            .unwrap()
            .unwrap();
        assert!(tenant.primary_domain().is_none());
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            vec!["tenant.domain_removed", "tenant.primary_domain_changed"]
        );
    }

    /// Ann names a domain Acme does not have. It is not found.
    #[test]
    fn an_unknown_domain_is_not_found() {
        let f = fixture(DomainSeed::verified("acme.test").build());

        let result = remove(&f, DomainId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann removes Acme's delegated domain. Its zone is closed, so we no
    /// longer answer for a hostname no registration remembers.
    #[test]
    fn removing_a_delegated_domain_closes_its_zone() {
        let f = fixture(DomainSeed::verified("auth.acme.test").delegated().build());

        remove(&f, f.id).unwrap();

        assert!(f.zones.opened().is_empty());
    }

    /// Ann removes a domain Acme runs at its own DNS provider. No zone is
    /// touched, and the removal does not depend on one existing.
    #[test]
    fn removing_a_self_managed_domain_touches_no_zone() {
        let f = fixture(DomainSeed::verified("acme.test").build());

        remove(&f, f.id).unwrap();

        assert_eq!(f.zones.opened().len(), 1);
    }

    /// Domain updates do not authorize deletion; the forbidden removal
    /// leaves the registration intact and records no event.
    #[test]
    fn a_caller_who_may_not_delete_domains_is_refused() {
        let f = fixture_with(
            DomainSeed::verified("login.acme.test").build(),
            FakeTenantAuthorities::holding(&[
                SystemPermission::Domains(DomainAction::View),
                SystemPermission::Domains(DomainAction::Update),
            ]),
        );

        let result = remove(&f, f.id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.domains.count(), 1);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot remove the domain, which remains registered.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture_with(
            DomainSeed::verified("acme.test").build(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = remove(&f, f.id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(f.domains.count(), 1);
    }
}

//! Revoking the authority a principal handed out, when the principal loses its
//! own standing.
//!
//! A delegation is authority a person lent an agent. When the person is
//! locked, deactivated or deleted, that loan must end too. Otherwise their
//! agents keep acting, and keep minting tokens, in the name of someone who can
//! no longer act at all. Every path that takes a person's standing away runs
//! this first.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::delegation::Revoker;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, OrgUserId, OrganizationId, PrincipalRef};

use crate::listing::{Limit, Page, PageRequest, SortOrder};
use crate::ports::agents::DelegationStore;
use crate::ports::tenant::{TenantSortField, TenantStore};
use crate::tenancy::ScopedTenant;

/// How many tenants are read per page while revoking.
const TENANT_PAGE: u32 = 100;

/// Revokes every delegation a principal granted, and everything derived from
/// each: the children passed on from it and the tokens exchanged for it.
#[derive(Clone)]
pub struct GrantRevocation {
    delegation_store: Arc<dyn DelegationStore>,
}

impl GrantRevocation {
    /// Creates the service over the delegation store.
    #[must_use]
    pub fn new(delegation_store: Arc<dyn DelegationStore>) -> Self {
        Self { delegation_store }
    }

    /// Revokes everything `delegator` granted in `tenant`, returning the
    /// audit events for the grants it revoked, attributed to `actor`.
    ///
    /// Each grant goes in one statement with its whole subtree. A grant
    /// already revoked is skipped, so running this again after a partial
    /// failure finishes the job rather than repeating it.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Infrastructure`] when the grants cannot be read
    /// or a revocation cannot be written. Callers treat this as a failure of
    /// the whole operation: a person must not lose standing while their
    /// agents keep theirs.
    pub async fn revoke_all_granted_by(
        &self,
        tenant: &ScopedTenant,
        delegator: &PrincipalRef,
        actor: &ActorRef,
    ) -> Result<Vec<DomainEvent>, DomainError> {
        let grants = self
            .delegation_store
            .find_by_delegator(tenant, delegator)
            .await?;

        let mut events = Vec::new();
        for mut grant in grants.into_iter().filter(|grant| !grant.is_revoked()) {
            grant.revoke(Revoker::Platform)?;
            self.delegation_store
                .revoke_subtree(tenant, grant.id())
                .await?;
            let revoked = grant.take_events(tenant).into_iter();
            events.extend(revoked.map(|event| event.with_actor(actor.clone())));
        }

        Ok(events)
    }
}

/// Revokes what an org user granted in every tenant of their organization.
///
/// An org user acts across the organization's tenants, so losing their
/// standing has to end their loans in each of them, not only in one.
#[derive(Clone)]
pub struct OrgGrantRevocation {
    tenants: Arc<dyn TenantStore>,
    grants: GrantRevocation,
}

impl OrgGrantRevocation {
    /// Creates the service over the tenant store and the per-tenant
    /// revocation.
    #[must_use]
    pub fn new(tenants: Arc<dyn TenantStore>, grants: GrantRevocation) -> Self {
        Self { tenants, grants }
    }

    /// Revokes everything `org_user` granted, in every tenant of
    /// `organization_id`, returning the audit events for what it revoked.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Infrastructure`] when the tenants or grants
    /// cannot be read or a revocation cannot be written. Callers treat this
    /// as a failure of the whole operation.
    pub async fn revoke_all_granted_by(
        &self,
        organization_id: &OrganizationId,
        org_user: &OrgUserId,
        actor: &ActorRef,
    ) -> Result<Vec<DomainEvent>, DomainError> {
        let delegator = PrincipalRef::OrgUser(*org_user);
        let mut events = Vec::new();
        let mut next = Some(PageRequest::first(Limit::internal(TENANT_PAGE)));
        while let Some(asked) = next.take() {
            let tenants = self.tenant_page(organization_id, &asked).await?;
            next = asked.following(&tenants);
            for tenant in &tenants.items {
                let scoped = ScopedTenant::from_registry(tenant);
                let revoked = self
                    .grants
                    .revoke_all_granted_by(&scoped, &delegator, actor)
                    .await?;
                events.extend(revoked);
            }
        }
        Ok(events)
    }

    /// The page `page` asks for of the organization's tenants.
    async fn tenant_page(
        &self,
        organization_id: &OrganizationId,
        page: &PageRequest,
    ) -> Result<Page<Tenant>, DomainError> {
        self.tenants
            .list_by_organization(
                organization_id,
                None,
                &SortOrder::<TenantSortField>::default(),
                page,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::{
        CapabilitySet, DelegationConstraints,
    };
    use ianua_domain::domains::agents::authority::delegation::{
        Delegation, DelegationRenewal, DelegationRow, DelegationStatus, Lineage,
    };
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::types::event_type::{AgentsEvent, EventType};
    use ianua_domain::types::{AgentId, DelegationId, Fact, Label, Seconds, UserId};

    use super::*;
    use crate::test_support::agents::FakeDelegationStore;
    use crate::test_support::tenant::{FakeTenantStore, test_tenant, test_tenant_in};
    use crate::test_support::{Fake, block_on, reference_label};

    const LIFETIME: Seconds = Seconds::new(600);

    fn grant_by(delegator: PrincipalRef, name: Option<&str>) -> Delegation<ResolvedTenant> {
        let now = clock::now();
        Delegation::reconstitute(DelegationRow {
            id: DelegationId::new(),
            delegator,
            delegate: AgentId::new(),
            granted: CapabilitySet::new(
                vec![SystemPermission::Routing(RoutingAction::View)],
                vec![],
            ),
            constraints: DelegationConstraints::new(LIFETIME, 2).unwrap(),
            lineage: Lineage::Root,
            depth: 0,
            status: DelegationStatus::Active,
            issued_at: now,
            expires_at: now + LIFETIME.duration(),
            renewed: DelegationRenewal::NotRenewed,
            updated_at: now,
            name: name.map(|name| Label::new("name", name).unwrap()),
        })
        .unwrap()
    }

    fn store_holding(
        tenant: &ScopedTenant,
        grants: &[Delegation<ResolvedTenant>],
    ) -> Arc<FakeDelegationStore> {
        let store = Arc::new(FakeDelegationStore::empty());
        for grant in grants {
            block_on(store.save(tenant, grant)).unwrap();
        }
        store
    }

    fn scoped(tenant: &Tenant) -> ScopedTenant {
        ScopedTenant::from_registry(tenant)
    }

    fn revoked_count(store: &FakeDelegationStore) -> usize {
        store
            .all()
            .iter()
            .filter(|grant| grant.is_revoked())
            .count()
    }

    /// Ann lent two agents part of her authority and is deactivated. Both
    /// loans end, and each is recorded as revoked by the admin who
    /// deactivated her.
    #[test]
    fn every_grant_the_person_made_is_revoked() {
        let tenant = scoped(&test_tenant("acme", "acme.com"));
        let ann = PrincipalRef::User(UserId::new());
        let admin = UserId::new();
        let store = store_holding(&tenant, &[grant_by(ann, None), grant_by(ann, None)]);

        let events = block_on(GrantRevocation::new(store.clone()).revoke_all_granted_by(
            &tenant,
            &ann,
            &ActorRef::User(admin),
        ))
        .unwrap();

        assert_eq!(revoked_count(&store), 2);
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| {
            event.event_type() == EventType::from(AgentsEvent::DelegationRevoked)
                && event.tenant_id() == Some(&*tenant)
                && matches!(event.performed_by(), Fact::Known(ActorRef::User(id)) if *id == admin)
        }));
    }

    /// Ann's loan is titled "Quarterly report". Its record names it so, and
    /// one with no title is named by its id.
    #[test]
    fn a_revoked_grant_is_recorded_under_its_title_or_its_id() {
        let tenant = scoped(&test_tenant("acme", "acme.com"));
        let ann = PrincipalRef::User(UserId::new());
        let titled = grant_by(ann, Some("Quarterly report"));
        let untitled = grant_by(ann, None);
        let untitled_id = untitled.id().to_string();
        let store = store_holding(&tenant, &[titled, untitled]);

        let events = block_on(GrantRevocation::new(store).revoke_all_granted_by(
            &tenant,
            &ann,
            &ActorRef::System,
        ))
        .unwrap();

        let labels: Vec<String> = events
            .iter()
            .filter_map(|event| reference_label(&event.payload(), "delegation").map(str::to_owned))
            .collect();
        assert!(labels.contains(&"Quarterly report".to_owned()));
        assert!(labels.contains(&untitled_id));
    }

    /// Ann is deactivated. Bob's loan to his own agent stays as it was.
    #[test]
    fn grants_someone_else_made_are_left_alone() {
        let tenant = scoped(&test_tenant("acme", "acme.com"));
        let ann = PrincipalRef::User(UserId::new());
        let bob = PrincipalRef::User(UserId::new());
        let store = store_holding(&tenant, &[grant_by(bob, None)]);

        let events = block_on(GrantRevocation::new(store.clone()).revoke_all_granted_by(
            &tenant,
            &ann,
            &ActorRef::System,
        ))
        .unwrap();

        assert!(events.is_empty());
        assert_eq!(revoked_count(&store), 0);
    }

    /// Ann's deactivation is run a second time after a partial failure. The
    /// loans the first run ended are not recorded as revoked again.
    #[test]
    fn running_again_records_nothing_already_revoked() {
        let tenant = scoped(&test_tenant("acme", "acme.com"));
        let ann = PrincipalRef::User(UserId::new());
        let store = store_holding(&tenant, &[grant_by(ann, None)]);
        let revocation = GrantRevocation::new(store);
        block_on(revocation.revoke_all_granted_by(&tenant, &ann, &ActorRef::System)).unwrap();

        let again =
            block_on(revocation.revoke_all_granted_by(&tenant, &ann, &ActorRef::System)).unwrap();

        assert!(again.is_empty());
    }

    /// Failure to save a delegation revocation is returned as an infrastructure error.
    #[test]
    fn a_revocation_that_cannot_be_written_fails_the_whole_operation() {
        let tenant = scoped(&test_tenant("acme", "acme.com"));
        let ann = PrincipalRef::User(UserId::new());
        let store = store_holding(&tenant, &[grant_by(ann, None)]);
        store.fail_revocations();

        let result = block_on(GrantRevocation::new(store).revoke_all_granted_by(
            &tenant,
            &ann,
            &ActorRef::System,
        ));

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// Ada, an Acme org member, lent agents authority in Acme's staging and
    /// production tenants. Losing her standing ends both loans, and leaves
    /// a tenant of another organization untouched.
    #[test]
    fn an_org_user_loses_their_grants_in_every_tenant_of_the_organization() {
        let acme = OrganizationId::new();
        let staging = test_tenant_in(acme, "staging", "staging.acme.com");
        let production = test_tenant_in(acme, "production", "acme.com");
        let globex = test_tenant("globex", "globex.com");
        let ada = OrgUserId::new();
        let store = Arc::new(FakeDelegationStore::empty());
        for tenant in [&staging, &production, &globex] {
            block_on(store.save(&scoped(tenant), &grant_by(PrincipalRef::OrgUser(ada), None)))
                .unwrap();
        }
        let revocation = OrgGrantRevocation::new(
            Arc::new(FakeTenantStore::holding_all([staging, production, globex])),
            GrantRevocation::new(store.clone()),
        );

        let events =
            block_on(revocation.revoke_all_granted_by(&acme, &ada, &ActorRef::System)).unwrap();

        assert_eq!(events.len(), 2);
        assert_eq!(revoked_count(&store), 2);
    }

    /// Ada belongs to an organization with no tenants yet. Losing her
    /// standing revokes nothing and records nothing.
    #[test]
    fn an_organization_without_tenants_has_nothing_to_revoke() {
        let revocation = OrgGrantRevocation::new(Fake::fake(), Fake::fake());

        let events = block_on(revocation.revoke_all_granted_by(
            &OrganizationId::new(),
            &OrgUserId::new(),
            &ActorRef::System,
        ))
        .unwrap();

        assert!(events.is_empty());
    }
}

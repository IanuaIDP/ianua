//! Accept domain handover: an admin of the receiving tenant accepts a
//! domain a sibling tenant offered it, and the domain moves.

use std::sync::Arc;

use ianua_domain::domains::tenant::control::{TenantArea, TenantControl};
use ianua_domain::domains::tenant::custom_domains::handover_offer::HandoverOffer;
use ianua_domain::domains::tenant::custom_domains::registered_domain::RegisteredDomain;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{DomainName, TenantId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::domain::{DnsZoneWriter, HandoverOfferStore, RegisteredDomainStore};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::runtime::UnitOfWork;
use crate::ports::tenant::TenantStore;
use crate::services::kept_together::kept_together;
use crate::services::lookup::existing_tenant;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::domain::limits::ensure_within_limit;

/// The ports [`AcceptDomainUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AcceptDomainPorts {
    /// Moves the registration between the tenants.
    pub domain_store: Arc<dyn RegisteredDomainStore>,
    /// Loads both tenants, to check the handover between them again.
    pub tenants: Arc<dyn TenantStore>,
    /// Finds the offer, and keeps it spent once accepted.
    pub offers: Arc<dyn HandoverOfferStore>,
    /// Moves the zone of a delegated domain with it.
    pub dns_zones: Arc<dyn DnsZoneWriter>,
    /// Keeps the move and the record of it together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// The plan's ceiling on the receiving tenant's domains.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
}

/// Which offer the caller's tenant accepts.
pub struct AcceptDomainRequest {
    /// The tenant that offered the domain.
    pub source_tenant_id: TenantId,
    /// The domain it offered.
    pub domain: DomainName,
}

/// Accepts a domain a sibling tenant offered the caller's tenant.
pub struct AcceptDomainUseCase {
    ports: AcceptDomainPorts,
}

impl AcceptDomainUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AcceptDomainPorts) -> Self {
        Self { ports }
    }
}

impl Command for AcceptDomainUseCase {
    type Caller = CallerContext;
    type Input = AcceptDomainRequest;
    type Output = Result<(), AppError>;

    /// Spends the offer and moves the domain to the caller's tenant,
    /// keeping its verification and certificate, and records
    /// `tenant.domain_transferred`.
    ///
    /// Everything the offer needed is checked again, since either tenant
    /// may have changed since. The zone of a delegated domain moves with it.
    /// The tenant's `NS` record points at us, not at whichever of our
    /// tenants holds the zone, so the name keeps answering across the move.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without domain-change rights, for another tenant's offer or a full plan.
    /// - `AppError::NotFound` for a missing tenant, offer or domain; `Domain` for a closed tenant.
    /// - `AppError::Conflict` for an accepted/expired offer, different organizations, a primary domain or a concurrent move/removal.
    /// - `AppError::Internal` on zone transfer, persistence or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: AcceptDomainRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        TenantControl::new(&authority)
            .ensure_may(&caller.tenant_id(), TenantArea::Domains)
            .map_err(AppError::from_domain)?;
        let tenants = self.ports.tenants.as_ref();
        let target = existing_tenant(tenants, &caller.tenant_id()).await?;
        let source = existing_tenant(tenants, &request.source_tenant_id).await?;
        let mut offer = existing_offer(self.ports.offers.as_ref(), &request).await?;
        let domain = offered_domain(self.ports.domain_store.as_ref(), &source, &offer).await?;
        offer
            .accept(&source, &target, TenantControl::new(&authority))
            .map_err(AppError::from_domain)?;
        ensure_within_limit(
            self.ports.limit_enforcer.as_ref(),
            caller,
            ResourceKind::Domains,
        )
        .await?;

        let handover = Handover {
            source: &source,
            target: &target,
            domain: &domain,
        };
        kept_together(
            self.ports.unit_of_work.as_ref(),
            accept_and_record(&self.ports, auditor, handover, &mut offer),
        )
        .await
    }
}

/// A domain leaving one tenant for another.
#[derive(Clone, Copy)]
struct Handover<'a> {
    /// The tenant it leaves.
    source: &'a Tenant,
    /// The tenant it joins.
    target: &'a Tenant,
    /// The registration.
    domain: &'a RegisteredDomain<ResolvedTenant>,
}

/// The offer `request` names.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant made no such offer.
/// - `AppError::Internal` on storage failure.
async fn existing_offer(
    offers: &dyn HandoverOfferStore,
    request: &AcceptDomainRequest,
) -> Result<HandoverOffer, AppError> {
    offers
        .find(&request.source_tenant_id, &request.domain)
        .await
        .or_internal()?
        .or_not_found(message!(
            "domain-handover-offer-not-found",
            "handover offer not found"
        ))
}

/// The giving tenant's registration of the domain `offer` hands over.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant no longer has the domain.
/// - `AppError::Internal` on storage failure.
async fn offered_domain(
    store: &dyn RegisteredDomainStore,
    source: &Tenant,
    offer: &HandoverOffer,
) -> Result<RegisteredDomain<ResolvedTenant>, AppError> {
    store
        .find_by_tenant_and_name(&ScopedTenant::from_registry(source), offer.domain())
        .await
        .or_internal()?
        .or_not_found(message!("domain-domain-not-found", "domain not found"))
}

/// Keeps the offer spent, moves the domain, then records the move.
async fn accept_and_record(
    ports: &AcceptDomainPorts,
    auditor: &RequestAuditor,
    handover: Handover<'_>,
    offer: &mut HandoverOffer,
) -> Result<(), AppError> {
    ports.offers.save(offer).await.or_internal()?;
    transfer(ports, handover).await?;
    auditor.dispatch(&offer.take_events()).await.or_internal()
}

/// Moves the registration, and the zone of a delegated domain.
///
/// The registration is saved under the receiving tenant before it is
/// deleted from the giving one. Saved under the same id, it keeps the claim
/// on its name and the certificates that serve it the whole way; deleted
/// first, it would release them, and the certificate would be lost. A
/// delete that finds nothing means another accept moved it first, and the
/// unit drops the save with it.
async fn transfer(ports: &AcceptDomainPorts, handover: Handover<'_>) -> Result<(), AppError> {
    let source = ScopedTenant::from_registry(handover.source);
    let target = ScopedTenant::from_registry(handover.target);
    let domain = handover.domain;
    ports
        .domain_store
        .save(&target, domain)
        .await
        .map_err(AppError::from_domain)?;
    let deleted = ports
        .domain_store
        .delete(&source, domain.id())
        .await
        .or_internal()?;
    if !deleted {
        return Err(AppError::Conflict(message!(
            "domain-the-domain-was-moved-or-removed",
            "the domain was moved or removed while the offer was accepted"
        )));
    }
    ports
        .dns_zones
        .transfer_zone(&source, &target, domain.domain())
        .await
        .or_internal()
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_domain::domains::authorization::permission::{DomainAction, SystemPermission};
    use ianua_domain::domains::tenant::custom_domains::dns_zone::DelegationLabel;
    use ianua_domain::domains::tenant::custom_domains::handover_offer::{
        HandoverOfferRow, HandoverOfferState,
    };
    use ianua_domain::domains::tenant::custom_domains::registered_domain::ClaimLifetimes;
    use ianua_domain::domains::tenant::custom_domains::verification_status::VerificationStatus;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{DomainId, OrganizationId};
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::listing::{Page, PageRequest, SortOrder};
    use crate::ports::TenantScoped;
    use crate::ports::domain::DomainSortField;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::domain::{
        DomainSeed, FakeDnsZoneWriter, FakeDomainStore, FakeHandoverOfferStore,
    };
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_in, test_tenant_with_id};
    use crate::test_support::{
        FakeEventDispatcher, FakeLimitEnforcer, RejectingLimitEnforcer, block_on, test_auditor,
        test_ctx,
    };

    struct Fixture {
        use_case: AcceptDomainUseCase,
        domains: Arc<FakeDomainStore>,
        zones: Arc<FakeDnsZoneWriter>,
        offers: Arc<FakeHandoverOfferStore>,
        audit: Arc<FakeEventDispatcher>,
        id: DomainId,
        source: TenantId,
    }

    struct Setup {
        domain: RegisteredDomain<ResolvedTenant>,
        source: Tenant,
        offer: Option<HandoverOfferRow>,
        authorities: FakeTenantAuthorities,
        limits: Arc<dyn LimitEnforcer>,
        deletes: Deletes,
    }

    /// What deleting the giving tenant's registration finds.
    enum Deletes {
        /// The registration, as stored.
        Find,
        /// Nothing: another accept moved it first.
        FindNothing,
    }

    fn acme() -> Tenant {
        let ctx = test_ctx();
        test_tenant_with_id(ctx.tenant_id(), ctx.organization_id(), "acme", "acme.test")
    }

    fn sibling(primary: &str) -> Tenant {
        test_tenant_in(test_ctx().organization_id(), "acme-eu", primary)
    }

    fn offer_row(from: &Tenant, name: &str, offered_ago: Duration) -> HandoverOfferRow {
        HandoverOfferRow {
            from: *from.id(),
            to: test_ctx().tenant_id(),
            domain: DomainName::new(name).unwrap(),
            offered_at: clock::now() - offered_ago,
            state: HandoverOfferState::Waiting,
        }
    }

    fn offered(domain: RegisteredDomain<ResolvedTenant>) -> Setup {
        let source = sibling("eu.acme.test");
        let offer = offer_row(&source, domain.domain().as_str(), Duration::days(1));
        Setup {
            domain,
            source,
            offer: Some(offer),
            authorities: FakeTenantAuthorities::holding_everything(),
            limits: Arc::new(FakeLimitEnforcer),
            deletes: Deletes::Find,
        }
    }

    /// Reconstitutes the offered handover when one is present.
    fn kept_offers(row: Option<HandoverOfferRow>) -> Arc<FakeHandoverOfferStore> {
        Arc::new(FakeHandoverOfferStore::holding(
            row.map(|row| HandoverOffer::reconstitute(row).unwrap()),
        ))
    }

    /// Stores the giving tenant's domain and exposes the configured acceptance outcome.
    fn fixture(setup: Setup) -> Fixture {
        let id = *setup.domain.id();
        let source = *setup.source.id();
        let domains = Arc::new(FakeDomainStore::holding(source, [setup.domain]));
        let zones = Arc::new(FakeDnsZoneWriter::with_nameservers(vec![
            DomainName::new("ns1.ianua.test").unwrap(),
        ]));
        let offers = kept_offers(setup.offer);
        let domain_store: Arc<dyn RegisteredDomainStore> = match setup.deletes {
            Deletes::Find => domains.clone(),
            Deletes::FindNothing => Arc::new(RacedDomainStore(domains.clone())),
        };
        let use_case = AcceptDomainUseCase::new(AcceptDomainPorts {
            domain_store,
            tenants: Arc::new(FakeTenantStore::holding_all([acme(), setup.source])),
            offers: offers.clone(),
            dns_zones: zones.clone(),
            tenant_authorities: Arc::new(setup.authorities),
            limit_enforcer: setup.limits,
            ..AcceptDomainPorts::fakes()
        });
        Fixture {
            use_case,
            domains,
            zones,
            offers,
            audit: Arc::new(FakeEventDispatcher::new()),
            id,
            source,
        }
    }

    fn accept_from(f: &Fixture, source: TenantId) -> Result<(), AppError> {
        block_on(f.use_case.execute(
            &test_ctx(),
            &test_auditor(f.audit.clone()),
            AcceptDomainRequest {
                source_tenant_id: source,
                domain: DomainName::new("shop.acme.test").unwrap(),
            },
        ))
    }

    fn accept(f: &Fixture) -> Result<(), AppError> {
        accept_from(f, f.source)
    }

    fn still_with_source(f: &Fixture) -> bool {
        f.domains.domain_of(f.source, &f.id).is_some()
    }

    fn shop() -> RegisteredDomain<ResolvedTenant> {
        DomainSeed::verified("shop.acme.test").build()
    }

    /// The EU tenant offered `shop.acme.test` to Acme, and Ann accepts it.
    /// Acme holds it, still verified, the EU tenant no longer does, the
    /// offer is spent and the transfer is recorded.
    #[test]
    fn an_accepted_domain_moves_to_the_receiving_tenant() {
        let f = fixture(offered(shop()));

        accept(&f).unwrap();

        let moved = f.domains.domain_of(test_ctx().tenant_id(), &f.id).unwrap();
        let offer = f
            .offers
            .offer_of(&f.source, &DomainName::new("shop.acme.test").unwrap())
            .unwrap();
        assert_eq!(moved.verification_status(), VerificationStatus::Verified);
        assert!(!still_with_source(&f));
        assert!(matches!(offer.state(), HandoverOfferState::Accepted { .. }));
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            vec!["tenant.domain_transferred"]
        );
    }

    /// Ann accepts a delegated domain. Its zone moves with it, so the live
    /// hostname keeps answering for its new holder.
    #[test]
    fn a_delegated_domains_zone_follows_it() {
        let domain = DomainSeed::verified("shop.acme.test").delegated().build();
        let name = domain.domain().clone();
        let label = DelegationLabel::for_registration(domain.id());
        let f = fixture(offered(domain));
        block_on(f.zones.create_zone(&f.source, &name, &label)).unwrap();

        accept(&f).unwrap();

        let acme = test_ctx().tenant_id();
        assert!(block_on(f.zones.create_zone(&acme, &name, &label)).is_ok());
        assert!(block_on(f.zones.create_zone(&f.source, &name, &label)).is_err());
    }

    /// Returning a domain to its source does not make an accepted offer
    /// reusable; accepting it again conflicts.
    #[test]
    fn an_offer_is_accepted_only_once() {
        let f = fixture(offered(shop()));
        accept(&f).unwrap();
        let acme = test_ctx().tenant();
        let held = block_on(f.domains.find_by_tenant_and_name(&acme, shop().domain()))
            .unwrap()
            .unwrap();
        block_on(f.domains.delete(&acme, held.id())).unwrap();
        block_on(f.domains.save(&ScopedTenant::for_test(f.source), &shop())).unwrap();

        let result = accept(&f);

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// An eight-day-old offer has expired; acceptance conflicts and leaves
    /// the domain with its source tenant.
    #[test]
    fn an_offer_that_ran_out_is_refused() {
        let source = sibling("eu.acme.test");
        let offer = offer_row(&source, "shop.acme.test", Duration::days(8));
        let f = fixture(Setup {
            source,
            offer: Some(offer),
            ..offered(shop())
        });

        let result = accept(&f);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(still_with_source(&f));
    }

    /// Without an offer, acceptance returns not found and leaves the
    /// domain registered to its source tenant.
    #[test]
    fn a_domain_never_offered_is_not_found() {
        let f = fixture(Setup {
            offer: None,
            ..offered(shop())
        });

        let result = accept(&f);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(still_with_source(&f));
    }

    /// Acme cannot accept an offer addressed to another tenant; the
    /// forbidden attempt leaves the domain with its source.
    #[test]
    fn an_offer_made_to_another_tenant_is_refused() {
        let source = sibling("eu.acme.test");
        let offer = HandoverOfferRow {
            to: TenantId::new(),
            ..offer_row(&source, "shop.acme.test", Duration::days(1))
        };
        let f = fixture(Setup {
            source,
            offer: Some(offer),
            ..offered(shop())
        });

        let result = accept(&f);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(still_with_source(&f));
    }

    /// Acceptance conflicts when the offered domain is now the source
    /// tenant's primary domain.
    #[test]
    fn a_domain_that_became_the_givers_primary_is_refused() {
        let source = sibling("shop.acme.test");
        let offer = offer_row(&source, "shop.acme.test", Duration::days(1));
        let f = fixture(Setup {
            source,
            offer: Some(offer),
            ..offered(shop())
        });

        let result = accept(&f);

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// An offer from a tenant in another organization cannot be accepted,
    /// even when addressed to Acme.
    #[test]
    fn an_offer_from_another_organization_is_refused() {
        let source = test_tenant_in(OrganizationId::new(), "globex", "globex.test");
        let offer = offer_row(&source, "shop.acme.test", Duration::days(1));
        let f = fixture(Setup {
            source,
            offer: Some(offer),
            ..offered(shop())
        });

        let result = accept(&f);

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Ann names a giving tenant that does not exist. It is not found.
    #[test]
    fn an_unknown_source_is_not_found() {
        let f = fixture(offered(shop()));

        let result = accept_from(&f, TenantId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Domain-viewing rights cannot accept a handover; the forbidden
    /// attempt leaves the domain with its source tenant.
    #[test]
    fn a_caller_who_may_only_view_domains_is_refused() {
        let f = fixture(Setup {
            authorities: FakeTenantAuthorities::holding(&[SystemPermission::Domains(
                DomainAction::View,
            )]),
            ..offered(shop())
        });

        let result = accept(&f);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(still_with_source(&f));
    }

    /// A store whose deletes find nothing: another accept of the same offer
    /// moved the domain first.
    struct RacedDomainStore(Arc<FakeDomainStore>);

    impl TenantScoped for RacedDomainStore {}

    #[async_trait]
    impl RegisteredDomainStore for RacedDomainStore {
        async fn find_by_names(
            &self,
            tenant: &ScopedTenant,
            domains: &[DomainName],
        ) -> Result<Vec<RegisteredDomain<ResolvedTenant>>, DomainError> {
            self.0.find_by_names(tenant, domains).await
        }

        async fn save(
            &self,
            tenant: &ScopedTenant,
            domain: &RegisteredDomain<ResolvedTenant>,
        ) -> Result<(), DomainError> {
            self.0.save(tenant, domain).await
        }

        async fn register(
            &self,
            tenant: &ScopedTenant,
            domain: &RegisteredDomain<ResolvedTenant>,
            lifetimes: &ClaimLifetimes,
            now: OffsetDateTime,
        ) -> Result<(), DomainError> {
            self.0.register(tenant, domain, lifetimes, now).await
        }

        async fn find_by_id(
            &self,
            tenant: &ScopedTenant,
            id: &DomainId,
        ) -> Result<Option<RegisteredDomain<ResolvedTenant>>, DomainError> {
            self.0.find_by_id(tenant, id).await
        }

        async fn list_by_tenant(
            &self,
            tenant: &ScopedTenant,
            sort: &SortOrder<DomainSortField>,
            page: &PageRequest,
        ) -> Result<Page<RegisteredDomain<ResolvedTenant>>, DomainError> {
            self.0.list_by_tenant(tenant, sort, page).await
        }

        async fn delete(&self, _: &ScopedTenant, _: &DomainId) -> Result<bool, DomainError> {
            Ok(false)
        }

        async fn find_by_tenant_and_name(
            &self,
            tenant: &ScopedTenant,
            domain: &DomainName,
        ) -> Result<Option<RegisteredDomain<ResolvedTenant>>, DomainError> {
            self.0.find_by_tenant_and_name(tenant, domain).await
        }
    }

    /// If deleting the source registration finds it already moved,
    /// acceptance conflicts without recording a transfer.
    #[test]
    fn an_accept_that_finds_the_domain_already_moved_is_refused() {
        let f = fixture(Setup {
            deletes: Deletes::FindNothing,
            ..offered(shop())
        });

        let result = accept(&f);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A full domain allowance prevents accepting a handover and leaves
    /// the domain with the giving tenant.
    #[test]
    fn a_handover_past_the_plans_ceiling_is_refused() {
        let f = fixture(Setup {
            limits: Arc::new(RejectingLimitEnforcer),
            ..offered(shop())
        });

        let result = accept(&f);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(still_with_source(&f));
    }

    /// A signed-out session cannot accept an offered domain.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture(Setup {
            authorities: FakeTenantAuthorities::refusing(Refusal::SignedOut),
            ..offered(shop())
        });

        let result = accept(&f);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

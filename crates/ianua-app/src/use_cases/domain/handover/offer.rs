//! Offer domain handover: an admin of the giving tenant offers one of its
//! domains to another tenant of the same organization, which must accept it
//! before it moves.

use std::sync::Arc;

use ianua_domain::domains::tenant::control::{TenantArea, TenantControl};
use ianua_domain::domains::tenant::custom_domains::handover::DomainHandover;
use ianua_domain::domains::tenant::custom_domains::handover_offer::HandoverOffer;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{DomainId, TenantId};
use time::OffsetDateTime;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::domain::{HandoverOfferStore, RegisteredDomainStore};
use crate::ports::tenant::TenantStore;
use crate::services::lookup::existing_tenant;
use crate::use_case::Command;
use crate::use_cases::domain::lookup::existing_domain;

/// The ports [`OfferDomainUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OfferDomainPorts {
    /// Loads the registration offered.
    pub domain_store: Arc<dyn RegisteredDomainStore>,
    /// Loads both tenants, to check the handover between them.
    pub tenants: Arc<dyn TenantStore>,
    /// Keeps the offer until the receiving tenant accepts it.
    pub offers: Arc<dyn HandoverOfferStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which domain of the caller's tenant to offer, and to whom.
pub struct OfferDomainRequest {
    /// The registration to offer.
    pub domain_id: DomainId,
    /// The tenant to offer it to. The domain decides whether it may receive
    /// it.
    pub target_tenant_id: TenantId,
}

/// Offers a domain of the caller's tenant to a sibling tenant.
pub struct OfferDomainUseCase {
    ports: OfferDomainPorts,
}

impl OfferDomainUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: OfferDomainPorts) -> Self {
        Self { ports }
    }
}

impl Command for OfferDomainUseCase {
    type Caller = CallerContext;
    type Input = OfferDomainRequest;
    type Output = Result<OffsetDateTime, AppError>;

    /// Offers the domain to the target tenant and gives back when the offer
    /// runs out. It replaces an earlier offer of the same domain. Nothing
    /// moves and nothing is recorded until the target accepts: the domain
    /// stays the caller's tenant's until then.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without domain-change rights.
    /// - `AppError::NotFound` for a missing domain/tenant; `Conflict` for identical tenants, different organizations or a primary domain.
    /// - `AppError::Domain` for a closed tenant; `Internal` on persistence failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: OfferDomainRequest,
    ) -> Result<OffsetDateTime, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        TenantControl::new(&authority)
            .ensure_may(&caller.tenant_id(), TenantArea::Domains)
            .map_err(AppError::from_domain)?;
        let tenants = self.ports.tenants.as_ref();
        let source = existing_tenant(tenants, &caller.tenant_id()).await?;
        let target = existing_tenant(tenants, &request.target_tenant_id).await?;
        let domain = existing_domain(
            self.ports.domain_store.as_ref(),
            &caller.tenant(),
            &request.domain_id,
        )
        .await?;
        let handover = DomainHandover {
            from: &source,
            to: &target,
            domain: domain.domain(),
        };
        let mut offer = HandoverOffer::offer(&handover, TenantControl::new(&authority))
            .map_err(AppError::from_domain)?;
        self.ports.offers.save(&offer).await.or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), offer.take_events())
            .await
            .or_internal()?;
        Ok(offer.expires_at())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{DomainAction, SystemPermission};
    use ianua_domain::domains::tenant::custom_domains::handover_offer::HandoverOfferState;
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::types::{DomainName, OrganizationId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::domain::{DomainSeed, FakeDomainStore, FakeHandoverOfferStore};
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_in, test_tenant_with_id};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        use_case: OfferDomainUseCase,
        offers: Arc<FakeHandoverOfferStore>,
        id: DomainId,
        target: TenantId,
    }

    fn acme() -> Tenant {
        let ctx = test_ctx();
        test_tenant_with_id(ctx.tenant_id(), ctx.organization_id(), "acme", "acme.test")
    }

    fn sibling() -> Tenant {
        test_tenant_in(test_ctx().organization_id(), "acme-eu", "eu.acme.test")
    }

    fn fixture_with(name: &str, target: Tenant, authorities: FakeTenantAuthorities) -> Fixture {
        let domain = DomainSeed::verified(name).build();
        let id = *domain.id();
        let target_id = *target.id();
        let offers = Arc::new(FakeHandoverOfferStore::default());
        let use_case = OfferDomainUseCase::new(OfferDomainPorts {
            domain_store: Arc::new(FakeDomainStore::holding(test_ctx().tenant_id(), [domain])),
            tenants: Arc::new(FakeTenantStore::holding_all([acme(), target])),
            offers: offers.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        Fixture {
            use_case,
            offers,
            id,
            target: target_id,
        }
    }

    fn fixture(name: &str) -> Fixture {
        fixture_with(name, sibling(), FakeTenantAuthorities::holding_everything())
    }

    fn offer(f: &Fixture, domain_id: DomainId, target: TenantId) -> Result<(), AppError> {
        offer_recorded(f, domain_id, target, &Arc::new(FakeEventDispatcher::new()))
    }

    fn offer_recorded(
        f: &Fixture,
        domain_id: DomainId,
        target: TenantId,
        audit: &Arc<FakeEventDispatcher>,
    ) -> Result<(), AppError> {
        block_on(f.use_case.execute(
            &test_ctx(),
            &test_auditor(audit.clone()),
            OfferDomainRequest {
                domain_id,
                target_tenant_id: target,
            },
        ))
        .map(|_| ())
    }

    fn offered(f: &Fixture) -> bool {
        f.offers
            .offer_of(&test_ctx().tenant_id(), &shop())
            .is_some()
    }

    fn shop() -> DomainName {
        DomainName::new("shop.acme.test").unwrap()
    }

    /// Ann offers `shop.acme.test` from Acme to its EU tenant. The offer
    /// waits for the EU tenant, and the domain stays Acme's until then.
    #[test]
    fn a_domain_is_offered_to_a_sibling_tenant() {
        let f = fixture("shop.acme.test");

        offer(&f, f.id, f.target).unwrap();

        let stored = f.offers.offer_of(&test_ctx().tenant_id(), &shop()).unwrap();
        assert_eq!(*stored.to(), f.target);
        assert_eq!(stored.state(), HandoverOfferState::Waiting);
    }

    /// Ann offers `shop.acme.test` to the EU tenant. The offer is recorded
    /// under Acme, naming the domain, so an offer nobody expected is seen
    /// before it is taken.
    #[test]
    fn an_offer_is_recorded_under_the_giving_tenant() {
        let f = fixture("shop.acme.test");
        let audit = Arc::new(FakeEventDispatcher::new());

        offer_recorded(&f, f.id, f.target, &audit).unwrap();

        assert_eq!(
            audit.tenant_of("tenant.domain_handover_offered"),
            Some(test_ctx().tenant_id())
        );
        assert_eq!(
            audit
                .payload_of("tenant.domain_handover_offered")
                .get("domain"),
            Some("shop.acme.test")
        );
    }

    /// Offering a domain across organizations conflicts and saves no
    /// handover offer.
    #[test]
    fn a_tenant_of_another_organization_is_offered_nothing() {
        let f = fixture_with(
            "shop.acme.test",
            test_tenant_in(OrganizationId::new(), "globex", "globex.test"),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = offer(&f, f.id, f.target);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(!offered(&f));
    }

    /// Acme cannot offer its domain to itself; the identical source and
    /// target produce a conflict.
    #[test]
    fn a_domain_is_not_offered_to_the_tenant_holding_it() {
        let f = fixture("shop.acme.test");

        let result = offer(&f, f.id, test_ctx().tenant_id());

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// A tenant's primary hostname cannot be offered to a sibling tenant.
    #[test]
    fn the_primary_domain_is_not_offered() {
        let f = fixture("acme.test");

        let result = offer(&f, f.id, f.target);

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Ann names a domain Acme does not have. It is not found.
    #[test]
    fn an_unknown_domain_is_not_found() {
        let f = fixture("shop.acme.test");

        let result = offer(&f, DomainId::new(), f.target);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann names a tenant that does not exist. It is not found.
    #[test]
    fn an_unknown_target_is_not_found() {
        let f = fixture("shop.acme.test");

        let result = offer(&f, f.id, TenantId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Domain-viewing rights cannot offer a handover; the forbidden
    /// attempt saves no offer.
    #[test]
    fn a_caller_who_may_only_view_domains_is_refused() {
        let f = fixture_with(
            "shop.acme.test",
            sibling(),
            FakeTenantAuthorities::holding(&[SystemPermission::Domains(DomainAction::View)]),
        );

        let result = offer(&f, f.id, f.target);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(!offered(&f));
    }

    /// A signed-out session cannot offer a domain to another tenant.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture_with(
            "shop.acme.test",
            sibling(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = offer(&f, f.id, f.target);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}

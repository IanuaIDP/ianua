//! A domain offered by one tenant and waiting for the other to accept it.
//!
//! Handing a domain over changes who answers for it on both sides. The
//! giving tenant's admin offers it, and an admin of the receiving tenant
//! accepts it. Neither can push or pull a domain alone. An offer is
//! accepted once, so a domain handed back later never returns on the old
//! offer.

use time::{Duration, OffsetDateTime};

use crate::domains::tenant::control::{TenantArea, TenantControl};
use crate::domains::tenant::custom_domains::handover::DomainHandover;
use crate::domains::tenant::events::custom_domains::{
    TenantDomainHandoverOffered, TenantDomainTransferred,
};
use crate::domains::tenant::lifecycle::Tenant;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete};
use crate::shared::model::row_check::RowCheck;
use crate::types::{DomainName, EventLabel, TenantId};

/// How long an offer waits for the receiving tenant.
pub const OFFER_LIFETIME: Duration = Duration::days(7);

/// Where an offer stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoverOfferState {
    /// Waiting for the receiving tenant.
    Waiting,
    /// Accepted, and so spent.
    Accepted {
        /// When it was accepted.
        at: OffsetDateTime,
    },
}

/// A domain one tenant offered to another, waiting to be accepted.
///
/// It knows both tenants, so its records name their tenant themselves: the
/// offer is filed under the giving tenant, the transfer under the
/// receiving one.
#[derive(Debug, Clone, PartialEq)]
pub struct HandoverOffer {
    from: TenantId,
    to: TenantId,
    domain: DomainName,
    offered_at: OffsetDateTime,
    state: HandoverOfferState,
    raised: RaisedEvents,
}

/// An offer as stored, for rebuilding it with
/// [`HandoverOffer::reconstitute`].
pub struct HandoverOfferRow {
    /// The tenant giving the domain.
    pub from: TenantId,
    /// The tenant receiving it.
    pub to: TenantId,
    /// The registered name offered for transfer to the receiving tenant.
    pub domain: DomainName,
    /// When it was offered.
    pub offered_at: OffsetDateTime,
    /// Whether it still waits, or when it was accepted.
    pub state: HandoverOfferState,
}

impl HandoverOffer {
    /// Offers `handover`'s domain to the receiving tenant, for an admin of
    /// the giving tenant. Raises `tenant.domain_handover_offered`, filed
    /// under the giving tenant and naming the receiving one.
    ///
    /// # Errors
    ///
    /// - The cases [`DomainHandover::ensure_allowed`] lists.
    pub fn offer(
        handover: &DomainHandover<'_>,
        by: TenantControl<'_>,
    ) -> Result<Self, DomainError> {
        handover.ensure_allowed(by)?;
        let mut offer = Self {
            from: *handover.from.id(),
            to: *handover.to.id(),
            domain: handover.domain.clone(),
            offered_at: crate::shared::clock::now(),
            state: HandoverOfferState::Waiting,
            raised: RaisedEvents::default(),
        };
        offer.raised.raise_tenant(
            offer.from,
            TenantDomainHandoverOffered {
                target_tenant_id: offer.to,
                target_tenant_label: label_of(handover.to),
                domain: offer.domain.clone(),
                occurred_at: offer.offered_at,
            },
        );
        Ok(offer)
    }

    /// Accepts the offer, for an admin of the receiving tenant, and spends
    /// it. Everything the offer needed is checked again, since either
    /// tenant may have changed since. Raises `tenant.domain_transferred`,
    /// filed under the receiving tenant and naming both, taken once the
    /// domain has moved.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `from` or `to` are not the offer's
    ///   tenants.
    /// - [`DomainError::Conflict`] when the offer was already accepted.
    /// - [`DomainError::Conflict`] when the offer ran out after
    ///   [`OFFER_LIFETIME`].
    /// - [`DomainError::Forbidden`] when the person may not change the
    ///   receiving tenant's domains.
    /// - The cases [`DomainHandover::ensure_still_possible`] lists.
    pub fn accept(
        &mut self,
        from: &Tenant,
        to: &Tenant,
        by: TenantControl<'_>,
    ) -> Result<(), DomainError> {
        if *from.id() != self.from || *to.id() != self.to {
            return Err(DomainError::forbidden(message!(
                "tenant-the-offer-is-between-other-tenants",
                "the offer is between other tenants"
            )));
        }
        let now = crate::shared::clock::now();
        self.ensure_open_at(now)?;
        to.ensure_changeable(by, TenantArea::Domains)?;
        DomainHandover {
            from,
            to,
            domain: &self.domain,
        }
        .ensure_still_possible()?;
        self.state = HandoverOfferState::Accepted { at: now };
        self.raised.raise_tenant(
            self.to,
            TenantDomainTransferred {
                source_tenant_id: self.from,
                source_tenant_label: label_of(from),
                target_tenant_id: self.to,
                target_tenant_label: label_of(to),
                domain: self.domain.clone(),
                occurred_at: now,
            },
        );
        Ok(())
    }

    /// Refuses an offer that was spent or ran out by `now`.
    fn ensure_open_at(&self, now: OffsetDateTime) -> Result<(), DomainError> {
        if let HandoverOfferState::Accepted { .. } = self.state {
            return Err(DomainError::conflict(message!(
                "tenant-the-offer-was-already-accepted-offer",
                "the offer was already accepted; offer the domain again"
            )));
        }
        if now >= self.expires_at() {
            return Err(DomainError::conflict(message!(
                "tenant-the-offer-ran-out-offer-the",
                "the offer ran out; offer the domain again"
            )));
        }
        Ok(())
    }

    /// Rebuilds an offer from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row hands a domain from a
    ///   tenant to itself.
    /// - [`DomainError::Infrastructure`] when the row says it was accepted
    ///   before it was offered, or after it ran out.
    pub fn reconstitute(row: HandoverOfferRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            from: row.from,
            to: row.to,
            domain: row.domain,
            offered_at: row.offered_at,
            state: row.state,
            raised: RaisedEvents::default(),
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &HandoverOfferRow) -> Result<(), DomainError> {
        let accepted_at = match row.state {
            HandoverOfferState::Waiting => None,
            HandoverOfferState::Accepted { at } => Some(at),
        };
        let runs_out = row.offered_at.saturating_add(OFFER_LIFETIME);
        RowCheck::of("domain handover offer")
            .holds(row.from != row.to, "a domain offered by a tenant to itself")
            .in_order_if(
                row.offered_at,
                accepted_at,
                "accepted before it was offered",
            )
            .holds(
                accepted_at.is_none_or(|at| at < runs_out),
                "accepted after it ran out",
            )
            .finish()
    }

    /// The tenant giving the domain.
    #[must_use]
    pub fn from(&self) -> &TenantId {
        &self.from
    }

    /// The tenant receiving it.
    #[must_use]
    pub fn to(&self) -> &TenantId {
        &self.to
    }

    /// The registered name whose pending transfer this offer controls.
    #[must_use]
    pub fn domain(&self) -> &DomainName {
        &self.domain
    }

    /// When it was offered.
    #[must_use]
    pub fn offered_at(&self) -> OffsetDateTime {
        self.offered_at
    }

    /// Whether it still waits, or when it was accepted.
    #[must_use]
    pub fn state(&self) -> HandoverOfferState {
        self.state
    }

    /// The moment the offer runs out unless it was accepted before.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.offered_at.saturating_add(OFFER_LIFETIME)
    }
}

impl RaisesComplete for HandoverOffer {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

/// `tenant` as the audit trail names it: its display name now.
fn label_of(tenant: &Tenant) -> EventLabel {
    EventLabel::of(tenant.display_name().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::tenant::compliance_limits::ComplianceLimits;
    use crate::domains::tenant::fixtures::{ADMIN, acme_params, active, holding, person};
    use crate::domains::tenant::lifecycle::ProvisionTenantParams;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::raised_complete_names;
    use crate::types::ActedBy;

    fn sibling_of(tenant: &Tenant) -> Tenant {
        let mut sibling = Tenant::provision(
            ProvisionTenantParams {
                organization_id: *tenant.organization_id(),
                ..acme_params()
            },
            &ComplianceLimits::default(),
            ActedBy::Platform,
        )
        .unwrap();
        sibling.activate(ActedBy::Platform).unwrap();
        sibling
    }

    fn offered(staging: &Tenant, production: &Tenant) -> HandoverOffer {
        let ann = person("ann@acme.test");
        let name = DomainName::new("shop.acme.com").unwrap();
        HandoverOffer::offer(
            &DomainHandover {
                from: staging,
                to: production,
                domain: &name,
            },
            holding(&ann, staging, ADMIN),
        )
        .unwrap()
    }

    fn row_of(offer: &HandoverOffer, state: HandoverOfferState) -> HandoverOfferRow {
        HandoverOfferRow {
            from: *offer.from(),
            to: *offer.to(),
            domain: offer.domain().clone(),
            offered_at: offer.offered_at(),
            state,
        }
    }

    /// Ann offers `shop.acme.com` from staging to production. Paul, an
    /// admin of production, accepts it. Ann, who administers only staging,
    /// cannot accept it for production.
    #[test]
    fn the_receiving_tenant_accepts_a_handover() {
        let staging = active();
        let production = sibling_of(&staging);
        let mut offer = offered(&staging, &production);
        let ann = person("ann@acme.test");
        let paul = person("paul@acme.test");

        let by_ann = offer.accept(&staging, &production, holding(&ann, &staging, ADMIN));
        let by_paul = offer.accept(&staging, &production, holding(&paul, &production, ADMIN));

        assert!(matches!(by_ann, Err(DomainError::Forbidden(_))));
        assert!(by_paul.is_ok());
        assert!(matches!(offer.state(), HandoverOfferState::Accepted { .. }));
    }

    /// Authority in the receiving tenant cannot authorize an offer of the
    /// giving tenant's domain.
    #[test]
    fn only_an_admin_of_the_giving_tenant_offers_its_domain() {
        let staging = active();
        let production = sibling_of(&staging);
        let paul = person("paul@acme.test");
        let name = DomainName::new("shop.acme.com").unwrap();
        let handover = DomainHandover {
            from: &staging,
            to: &production,
            domain: &name,
        };

        let result = HandoverOffer::offer(&handover, holding(&paul, &production, ADMIN));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Accepting a handover spends the offer; a second acceptance with the
    /// same tenants and authority is rejected as a conflict.
    #[test]
    fn an_accepted_offer_cannot_be_accepted_again() {
        let staging = active();
        let production = sibling_of(&staging);
        let mut offer = offered(&staging, &production);
        let paul = person("paul@acme.test");
        offer
            .accept(&staging, &production, holding(&paul, &production, ADMIN))
            .unwrap();

        let again = offer.accept(&staging, &production, holding(&paul, &production, ADMIN));

        assert!(matches!(again, Err(DomainError::Conflict(_))));
    }

    /// Archiving the receiving tenant prevents acceptance of its pending
    /// domain handover offer.
    #[test]
    fn a_tenant_closed_since_the_offer_cannot_accept_it() {
        let staging = active();
        let mut production = sibling_of(&staging);
        let mut offer = offered(&staging, &production);
        let paul = person("paul@acme.test");
        production.archive(ActedBy::Platform).unwrap();

        let accepted = offer.accept(&staging, &production, holding(&paul, &production, ADMIN));

        assert!(accepted.is_err());
    }

    /// Suspending the giving tenant prevents acceptance and leaves the
    /// domain handover offer waiting.
    #[test]
    fn a_giving_tenant_suspended_since_the_offer_gives_nothing_away() {
        let mut staging = active();
        let production = sibling_of(&staging);
        let mut offer = offered(&staging, &production);
        let paul = person("paul@acme.test");
        staging.suspend(ActedBy::Platform).unwrap();

        let accepted = offer.accept(&staging, &production, holding(&paul, &production, ADMIN));

        assert!(matches!(accepted, Err(DomainError::InvalidTransition(_))));
        assert_eq!(offer.state(), HandoverOfferState::Waiting);
    }

    /// Acceptance eight days after an offer was made is rejected because
    /// its one-week lifetime has elapsed.
    #[test]
    fn an_offer_runs_out_after_a_week() {
        let staging = active();
        let production = sibling_of(&staging);
        let mut offer = offered(&staging, &production);
        let paul = person("paul@acme.test");

        let _later = crate::shared::clock::freeze(offer.offered_at() + Duration::days(8));
        let accepted = offer.accept(&staging, &production, holding(&paul, &production, ADMIN));

        assert!(matches!(accepted, Err(DomainError::Conflict(_))));
    }

    /// Stored offers accepted an hour before creation or two weeks after
    /// creation are rejected as corrupt.
    #[test]
    fn a_row_accepted_outside_the_offers_week_is_refused() {
        let staging = active();
        let production = sibling_of(&staging);
        let offer = offered(&staging, &production);
        let early = offer.offered_at() - Duration::hours(1);
        let late = offer.offered_at() + Duration::days(14);

        let before =
            HandoverOffer::reconstitute(row_of(&offer, HandoverOfferState::Accepted { at: early }));
        let after =
            HandoverOffer::reconstitute(row_of(&offer, HandoverOfferState::Accepted { at: late }));

        assert!(refused_as_corrupt(&before));
        assert!(refused_as_corrupt(&after));
    }

    /// Ann offers `shop.acme.com` from staging to production. The offer is
    /// raised filed under staging, naming production.
    #[test]
    fn offering_raises_tenant_domain_handover_offered_under_the_giver() {
        let staging = active();
        let production = sibling_of(&staging);

        let events = offered(&staging, &production).take_events();

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "tenant.domain_handover_offered"
        );
        assert_eq!(events[0].tenant_id(), Some(staging.id()));
        let payload = events[0].payload();
        let Some(FieldValue::Reference(target)) = payload.value("target_tenant") else {
            panic!("the receiving tenant is not referenced");
        };
        assert_eq!(target.id(), production.id().to_string());
    }

    /// Paul accepts Ann's offer for production. The transfer is raised
    /// filed under production, which now holds the domain.
    #[test]
    fn accepting_raises_tenant_domain_transferred_under_the_receiver() {
        let staging = active();
        let production = sibling_of(&staging);
        let mut offer = offered(&staging, &production);
        raised_complete_names(&mut offer);
        let paul = person("paul@acme.test");

        offer
            .accept(&staging, &production, holding(&paul, &production, ADMIN))
            .unwrap();

        let events = offer.take_events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "tenant.domain_transferred"
        );
        assert_eq!(events[0].tenant_id(), Some(production.id()));
    }

    /// Acceptance using only the giving tenant's authority is rejected
    /// without raising a transfer event.
    #[test]
    fn a_refused_accept_raises_nothing() {
        let staging = active();
        let production = sibling_of(&staging);
        let mut offer = offered(&staging, &production);
        raised_complete_names(&mut offer);
        let ann = person("ann@acme.test");

        let refused = offer.accept(&staging, &production, holding(&ann, &staging, ADMIN));

        assert!(refused.is_err());
        assert!(raised_complete_names(&mut offer).is_empty());
    }

    /// An offer is read back from storage. Loading it is no change, so it
    /// has raised nothing.
    #[test]
    fn an_offer_read_back_from_storage_has_raised_nothing() {
        let staging = active();
        let production = sibling_of(&staging);
        let offer = offered(&staging, &production);

        let mut stored =
            HandoverOffer::reconstitute(row_of(&offer, HandoverOfferState::Waiting)).unwrap();

        assert!(raised_complete_names(&mut stored).is_empty());
    }
}

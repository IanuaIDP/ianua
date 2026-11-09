//! A handover offer as its row holds it: read back into the offer, and
//! written out from it.

use ianua_domain::domains::tenant::custom_domains::handover_offer::{
    HandoverOffer, HandoverOfferRow, HandoverOfferState,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DomainName, TenantId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const OFFER: Stored = Stored("domain handover offer");

/// An offer as it is read. The store's checked queries fill it.
pub(super) struct OfferRecord {
    pub(super) tenant_id: Uuid,
    pub(super) domain: String,
    pub(super) to_tenant_id: Uuid,
    pub(super) offered_at: OffsetDateTime,
    pub(super) accepted_at: Option<OffsetDateTime>,
}

impl OfferRecord {
    /// The offer the record holds, rebuilt through the offer's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the domain is no longer a
    /// domain name, or the row breaks a rule the offer keeps.
    pub(super) fn into_offer(self) -> Result<HandoverOffer, DomainError> {
        let state = match self.accepted_at {
            None => HandoverOfferState::Waiting,
            Some(at) => HandoverOfferState::Accepted { at },
        };
        HandoverOffer::reconstitute(HandoverOfferRow {
            from: TenantId::from_uuid(self.tenant_id),
            to: TenantId::from_uuid(self.to_tenant_id),
            domain: OFFER.value("domain", DomainName::new(self.domain))?,
            offered_at: self.offered_at,
            state,
        })
    }
}

/// When `offer` was accepted, as its column holds it: `None` while it
/// waits.
pub(super) fn accepted_at(offer: &HandoverOffer) -> Option<OffsetDateTime> {
    match offer.state() {
        HandoverOfferState::Waiting => None,
        HandoverOfferState::Accepted { at } => Some(at),
    }
}

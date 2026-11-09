//! An in-memory store of domain handover offers.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::tenant::custom_domains::handover_offer::{
    HandoverOffer, HandoverOfferRow,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DomainName, TenantId};

use crate::ports::domain::HandoverOfferStore;
use crate::test_support::Fake;

/// In-memory handover offer store for use case tests, keeping one offer per
/// giving tenant and domain and reading each back as storage would.
#[derive(Default)]
pub struct FakeHandoverOfferStore {
    offers: Mutex<Vec<HandoverOffer>>,
}

impl FakeHandoverOfferStore {
    /// A store holding `offers`.
    #[must_use]
    pub fn holding(offers: impl IntoIterator<Item = HandoverOffer>) -> Self {
        let store = Self::default();
        store.offers.lock().unwrap().extend(offers);
        store
    }

    /// The offer of `domain` by `from`, as last saved.
    #[must_use]
    pub fn offer_of(&self, from: &TenantId, domain: &DomainName) -> Option<HandoverOffer> {
        self.offers
            .lock()
            .unwrap()
            .iter()
            .find(|offer| offer.from() == from && offer.domain() == domain)
            .map(read_back)
    }
}

fn read_back(offer: &HandoverOffer) -> HandoverOffer {
    HandoverOffer::reconstitute(HandoverOfferRow {
        from: *offer.from(),
        to: *offer.to(),
        domain: offer.domain().clone(),
        offered_at: offer.offered_at(),
        state: offer.state(),
    })
    .expect("a handover offer reads back as itself")
}

#[async_trait]
impl HandoverOfferStore for FakeHandoverOfferStore {
    async fn save(&self, offer: &HandoverOffer) -> Result<(), DomainError> {
        let mut offers = self.offers.lock().unwrap();
        offers.retain(|kept| kept.from() != offer.from() || kept.domain() != offer.domain());
        offers.push(read_back(offer));
        Ok(())
    }

    async fn find(
        &self,
        from: &TenantId,
        domain: &DomainName,
    ) -> Result<Option<HandoverOffer>, DomainError> {
        Ok(self.offer_of(from, domain))
    }
}

impl Fake for Arc<dyn HandoverOfferStore> {
    fn fake() -> Self {
        Arc::new(FakeHandoverOfferStore::default())
    }
}

//! The offers that hand a domain between two tenants of one organization,
//! kept in the platform database.
//!
//! An offer belongs to both tenants, the giving one that writes it and the
//! receiving one that spends it, and either may live in a database of its
//! own, so it is kept beside the tenants themselves. Every call is platform
//! work naming the giving tenant; row-level security lets either tenant see
//! it.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::domain::HandoverOfferStore;
use ianua_domain::domains::tenant::custom_domains::handover_offer::HandoverOffer;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DomainName, TenantId};

use self::record::{OfferRecord, accepted_at};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of domain handover offers.
pub struct PgHandoverOfferStore {
    databases: Arc<Databases>,
}

impl PgHandoverOfferStore {
    /// A store keeping offers in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl HandoverOfferStore for PgHandoverOfferStore {
    async fn save(&self, offer: &HandoverOffer) -> Result<(), DomainError> {
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file!(
                "queries/domain_handover_offers/save.sql",
                offer.from().as_uuid(),
                offer.domain().as_str(),
                offer.to().as_uuid(),
                offer.offered_at(),
                accepted_at(offer)
            )
            .execute(connection)
            .await
            .map(|_| ())
        })
        .await
    }

    async fn find(
        &self,
        from: &TenantId,
        domain: &DomainName,
    ) -> Result<Option<HandoverOffer>, DomainError> {
        let record = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_as!(
                OfferRecord,
                "queries/domain_handover_offers/find.sql",
                from.as_uuid(),
                domain.as_str()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record.map(OfferRecord::into_offer).transpose()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::custom_domains::handover_offer::{
        HandoverOfferRow, HandoverOfferState,
    };

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::domain::{domain_name, handover_offer_row, saved_tenant};

    struct Fixture {
        database: TestDb,
        store: PgHandoverOfferStore,
        from: TenantId,
        to: TenantId,
    }

    /// A fresh database, two saved tenants, and the store on it.
    async fn fixture() -> Fixture {
        let database = TestDb::fresh().await;
        let from = *saved_tenant(&database.databases).await;
        let to = *saved_tenant(&database.databases).await;
        Fixture {
            store: PgHandoverOfferStore::new(Arc::clone(&database.databases)),
            database,
            from,
            to,
        }
    }

    fn offer(row: HandoverOfferRow) -> HandoverOffer {
        HandoverOffer::reconstitute(row).unwrap()
    }

    /// A saved offer is found by its giving tenant and its domain; the
    /// receiving tenant, or another domain, finds nothing under that key.
    #[tokio::test]
    async fn a_saved_offer_is_found_by_its_giver_and_domain() {
        let db = fixture().await;
        let made = offer(handover_offer_row(db.from, db.to, "login.acme.example"));

        db.store.save(&made).await.unwrap();

        let found = db
            .store
            .find(&db.from, made.domain())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.to(), &db.to);
        assert_eq!(found.offered_at(), made.offered_at());
        assert_eq!(found.state(), HandoverOfferState::Waiting);
        assert!(
            db.store
                .find(&db.to, made.domain())
                .await
                .unwrap()
                .is_none()
        );
        let other = domain_name("shop.acme.example");
        assert!(db.store.find(&db.from, &other).await.unwrap().is_none());
    }

    /// An accepted offer is kept spent, so it is never accepted twice.
    #[tokio::test]
    async fn an_accepted_offer_is_kept_spent() {
        let db = fixture().await;
        db.store
            .save(&offer(handover_offer_row(
                db.from,
                db.to,
                "login.acme.example",
            )))
            .await
            .unwrap();
        let spent = offer(HandoverOfferRow {
            state: HandoverOfferState::Accepted { at: at(60) },
            ..handover_offer_row(db.from, db.to, "login.acme.example")
        });

        db.store.save(&spent).await.unwrap();

        let found = db.store.find(&db.from, spent.domain()).await.unwrap();
        assert_eq!(
            found.unwrap().state(),
            HandoverOfferState::Accepted { at: at(60) }
        );
    }

    /// A new offer of the same domain replaces the giver's earlier one, so
    /// a domain is offered to one tenant at a time.
    #[tokio::test]
    async fn a_new_offer_replaces_the_earlier_one() {
        let db = fixture().await;
        db.store
            .save(&offer(handover_offer_row(
                db.from,
                db.to,
                "login.acme.example",
            )))
            .await
            .unwrap();
        let third = *saved_tenant(&db.database.databases).await;
        let again = offer(HandoverOfferRow {
            offered_at: at(100),
            ..handover_offer_row(db.from, third, "login.acme.example")
        });

        db.store.save(&again).await.unwrap();

        let found = db
            .store
            .find(&db.from, again.domain())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.to(), &third);
        assert_eq!(found.offered_at(), at(100));
    }

    /// A handover offer stored as accepted eight days after it was offered
    /// fails to load as corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_offer_is_refused() {
        let db = fixture().await;
        let made = offer(handover_offer_row(db.from, db.to, "login.acme.example"));
        db.store.save(&made).await.unwrap();
        db.database
            .tamper(
                "ALTER TABLE domain_handover_offers \
                     DROP CONSTRAINT domain_handover_offers_accepted_in_time; \
                 UPDATE domain_handover_offers SET accepted_at = offered_at + interval '8 days'",
            )
            .await;

        let found = db.store.find(&db.from, made.domain()).await;

        assert!(matches!(found, Err(DomainError::Infrastructure(_))));
    }
}

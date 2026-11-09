//! The payment provider's events the platform acted on, kept in the
//! platform database: each event by the provider's id, so a repeated
//! delivery is acted on once, and per organization the newest event of
//! each kind applied, so a late event cannot undo a newer one.
//!
//! An event is kept for [`KEPT_FOR`], well past the days a provider
//! retries a delivery; taking an event lets go of the organization's older
//! ones. The newest applied of each kind is kept for good, one row per
//! organization and kind, so even an event delivered again after it was let
//! go cannot undo a newer one.

mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::organization::{
    EventOrder, EventReceipt, PaymentEvent, PaymentEventLedger, PaymentStream,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::OrganizationId;
use time::Duration;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::stored::StoredWord as _;
use crate::postgres::foundation::unit::scoped;

/// How long a taken event is kept, against deliveries repeated late.
const KEPT_FOR: Duration = Duration::days(30);

/// The Postgres ledger of the payment provider's events.
pub struct PgPaymentEventLedger {
    databases: Arc<Databases>,
}

impl PgPaymentEventLedger {
    /// A ledger kept in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl PaymentEventLedger for PgPaymentEventLedger {
    async fn receive(
        &self,
        organization_id: &OrganizationId,
        event: &PaymentEvent,
    ) -> Result<EventReceipt, DomainError> {
        let now = clock::now();
        let first = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_scalar!(
                "queries/payment_events/receive.sql",
                event.id.as_str(),
                organization_id.as_uuid(),
                event.created_at,
                now,
                now.saturating_sub(KEPT_FOR)
            )
            .fetch_one(connection)
            .await
        })
        .await?;
        if !first {
            return Ok(EventReceipt::Repeated);
        }
        Ok(EventReceipt::First)
    }

    async fn advance(
        &self,
        organization_id: &OrganizationId,
        stream: PaymentStream,
        event: &PaymentEvent,
    ) -> Result<EventOrder, DomainError> {
        let newest = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_scalar!(
                "queries/payment_event_marks/advance.sql",
                organization_id.as_uuid(),
                stream.word(),
                event.created_at
            )
            .fetch_one(connection)
            .await
        })
        .await?;
        if !newest {
            return Ok(EventOrder::Stale);
        }
        Ok(EventOrder::Newest)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::organization::OrganizationStore;
    use ianua_app::test_support::organization::test_payment_event;
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::shared::config::DomainLimits;

    use super::*;
    use crate::postgres::organization::PgOrganizationStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::organization::organization_row;

    /// A fresh database with Acme saved, and the ledger on it.
    async fn fixture() -> (TestDb, PgPaymentEventLedger, OrganizationId) {
        let db = TestDb::fresh().await;
        let organization = Organization::reconstitute(organization_row("acme", "acme")).unwrap();
        PgOrganizationStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&organization)
            .await
            .unwrap();
        let ledger = PgPaymentEventLedger::new(Arc::clone(&db.databases));
        (db, ledger, *organization.id())
    }

    /// Concurrent receipts of the same payment event produce one first
    /// receipt and one repeat; a later receipt is also a repeat.
    #[tokio::test]
    async fn an_event_delivered_twice_is_taken_once() {
        let (_db, ledger, acme) = fixture().await;
        let event = test_payment_event("evt_1", clock::now());

        let (one, two) = tokio::join!(ledger.receive(&acme, &event), ledger.receive(&acme, &event));
        let again = ledger.receive(&acme, &event).await.unwrap();

        let mut receipts = [one.unwrap(), two.unwrap()];
        receipts.sort_by_key(|receipt| *receipt == EventReceipt::Repeated);
        assert_eq!(receipts, [EventReceipt::First, EventReceipt::Repeated]);
        assert_eq!(again, EventReceipt::Repeated);
    }

    /// An older payment event is stale after a newer one advances the
    /// ledger, while the method stream advances independently and a later
    /// payment event is accepted as newest.
    #[tokio::test]
    async fn an_event_older_than_the_newest_applied_is_stale() {
        let (_db, ledger, acme) = fixture().await;
        let paid_at = clock::now();
        let paid = test_payment_event("evt_paid", paid_at);
        let late = test_payment_event("evt_late", paid_at - Duration::minutes(1));
        let later = test_payment_event("evt_later", paid_at + Duration::minutes(1));

        let first = ledger.advance(&acme, PaymentStream::Payment, &paid).await;
        let stale = ledger.advance(&acme, PaymentStream::Payment, &late).await;
        let method = ledger.advance(&acme, PaymentStream::Method, &late).await;
        let newer = ledger.advance(&acme, PaymentStream::Payment, &later).await;

        assert_eq!(first.unwrap(), EventOrder::Newest);
        assert_eq!(stale.unwrap(), EventOrder::Stale);
        assert_eq!(method.unwrap(), EventOrder::Newest);
        assert_eq!(newer.unwrap(), EventOrder::Newest);
    }
}

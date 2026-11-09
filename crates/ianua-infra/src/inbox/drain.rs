//! The drain of the gateway's inbox into the audit trail, for the worker.
//!
//! Each pass takes the oldest events of each database's inbox, locked so
//! two drains never take the same ones, and in one transaction checks
//! each one's seal and type again, appends those that hold to their
//! tenant's trail through the dispatcher it was given, so each gets its
//! chain link and its outbox row, and removes every one it took. One whose
//! seal or type does not hold is removed and logged, never appended. A
//! pass that fails to append rolls back whole: its events stay in the
//! inbox for the next pass, so none is lost and none is appended twice.

use std::num::NonZeroU32;
use std::sync::Arc;

use futures_util::future::try_join_all;
use ianua_app::ports::runtime::{Settlement, atomically};
use ianua_app::ports::shared::EventDispatcher;
use ianua_domain::domains::audit::builder::read_back;
use ianua_domain::shared::errors::DomainError;
use uuid::Uuid;

use crate::crypto::EventSeal;
use crate::inbox::record::{Opened, PendingRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::{PgUnitOfWork, scoped};

/// What one pass did with the events it took.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Drained {
    /// Events appended to their tenants' trails.
    pub appended: u64,
    /// Events removed unappended: their seal or their type did not hold, or
    /// they did not read.
    pub dropped: u64,
}

impl Drained {
    const ONE_APPENDED: Self = Self {
        appended: 1,
        dropped: 0,
    };

    const ONE_DROPPED: Self = Self {
        appended: 0,
        dropped: 1,
    };

    /// Whether the pass took anything.
    #[must_use]
    pub fn took_any(self) -> bool {
        self.appended > 0 || self.dropped > 0
    }

    fn and(self, other: Self) -> Self {
        Self {
            appended: self.appended.saturating_add(other.appended),
            dropped: self.dropped.saturating_add(other.dropped),
        }
    }
}

/// The drain of the gateway's inbox into the audit trail.
pub struct InboxDrain {
    databases: Arc<Databases>,
    trail: Arc<dyn EventDispatcher>,
    seal: EventSeal,
}

impl std::fmt::Debug for InboxDrain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboxDrain").finish_non_exhaustive()
    }
}

impl InboxDrain {
    /// A drain of the inboxes in `databases` into `trail`, which must keep
    /// its records in those same databases, so each event is appended and
    /// removed in one transaction, checking each with `seal`, the data
    /// plane's.
    #[must_use]
    pub fn new(
        databases: Arc<Databases>,
        trail: Arc<dyn EventDispatcher>,
        seal: EventSeal,
    ) -> Self {
        Self {
            databases,
            trail,
            seal,
        }
    }

    /// Drains at most `batch` events of each place events are kept, and
    /// answers what it did with them.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when an inbox cannot be read,
    /// or an event cannot be appended or removed. What that database's pass
    /// took stays in its inbox.
    pub async fn pass(&self, batch: NonZeroU32) -> Result<Drained, DomainError> {
        let limit = i64::from(batch.get());
        let apart = self
            .databases
            .with_own_database()
            .into_iter()
            .map(|tenant| self.drained(RowScope::Tenant(tenant), limit));
        let (shared, apart) =
            futures_util::try_join!(self.drained(RowScope::Platform, limit), try_join_all(apart),)?;
        Ok(apart.into_iter().fold(shared, Drained::and))
    }

    /// Drains the events kept where `scope` reads, in one unit of work.
    async fn drained(&self, scope: RowScope, limit: i64) -> Result<Drained, DomainError> {
        atomically(&PgUnitOfWork, self.drain(scope, limit), |done| match done {
            Ok(_) => Settlement::Commit,
            Err(_) => Settlement::Rollback,
        })
        .await?
    }

    /// Takes the oldest events kept where `scope` reads, appends those that
    /// hold, and removes every one taken.
    ///
    /// Each append holds its tenant's chain lock until the pass commits, so
    /// the events are appended tenant by tenant in one order, each tenant's
    /// in the order written: two drains then take the locks in the same
    /// order and never wait on each other in a circle.
    async fn drain(&self, scope: RowScope, limit: i64) -> Result<Drained, DomainError> {
        let mut pending = scoped(&self.databases, scope, async |connection| {
            sqlx::query_file_as!(PendingRecord, "queries/gateway_events/pending.sql", limit)
                .fetch_all(connection)
                .await
        })
        .await?;
        pending.sort_by_key(|row| row.tenant_id);
        let mut drained = Drained::default();
        let mut tenants = Vec::with_capacity(pending.len());
        let mut taken = Vec::with_capacity(pending.len());
        for row in pending {
            tenants.push(row.tenant_id);
            taken.push(row.id);
            drained = drained.and(self.settled(row).await?);
        }
        self.remove(scope, &tenants, &taken).await?;
        Ok(drained)
    }

    /// Appends `row`'s event to its tenant's trail when its seal and type
    /// hold, and answers which it was: appended, or dropped.
    async fn settled(&self, row: PendingRecord) -> Result<Drained, DomainError> {
        let (id, tenant) = (row.id, row.tenant_id);
        match row.opened(&self.seal) {
            Ok(opened) => {
                self.append(opened).await?;
                Ok(Drained::ONE_APPENDED)
            }
            Err(why) => {
                tracing::warn!(event = %id, %tenant, reason = %why, "a gateway event was dropped unappended");
                Ok(Drained::ONE_DROPPED)
            }
        }
    }

    /// Appends the event `opened` holds to its tenant's trail, in the
    /// context the gateway recorded it in.
    // The drain hands the trail the context the gateway's own
    // `RequestAuditor` bound at its boundary, read back from the sealed
    // entry; it makes no context of its own. See clippy.toml's
    // `disallowed-methods`.
    #[allow(clippy::disallowed_methods)]
    async fn append(&self, opened: Opened) -> Result<(), DomainError> {
        let read = read_back(&opened.record, opened.origin);
        self.trail.dispatch(&[read.event], &read.context).await
    }

    /// Removes the events `taken` of `tenants` from the inbox where `scope`
    /// reads.
    async fn remove(
        &self,
        scope: RowScope,
        tenants: &[Uuid],
        taken: &[Uuid],
    ) -> Result<(), DomainError> {
        if taken.is_empty() {
            return Ok(());
        }
        scoped(&self.databases, scope, async |connection| {
            sqlx::query_file!("queries/gateway_events/remove.sql", tenants, taken)
                .execute(connection)
                .await
                .map(|_| ())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    // The tests record through the inbox's dispatcher straight, as the
    // gateway's `RequestAuditor` would, since no use case is under test.
    #![allow(clippy::disallowed_methods)]

    use ianua_app::tenancy::ScopedTenant;
    use ianua_domain::domains::audit::builder::AuditContext;
    use ianua_domain::domains::proxy::events::HoneypotHit;
    use ianua_domain::shared::events::event::DomainEvent;
    use ianua_domain::test_support::events::sample_tenant_event;
    use ianua_domain::types::event_type::ProxyEvent;
    use ianua_domain::types::{CorrelationId, EventType, Fact, IpAddress, TenantId, UntrustedText};

    use super::*;
    use crate::bus::{HeardEvent, HeardEvents, MemoryBus, Published};
    use crate::crypto::keys::tests::test_root;
    use crate::crypto::{EventCheck, RootSecret, raised_by_the_data_plane};
    use crate::inbox::InboxEventDispatcher;
    use crate::outbox::OutboxRelay;
    use crate::postgres::audit::PgEventDispatcher;
    use crate::postgres::shared::PgRecordedEvents;
    use crate::test_support::TestDb;
    use crate::test_support::rows::audit::{chain_heads, saved_organization, saved_tenant_of};

    const ADDRESS: &str = "203.0.113.9";

    struct Fixture {
        db: TestDb,
        tenant: ScopedTenant,
    }

    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        Fixture { db, tenant }
    }

    fn gateway_seal() -> EventSeal {
        EventSeal::data_plane(&test_root())
    }

    fn control_plane() -> EventSeal {
        EventSeal::control_plane(&test_root())
    }

    fn most(limit: u32) -> NonZeroU32 {
        NonZeroU32::new(limit).unwrap()
    }

    fn honeypot_hit(tenant: TenantId) -> DomainEvent {
        HoneypotHit::observed(
            tenant,
            IpAddress::new(ADDRESS).unwrap(),
            UntrustedText::record("/wp-admin"),
            CorrelationId::new(),
        )
    }

    impl Fixture {
        /// The gateway's dispatcher, signed in as the gateway's role,
        /// sealing with `seal`.
        fn inbox(&self, seal: EventSeal) -> InboxEventDispatcher {
            InboxEventDispatcher::new(Arc::clone(&self.db.gateway), seal)
        }

        /// The worker's drain on `databases`, into the trail there.
        fn drain_on(&self, databases: &Arc<Databases>) -> InboxDrain {
            let trail = PgEventDispatcher::new(Arc::clone(databases), chain_heads());
            InboxDrain::new(Arc::clone(databases), Arc::new(trail), gateway_seal())
        }

        fn drain(&self) -> InboxDrain {
            self.drain_on(&self.db.databases)
        }

        /// Checks the relayed event through the worker's verifier and retains its gateway context.
        async fn assert_honeypot_record(&self, event: Published) {
            let heard = HeardEvents::new(
                EventCheck::new(control_plane(), gateway_seal()),
                Arc::new(PgRecordedEvents::new(Arc::clone(&self.db.databases))),
            );
            let read = heard
                .published(&HeardEvent {
                    subject: event.subject,
                    payload: event.payload,
                    seal: Some(event.seal),
                })
                .await
                .unwrap()
                .unwrap();
            let record = read.record();
            assert_eq!(record.event_type, EventType::Proxy(ProxyEvent::HoneypotHit));
            assert_eq!(
                record.ip_address,
                Fact::Known(IpAddress::new(ADDRESS).unwrap())
            );
        }

        /// Relays the outbox to a bus of its own, and answers what went out.
        async fn relayed(&self) -> Vec<Published> {
            let bus = Arc::new(MemoryBus::new(100));
            OutboxRelay::new(Arc::clone(&self.db.databases), bus.clone(), control_plane())
                .pass(most(100))
                .await
                .unwrap();
            bus.published()
        }

        /// Puts a row in the inbox as the app's role, past the dispatcher,
        /// typed `event_type`, and answers whether the table took it.
        async fn planted(&self, event_type: &str) -> bool {
            let tenant = *self.tenant.as_uuid();
            scoped(
                &self.db.databases,
                RowScope::Tenant(*self.tenant),
                async |connection| {
                    sqlx::query(
                        "INSERT INTO gateway_events \
                         (id, tenant_id, event_type, subject, payload, seal, occurred_at, written_at) \
                         VALUES (gen_random_uuid(), $1, $2, 'subject', '{}', 'seal', now(), now())",
                    )
                    .bind(tenant)
                    .bind(event_type)
                    .execute(connection)
                    .await
                },
            )
            .await
            .is_ok()
        }
    }

    /// A honeypot hit the gateway recorded is appended to the tenant's
    /// trail once, queued in the outbox once, and leaves the inbox: the
    /// worker hears it as the gateway recorded it, address and all.
    #[tokio::test]
    async fn an_inbox_event_lands_once_on_the_trail_and_in_the_outbox() {
        let fx = fixture().await;
        let at_the_gateway = AuditContext::system()
            .with_request(Fact::Known(IpAddress::new(ADDRESS).unwrap()), Fact::Unknown);
        fx.inbox(gateway_seal())
            .dispatch(&[honeypot_hit(*fx.tenant)], &at_the_gateway)
            .await
            .unwrap();

        let first = fx.drain().pass(most(10)).await.unwrap();
        let again = fx.drain().pass(most(10)).await.unwrap();

        assert_eq!(first, Drained::ONE_APPENDED);
        assert_eq!(again, Drained::default());
        let published = fx.relayed().await;
        assert_eq!(published.len(), 1);
        let event = published.into_iter().next().unwrap();
        fx.assert_honeypot_record(event).await;
    }

    /// Draining an event with a forged seal counts it as dropped, leaves nothing
    /// for the next pass and produces no relayed event.
    #[tokio::test]
    async fn a_forged_seal_is_dropped() {
        let fx = fixture().await;
        let forger = EventSeal::data_plane(&RootSecret::parse(&"cd".repeat(32)).unwrap());
        fx.inbox(forger)
            .dispatch(&[honeypot_hit(*fx.tenant)], &AuditContext::system())
            .await
            .unwrap();

        let first = fx.drain().pass(most(10)).await.unwrap();
        let again = fx.drain().pass(most(10)).await.unwrap();

        assert_eq!(first, Drained::ONE_DROPPED);
        assert_eq!(again, Drained::default());
        assert!(fx.relayed().await.is_empty());
    }

    /// Dispatching a permitted event together with a forbidden event fails and
    /// leaves the inbox empty.
    #[tokio::test]
    async fn an_event_the_gateway_does_not_raise_is_refused_at_write() {
        let fx = fixture().await;

        let refused = fx
            .inbox(gateway_seal())
            .dispatch(
                &[honeypot_hit(*fx.tenant), sample_tenant_event(*fx.tenant)],
                &AuditContext::system(),
            )
            .await;

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(fx.drain().pass(most(10)).await.unwrap(), Drained::default());
    }

    /// Direct inserts into the inbox accept exactly the event types the data
    /// plane may raise.
    #[tokio::test]
    async fn the_inbox_holds_only_the_types_the_data_plane_raises() {
        let fx = fixture().await;

        for event_type in EventType::all() {
            let taken = fx.planted(event_type.as_str()).await;

            assert_eq!(
                taken,
                raised_by_the_data_plane(event_type),
                "{}",
                event_type.as_str()
            );
        }
    }

    /// Two concurrent drains append six queued events in total and produce six
    /// relayed events.
    #[tokio::test]
    async fn two_drains_at_once_append_each_event_once() {
        let fx = fixture().await;
        let events: Vec<DomainEvent> = (0..6).map(|_| honeypot_hit(*fx.tenant)).collect();
        fx.inbox(gateway_seal())
            .dispatch(&events, &AuditContext::system())
            .await
            .unwrap();
        let other_node = fx.db.another_node();
        let (one, two) = (fx.drain(), fx.drain_on(&other_node));

        let (by_one, by_two) = tokio::join!(drained_dry(&one), drained_dry(&two));

        assert_eq!(by_one.saturating_add(by_two), 6);
        assert_eq!(fx.relayed().await.len(), 6);
    }

    /// Drains in passes of two until a pass takes nothing, and answers how
    /// many events it appended.
    async fn drained_dry(drain: &InboxDrain) -> u64 {
        let mut appended = 0;
        loop {
            let pass = drain.pass(most(2)).await.unwrap();
            if !pass.took_any() {
                return appended;
            }
            appended += pass.appended;
        }
    }
}

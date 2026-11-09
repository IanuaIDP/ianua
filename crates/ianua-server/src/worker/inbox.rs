//! The drain of the gateway's inbox: every event the gateway kept goes on
//! its tenant's audit trail once the worker has checked it.
//!
//! Each pass takes the oldest events of every database's inbox, locked so
//! two workers' drains never take the same ones, checks each one's seal
//! against the data plane's and its type against those the gateway may
//! raise, appends those that hold through the trail's dispatcher, so each
//! gets its chain link and its outbox row, and removes every one it took,
//! in one transaction. An event that does not hold is dropped, counted
//! and logged, never appended. A pass that took anything is followed by
//! another at once, so a backlog drains; one that took nothing waits for
//! the interval. A pass that fails rolls back whole, so its events stay
//! in the inbox for the next and none is lost or appended twice.

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use ianua_boot::shutdown::Shutdown;
use ianua_infra::inbox::{Drained, InboxDrain};

use crate::config::Config;
use crate::platform::Platform;

/// Starts the drain of the gateway's inbox into the trail.
pub(super) fn start(platform: &Platform, config: &Config, shutdown: &Shutdown) {
    let events = &config.worker.events;
    let drain = Drain {
        inbox: InboxDrain::new(
            Arc::clone(&platform.databases),
            Arc::clone(&platform.event_dispatcher),
            platform.keys.data_plane_seal.clone(),
        ),
        batch: events.inbox_batch,
        every: events.inbox_interval,
    };
    shutdown.spawn("the gateway's inbox drain", drain.run(shutdown.clone()));
}

/// The drain's loop.
struct Drain {
    inbox: InboxDrain,
    batch: NonZeroU32,
    every: Duration,
}

impl Drain {
    /// Drains until `shutdown` stops it. A pass under way when the stop
    /// comes finishes: it commits whole or leaves its events for the next
    /// start.
    async fn run(self, shutdown: Shutdown) {
        while !shutdown.is_stopping() {
            if self.drained().await.took_any() {
                continue;
            }
            tokio::select! {
                () = shutdown.stopping() => return,
                () = tokio::time::sleep(self.every) => {}
            }
        }
    }

    /// Runs one pass and answers what it did, nothing when it failed.
    async fn drained(&self) -> Drained {
        match self.inbox.pass(self.batch).await {
            Ok(drained) => noted(drained),
            Err(error) => {
                tracing::warn!(
                    %error,
                    "the gateway's inbox could not be drained; the drain tries again"
                );
                Drained::default()
            }
        }
    }
}

/// Logs what a pass did, a drop loudly, and answers it.
fn noted(drained: Drained) -> Drained {
    if drained.dropped > 0 {
        tracing::warn!(
            dropped = drained.dropped,
            appended = drained.appended,
            "gateway events were dropped unappended: their seal or their type did not hold"
        );
    }
    if drained.appended > 0 {
        tracing::debug!(
            appended = drained.appended,
            "gateway events appended to the trail"
        );
    }
    drained
}

#[cfg(test)]
mod tests {
    // The tests record straight through the gateway's dispatcher, as the
    // gateway's `RequestAuditor` would, since no use case is under test.
    #![allow(clippy::disallowed_methods)]

    use ianua_app::ports::shared::EventDispatcher;
    use ianua_domain::domains::audit::builder::AuditContext;
    use ianua_domain::domains::proxy::events::HoneypotHit;
    use ianua_domain::types::{CorrelationId, IpAddress, UntrustedText};
    use ianua_infra::bus::MemoryBus;
    use ianua_infra::crypto::{EventSeal, RootSecret};
    use ianua_infra::inbox::InboxEventDispatcher;
    use ianua_infra::outbox::OutboxRelay;
    use ianua_infra::postgres::Databases;
    use ianua_infra::postgres::audit::PgEventDispatcher;
    use ianua_infra::test_support::TestDb;
    use ianua_infra::test_support::rows::audit::{
        chain_heads, saved_organization, saved_tenant_of,
    };

    use super::*;

    /// The root the platform and its gateway share in these tests.
    fn shared_root() -> RootSecret {
        RootSecret::parse(&format!("{:064x}", 1)).unwrap()
    }

    /// The drain of the inboxes `databases` holds into their trail,
    /// checking against the shared root's data plane seal.
    fn drain_on(databases: &Arc<Databases>) -> Drain {
        let trail = PgEventDispatcher::new(Arc::clone(databases), chain_heads());
        Drain {
            inbox: InboxDrain::new(
                Arc::clone(databases),
                Arc::new(trail),
                EventSeal::data_plane(&shared_root()),
            ),
            batch: NonZeroU32::MIN,
            every: Duration::from_secs(1),
        }
    }

    /// Keeps a honeypot hit of a fresh tenant in the inbox, as the gateway
    /// does, sealed with `seal`.
    async fn kept_honeypot_hit(db: &TestDb, seal: EventSeal) {
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        let hit = HoneypotHit::observed(
            *tenant,
            IpAddress::new("203.0.113.9").unwrap(),
            UntrustedText::record("/wp-admin"),
            CorrelationId::new(),
        );
        InboxEventDispatcher::new(Arc::clone(&db.gateway), seal)
            .dispatch(&[hit], &AuditContext::system())
            .await
            .unwrap();
    }

    /// Relays the outbox to a bus of its own, and answers how many events
    /// went out.
    async fn relayed(db: &TestDb) -> usize {
        let bus = Arc::new(MemoryBus::new(100));
        let control = RootSecret::parse(&format!("{:064x}", 2)).unwrap();
        OutboxRelay::new(
            Arc::clone(&db.databases),
            Arc::clone(&bus) as _,
            EventSeal::control_plane(&control),
        )
        .pass(NonZeroU32::new(100).unwrap())
        .await
        .unwrap();
        bus.published().len()
    }

    /// A honeypot hit the gateway sealed is appended to its tenant's trail
    /// on the drain's first pass and leaves the inbox, so the next pass
    /// takes nothing and the outbox holds it once.
    #[tokio::test]
    async fn a_sealed_gateway_event_is_appended_once_and_leaves_the_inbox() {
        let db = TestDb::fresh().await;
        kept_honeypot_hit(&db, EventSeal::data_plane(&shared_root())).await;
        let drain = drain_on(&db.databases);

        let first = drain.drained().await;
        let again = drain.drained().await;

        assert_eq!((first.appended, first.dropped), (1, 0));
        assert_eq!(again, Drained::default());
        assert_eq!(relayed(&db).await, 1);
    }

    /// A honeypot hit sealed with another root is counted as dropped rather
    /// than appended. The next drain finds nothing and the outbox relays
    /// no event.
    #[tokio::test]
    async fn a_forged_gateway_event_is_dropped() {
        let db = TestDb::fresh().await;
        let forger = RootSecret::parse(&"cd".repeat(32)).unwrap();
        kept_honeypot_hit(&db, EventSeal::data_plane(&forger)).await;
        let drain = drain_on(&db.databases);

        let first = drain.drained().await;
        let again = drain.drained().await;

        assert_eq!((first.appended, first.dropped), (0, 1));
        assert_eq!(again, Drained::default());
        assert_eq!(relayed(&db).await, 0);
    }
}

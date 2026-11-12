//! The outbox relay: every event a change recorded goes out on the bus,
//! sealed by the control plane, once the change committed.
//!
//! Each pass takes the oldest queued records of every database, locked so
//! two workers' relays never take the same ones, publishes each under its
//! record's id, so the bus keeps one copy of a record published twice, and
//! removes those the bus took. A pass that sent anything is followed by
//! another at once, so a backlog drains; one that sent nothing waits for
//! the relay interval, or until the event channel says events wait,
//! whichever comes first. A bus that is down delays events and loses none:
//! they stay queued until it takes them.

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use ianua_boot::shutdown::Shutdown;
use ianua_infra::outbox::OutboxRelay;
use ianua_infra::postgres::foundation::workers::announcements::{
    Announcements, Channel, wait_for_announcement,
};
use tokio::sync::watch;

use crate::config::Config;
use crate::platform::Platform;

/// Starts the relay of the outboxes to the bus, woken by `announcements`
/// of events recorded as well as by its interval.
pub(super) fn start(
    platform: &Platform,
    config: &Config,
    announcements: &Announcements,
    shutdown: &Shutdown,
) {
    let events = &config.worker.events;
    let relay = Relay {
        outbox: OutboxRelay::new(
            Arc::clone(&platform.databases),
            Arc::clone(&platform.bus),
            platform.keys.event_seal.clone(),
        ),
        batch: events.relay_batch,
        every: events.relay_interval,
        recorded: announcements.watch(Channel::Events),
    };
    shutdown.spawn("the outbox relay", relay.run(shutdown.clone()));
}

/// The relay's loop.
struct Relay {
    outbox: OutboxRelay,
    batch: NonZeroU32,
    every: Duration,
    /// How many recordings the event channel announced.
    recorded: watch::Receiver<u64>,
}

impl Relay {
    /// Relays until `shutdown` stops it. A pass under way when the stop
    /// comes finishes: what it published and did not yet remove goes out
    /// again on the next start, and the bus keeps one copy. Events
    /// recorded during a pass wake the relay as soon as the pass ends.
    async fn run(mut self, shutdown: Shutdown) {
        while !shutdown.is_stopping() {
            self.recorded.borrow_and_update();
            if self.passed().await {
                continue;
            }
            tokio::select! {
                () = shutdown.stopping() => return,
                () = tokio::time::sleep(self.every) => {}
                () = wait_for_announcement(&mut self.recorded) => {}
            }
        }
    }

    /// Runs one pass, and answers whether it sent anything.
    async fn passed(&self) -> bool {
        match self.outbox.pass(self.batch).await {
            Ok(0) => false,
            Ok(sent) => {
                tracing::debug!(sent, "events relayed to the bus");
                true
            }
            Err(error) => {
                tracing::warn!(%error, "the outbox could not be read; the relay tries again");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // The test records an event straight through the dispatcher to fill the
    // outbox the relay reads, as no use case is under test here.
    #![allow(clippy::disallowed_methods)]

    use ianua_app::ports::shared::EventDispatcher;
    use ianua_domain::domains::audit::builder::AuditContext;
    use ianua_infra::bus::MemoryBus;
    use ianua_infra::crypto::{EventSeal, RootSecret};
    use ianua_infra::postgres::audit::PgEventDispatcher;
    use ianua_infra::test_support::TestDb;
    use ianua_infra::test_support::rows::audit::{
        chain_heads, failed_sign_in, saved_organization, saved_tenant_of,
    };

    use super::*;

    /// A failed sign-in recorded by one of Acme's tenants goes out on the
    /// bus on the relay's first pass and leaves the outbox, so the next
    /// pass sends nothing and waits.
    #[tokio::test]
    async fn the_relay_publishes_and_removes_what_it_sent() {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        PgEventDispatcher::new(Arc::clone(&db.databases), chain_heads())
            .dispatch(&[failed_sign_in(*tenant, 1)], &AuditContext::system())
            .await
            .unwrap();
        let bus = Arc::new(MemoryBus::new(100));
        let root = RootSecret::parse(&format!("{:064x}", 2)).unwrap();
        let relay = Relay {
            outbox: OutboxRelay::new(
                Arc::clone(&db.databases),
                Arc::clone(&bus) as _,
                EventSeal::control_plane(&root),
            ),
            batch: NonZeroU32::MIN,
            every: Duration::from_secs(1),
            recorded: Announcements::new().watch(Channel::Events),
        };

        let first = relay.passed().await;
        let second = relay.passed().await;

        assert!(first);
        assert!(!second);
        assert_eq!(bus.published().len(), 1);
    }
}

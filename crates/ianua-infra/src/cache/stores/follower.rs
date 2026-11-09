//! Every node's reader of the events stream for its store caches: each
//! event whose seal holds is applied, so the caches it touches drop the
//! owner's entries here and raise the owner's versions.
//!
//! Only a sealed event counts: one with no seal, or a seal the event check
//! refuses, as a data plane's seal on a tenant's deletion, is dropped
//! unread. A sealed event of a type this node does not know, as a newer
//! node may raise, touches every cache of its owner; one whose record does
//! not read back drops every entry here. Whenever events may have gone by
//! unheard, the follower fell behind or the feed was lost, every entry here
//! is dropped, since what a missed event should have dropped cannot be
//! known. The node that made a change has applied it already when its
//! event comes back; applying it again only raises the version once more.

use std::sync::Arc;
use std::time::Duration;

use ianua_domain::types::EventType;

use crate::bus::{Bus, EventEnvelope, EventFeed, Heard, HeardEvent};
use crate::cache::stores::invalidation::{Change, StoreCaches};
use crate::cache::stores::owners::Owner;
use crate::crypto::EventCheck;

/// How long the follower waits before following again once the feed is
/// lost or cannot be opened.
const RETRY: Duration = Duration::from_secs(1);

/// The follower of the events stream for one node's store caches.
pub struct StoreCacheFollower {
    bus: Arc<dyn Bus>,
    check: EventCheck,
    caches: Arc<StoreCaches>,
}

impl std::fmt::Debug for StoreCacheFollower {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreCacheFollower").finish_non_exhaustive()
    }
}

impl StoreCacheFollower {
    /// A follower of `bus`, applying to `caches` the events `check` finds
    /// sealed by a publisher that may raise them.
    #[must_use]
    pub fn new(bus: Arc<dyn Bus>, check: EventCheck, caches: Arc<StoreCaches>) -> Self {
        Self { bus, check, caches }
    }

    /// Follows the events for as long as the node runs, following again
    /// whenever the feed is lost. Spawn it once per node.
    pub async fn run(self) {
        loop {
            self.follow_once().await;
            self.caches.forget_everything_here();
            tokio::time::sleep(RETRY).await;
        }
    }

    /// Opens a feed and applies what it hears until it ends.
    async fn follow_once(&self) {
        let feed = match self.bus.follow().await {
            Ok(feed) => feed,
            Err(error) => {
                tracing::warn!(%error, "the store caches cannot follow the events; retrying");
                return;
            }
        };
        self.caches.forget_everything_here();
        self.drain(feed).await;
        tracing::warn!("the store caches lost the events feed; following again");
    }

    /// Applies everything `feed` hears, until it ends.
    async fn drain(&self, mut feed: Box<dyn EventFeed>) {
        while let Some(heard) = feed.next().await {
            match heard {
                Heard::Event(event) => self.heard(&event).await,
                Heard::Missed => self.caches.forget_everything_here(),
            }
        }
    }

    /// Applies `event` when its seal holds.
    async fn heard(&self, event: &HeardEvent) {
        let Some(seal) = event.seal.as_deref() else {
            return;
        };
        if !self.check.holds(&event.subject, &event.payload, seal) {
            tracing::warn!("an event whose seal does not hold was left unapplied");
            return;
        }
        let Ok(envelope) = serde_json::from_slice::<EventEnvelope>(&event.payload) else {
            self.caches.forget_everything_here();
            return;
        };
        let owner = Owner::from(envelope.scope);
        match EventType::parse(&envelope.event_type) {
            Some(event_type) => self.caches.apply(Change::of(event_type, owner)).await,
            None => self.caches.apply_unknown(owner).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::*;
    use crate::bus::{EventScope, MemoryBus, SealedEvent};
    use crate::cache::MemoryState;
    use crate::cache::stores::entries::{Entries, EntryKeeping};
    use crate::cache::stores::owners::Owners;
    use crate::cache::stores::versions::Cached;
    use crate::crypto::EventSeal;
    use crate::crypto::keys::tests::test_root;

    struct Node {
        bus: Arc<MemoryBus>,
        callers: Arc<Entries<&'static str, u8>>,
        follower: StoreCacheFollower,
    }

    fn node() -> Node {
        let caches = Arc::new(StoreCaches::new(
            Arc::new(MemoryState::new(100)),
            Duration::from_secs(60),
        ));
        let callers = caches.entries(
            Cached::Callers,
            EntryKeeping {
                lifetime: Duration::from_secs(60),
                capacity: 100,
            },
        );
        let bus = Arc::new(MemoryBus::new(100));
        let check = EventCheck::new(
            EventSeal::control_plane(&test_root()),
            EventSeal::data_plane(&test_root()),
        );
        Node {
            follower: StoreCacheFollower::new(bus.clone(), check, caches),
            bus,
            callers,
        }
    }

    fn deleted(tenant: Uuid) -> (String, Vec<u8>) {
        let envelope = EventEnvelope {
            id: Uuid::now_v7(),
            scope: EventScope::Tenant(tenant),
            organization_id: None,
            event_type: "tenant.deleted".to_owned(),
            actor: "system".to_owned(),
            payload: Value::Null,
            occurred_at: OffsetDateTime::UNIX_EPOCH,
            chain_depth: 0,
        };
        (envelope.subject(), serde_json::to_vec(&envelope).unwrap())
    }

    async fn heard(node: &Node, subject: &str, payload: &[u8], seal: &EventSeal) {
        let mut feed = node.bus.follow().await.unwrap();
        let event = SealedEvent {
            subject,
            id: &Uuid::now_v7().to_string(),
            payload,
            seal: &seal.seal(subject, payload),
        };
        node.bus.publish(&event).await.unwrap();
        let Some(Heard::Event(event)) = feed.next().await else {
            panic!("the event was not heard");
        };
        node.follower.heard(&event).await;
    }

    /// A tenant's deletion heard from the bus, sealed by the control
    /// plane, drops the tenant's entries on this node.
    #[tokio::test]
    async fn a_sealed_deletion_drops_the_tenants_entries() {
        let node = node();
        let acme = Uuid::now_v7();
        node.callers
            .put("ann", 1, Owners::only(Owner::Tenant(acme)));
        let (subject, payload) = deleted(acme);

        heard(
            &node,
            &subject,
            &payload,
            &EventSeal::control_plane(&test_root()),
        )
        .await;

        assert!(node.callers.get(&"ann").is_none());
    }

    /// A tenant-deletion event signed with the data-plane key leaves the cached entry untouched.
    #[tokio::test]
    async fn a_forged_event_is_left_unapplied() {
        let node = node();
        let acme = Uuid::now_v7();
        node.callers
            .put("ann", 1, Owners::only(Owner::Tenant(acme)));
        let (subject, payload) = deleted(acme);

        heard(
            &node,
            &subject,
            &payload,
            &EventSeal::data_plane(&test_root()),
        )
        .await;

        assert!(node.callers.get(&"ann").is_some());
    }

    /// A feed reporting missed events causes the follower to discard its cached entry.
    #[tokio::test]
    async fn missed_events_drop_every_entry() {
        let node = node();
        node.callers
            .put("ann", 1, Owners::only(Owner::Tenant(Uuid::now_v7())));
        let feed: Box<dyn EventFeed> = Box::new(MissedOnce(true));

        node.follower.drain(feed).await;

        assert!(node.callers.get(&"ann").is_none());
    }

    /// A feed that says once that events went by unheard, then ends.
    struct MissedOnce(bool);

    #[async_trait::async_trait]
    impl EventFeed for MissedOnce {
        async fn next(&mut self) -> Option<Heard> {
            std::mem::take(&mut self.0).then_some(Heard::Missed)
        }
    }
}

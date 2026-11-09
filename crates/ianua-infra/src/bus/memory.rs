//! A message bus in this process: for a deployment of one node, for
//! development, and for tests.
//!
//! Published events are kept in order, at most a set number, the oldest
//! dropped first; an id published again within that number is kept once,
//! as a bus server keeps one copy within its window. Broadcasts go to
//! whoever listens on the subject now, through a bounded channel per
//! subject: a listener that falls behind loses the oldest, it never holds
//! the publisher. A subject's channel is kept only while someone listens on
//! it, and a broadcast nobody hears makes none, so subjects named once and
//! left never pile up. A follower hears each event kept from when it began
//! following, through a bounded channel of its own: one that falls behind
//! is told it missed some, it never holds the publisher. A share holds the
//! events published on its subjects since it was first read, at most the
//! number the bus keeps, the oldest dropped first, and hands each to one
//! of its readers at a time.

mod share;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::sync::broadcast;

use self::share::MemoryShare;
use crate::bus::stream::{
    Bus, BusError, EventFeed, EventShare, Heard, HeardEvent, Listener, SealedEvent, SharedFeed,
};

/// How many broadcasts a slow listener may fall behind by.
const LISTENER_ROOM: usize = 256;

/// How many events a slow follower may fall behind by.
const FOLLOWER_ROOM: usize = 1_024;

/// One event kept in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    /// The subject it was published on.
    pub subject: String,
    /// The id it was published under.
    pub id: String,
    /// What it carries.
    pub payload: Vec<u8>,
    /// Its publisher's seal.
    pub seal: String,
}

#[derive(Debug, Default)]
struct Kept {
    events: VecDeque<Published>,
    ids: HashSet<String>,
}

/// A message bus in this process's memory.
#[derive(Debug)]
pub struct MemoryBus {
    kept: Mutex<Kept>,
    capacity: usize,
    subjects: Mutex<HashMap<String, broadcast::Sender<Vec<u8>>>>,
    followers: broadcast::Sender<Published>,
    shares: Mutex<HashMap<String, Arc<MemoryShare>>>,
}

impl MemoryBus {
    /// A bus keeping at most `capacity` events.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            kept: Mutex::new(Kept::default()),
            capacity: capacity.max(1),
            subjects: Mutex::new(HashMap::new()),
            followers: broadcast::channel(FOLLOWER_ROOM).0,
            shares: Mutex::new(HashMap::new()),
        }
    }

    /// The share `share` names, made when it is not read yet.
    fn shared(&self, share: &EventShare) -> Result<Arc<MemoryShare>, BusError> {
        let mut shares = self.shares.lock().map_err(|_| poisoned())?;
        Ok(Arc::clone(shares.entry(share.name.clone()).or_insert_with(
            || Arc::new(MemoryShare::new(share, self.capacity)),
        )))
    }

    /// Hands `published` to every share holding its subject.
    fn distribute(&self, published: &Published) -> Result<(), BusError> {
        let shares = self.shares.lock().map_err(|_| poisoned())?;
        for share in shares.values() {
            share.hold(published);
        }
        Ok(())
    }

    /// The events kept, oldest first.
    #[must_use]
    pub fn published(&self) -> Vec<Published> {
        self.kept
            .lock()
            .map(|kept| kept.events.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// The channel of `subject` for a new listener, made when there is
    /// none. Channels nobody listens on any more are dropped first, so the
    /// subjects kept are the ones listened on now.
    fn listened(&self, subject: &str) -> Result<broadcast::Receiver<Vec<u8>>, BusError> {
        let mut subjects = self.subjects.lock().map_err(|_| poisoned())?;
        subjects.retain(|_, sender| sender.receiver_count() > 0);
        Ok(subjects
            .entry(subject.to_owned())
            .or_insert_with(|| broadcast::channel(LISTENER_ROOM).0)
            .subscribe())
    }

    /// The channel of `subject`, when someone listens on it.
    fn heard(&self, subject: &str) -> Result<Option<broadcast::Sender<Vec<u8>>>, BusError> {
        let subjects = self.subjects.lock().map_err(|_| poisoned())?;
        Ok(subjects.get(subject).cloned())
    }
}

/// The error a lock another thread panicked under answers.
fn poisoned() -> BusError {
    BusError::Unreachable("the in-process bus was left broken by a panic".into())
}

#[async_trait]
impl Bus for MemoryBus {
    async fn publish(&self, event: &SealedEvent<'_>) -> Result<(), BusError> {
        let mut kept = self.kept.lock().map_err(|_| poisoned())?;
        if !kept.ids.insert(event.id.to_owned()) {
            return Ok(());
        }
        let published = Published {
            subject: event.subject.to_owned(),
            id: event.id.to_owned(),
            payload: event.payload.to_vec(),
            seal: event.seal.to_owned(),
        };
        let _ = self.followers.send(published.clone());
        self.distribute(&published)?;
        kept.events.push_back(published);
        while kept.events.len() > self.capacity {
            let Some(oldest) = kept.events.pop_front() else {
                break;
            };
            kept.ids.remove(&oldest.id);
        }
        Ok(())
    }

    async fn broadcast(&self, subject: &str, payload: &[u8]) -> Result<(), BusError> {
        let Some(sender) = self.heard(subject)? else {
            return Ok(());
        };
        let _ = sender.send(payload.to_vec());
        Ok(())
    }

    async fn listen(&self, subject: &str) -> Result<Box<dyn Listener>, BusError> {
        Ok(Box::new(MemoryListener {
            receiver: self.listened(subject)?,
        }))
    }

    async fn follow(&self) -> Result<Box<dyn EventFeed>, BusError> {
        Ok(Box::new(MemoryFeed {
            receiver: self.followers.subscribe(),
        }))
    }

    async fn share(&self, share: &EventShare) -> Result<Box<dyn SharedFeed>, BusError> {
        Ok(Box::new(share::reader(self.shared(share)?)))
    }

    async fn ping(&self) -> Result<(), BusError> {
        Ok(())
    }
}

/// The events one follower of the in-process bus hears.
struct MemoryFeed {
    receiver: broadcast::Receiver<Published>,
}

#[async_trait]
impl EventFeed for MemoryFeed {
    async fn next(&mut self) -> Option<Heard> {
        match self.receiver.recv().await {
            Ok(published) => Some(Heard::Event(HeardEvent {
                subject: published.subject,
                payload: published.payload,
                seal: Some(published.seal),
            })),
            Err(broadcast::error::RecvError::Lagged(_)) => Some(Heard::Missed),
            Err(broadcast::error::RecvError::Closed) => None,
        }
    }
}

/// The broadcasts on one subject of the in-process bus.
struct MemoryListener {
    receiver: broadcast::Receiver<Vec<u8>>,
}

#[async_trait]
impl Listener for MemoryListener {
    async fn next(&mut self) -> Option<Vec<u8>> {
        loop {
            match self.receiver.recv().await {
                Ok(payload) => return Some(payload),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

/// A bus that takes nothing and does not answer, for the tests of what
/// must hold while the bus is down.
#[cfg(test)]
pub(crate) struct RefusingBus;

#[cfg(test)]
#[async_trait]
impl Bus for RefusingBus {
    async fn publish(&self, _: &SealedEvent<'_>) -> Result<(), BusError> {
        Err(BusError::TimedOut)
    }

    async fn broadcast(&self, _: &str, _: &[u8]) -> Result<(), BusError> {
        Err(BusError::TimedOut)
    }

    async fn listen(&self, _: &str) -> Result<Box<dyn Listener>, BusError> {
        Err(BusError::TimedOut)
    }

    async fn follow(&self) -> Result<Box<dyn EventFeed>, BusError> {
        Err(BusError::TimedOut)
    }

    async fn share(&self, _: &EventShare) -> Result<Box<dyn SharedFeed>, BusError> {
        Err(BusError::TimedOut)
    }

    async fn ping(&self) -> Result<(), BusError> {
        Err(BusError::TimedOut)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn published(bus: &MemoryBus, subject: &str, id: &str, payload: &[u8]) {
        let event = SealedEvent {
            subject,
            id,
            payload,
            seal: "seal",
        };
        bus.publish(&event).await.unwrap();
    }

    /// An event published twice under one id is kept once, and events keep
    /// their order.
    #[tokio::test]
    async fn an_event_published_twice_is_kept_once() {
        let bus = MemoryBus::new(10);

        published(&bus, "ianua.platform.a", "1", b"first").await;
        published(&bus, "ianua.platform.a", "1", b"again").await;
        published(&bus, "ianua.platform.b", "2", b"second").await;

        let ids: Vec<String> = bus.published().into_iter().map(|event| event.id).collect();
        assert_eq!(ids, ["1", "2"]);
    }

    /// Publishing ten events into three slots retains only the newest three.
    #[tokio::test]
    async fn a_flood_keeps_only_the_newest() {
        let bus = MemoryBus::new(3);

        for n in 0..10 {
            published(&bus, "ianua.platform.a", &n.to_string(), b"x").await;
        }

        let ids: Vec<String> = bus.published().into_iter().map(|event| event.id).collect();
        assert_eq!(ids, ["7", "8", "9"]);
    }

    /// A listener hears what is broadcast on its subject after it began
    /// listening, and nothing of another subject.
    #[tokio::test]
    async fn a_listener_hears_its_subject() {
        let bus = MemoryBus::new(10);
        let mut listener = bus.listen("realtime.user.1").await.unwrap();

        bus.broadcast("realtime.user.2", b"not for us")
            .await
            .unwrap();
        bus.broadcast("realtime.user.1", b"hello").await.unwrap();

        assert_eq!(listener.next().await, Some(b"hello".to_vec()));
    }

    /// Broadcasts without listeners and abandoned subscriptions leave only
    /// the final active subject's channel in memory.
    #[tokio::test]
    async fn subjects_nobody_listens_on_are_not_kept() {
        let bus = MemoryBus::new(10);
        for n in 0..100 {
            bus.broadcast(&format!("realtime.user.{n}"), b"x")
                .await
                .unwrap();
        }
        for n in 0..100 {
            drop(bus.listen(&format!("realtime.tenant.{n}")).await.unwrap());
        }
        let _kept = bus.listen("realtime.user.last").await.unwrap();

        let held = bus.subjects.lock().unwrap().len();

        assert_eq!(held, 1);
    }

    /// A follower hears each event kept after it began following, with its
    /// seal, and an id published again is heard once.
    #[tokio::test]
    async fn a_follower_hears_each_kept_event_once() {
        let bus = MemoryBus::new(10);
        published(&bus, "ianua.platform.a", "0", b"before").await;
        let mut feed = bus.follow().await.unwrap();

        published(&bus, "ianua.platform.a", "1", b"first").await;
        published(&bus, "ianua.platform.a", "1", b"again").await;
        published(&bus, "ianua.platform.b", "2", b"second").await;

        let first = feed.next().await;
        let second = feed.next().await;
        assert_eq!(
            first,
            Some(Heard::Event(HeardEvent {
                subject: "ianua.platform.a".to_owned(),
                payload: b"first".to_vec(),
                seal: Some("seal".to_owned()),
            }))
        );
        assert!(matches!(second, Some(Heard::Event(event)) if event.payload == b"second"));
    }

    /// A follower that exceeds its buffer receives a missed-events marker.
    #[tokio::test]
    async fn a_follower_that_falls_behind_is_told() {
        let bus = MemoryBus::new(FOLLOWER_ROOM * 2);
        let mut feed = bus.follow().await.unwrap();

        for n in 0..=FOLLOWER_ROOM {
            published(&bus, "ianua.platform.a", &n.to_string(), b"x").await;
        }

        assert_eq!(feed.next().await, Some(Heard::Missed));
    }
}

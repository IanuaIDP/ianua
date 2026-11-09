//! A share of the in-process bus's events: the events published on its
//! subjects since it was first read, each handed to one of its readers at
//! a time.
//!
//! An event failed on is held again until its wait has passed, and one
//! whose reader dropped it unsettled once the share's wait for a stopped
//! reader has passed from when it was handed. Unlike a bus server, an
//! event its reader still holds past that wait is not handed to another
//! reader beside it: in one process a reader that stopped drops what it
//! held. An event handed out as often as the share allows is not held
//! again.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::bus::memory::Published;
use crate::bus::stream::{BusError, EventShare, Handed, HeardEvent, Settle, Settled, SharedFeed};

/// One event the share holds, waiting to be handed out.
struct Waiting {
    published: Published,
    delivery: u32,
    due: Instant,
}

/// What a reader asking for an event finds.
enum Found {
    /// An event to hand out now.
    Due(Waiting),
    /// Nothing due before this moment.
    Next(Instant),
    /// Nothing held.
    Nothing,
    /// The share was left broken by a panic.
    Broken,
}

/// One share of the in-process bus.
pub(in crate::bus) struct MemoryShare {
    subjects: Vec<String>,
    max_deliver: u32,
    ack_wait: Duration,
    capacity: usize,
    held: Mutex<VecDeque<Waiting>>,
    arrived: Notify,
}

impl std::fmt::Debug for MemoryShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryShare")
            .field("subjects", &self.subjects)
            .field("max_deliver", &self.max_deliver)
            .field("ack_wait", &self.ack_wait)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl MemoryShare {
    /// The share `share` describes, holding at most `capacity` events.
    pub(in crate::bus) fn new(share: &EventShare, capacity: usize) -> Self {
        Self {
            subjects: share.subjects.clone(),
            max_deliver: share.max_deliver.max(1),
            ack_wait: share.ack_wait,
            capacity: capacity.max(1),
            held: Mutex::new(VecDeque::new()),
            arrived: Notify::new(),
        }
    }

    /// Holds `published` when its subject is one of the share's, dropping
    /// the oldest held past the share's room.
    pub(in crate::bus) fn hold(&self, published: &Published) {
        if !self
            .subjects
            .iter()
            .any(|pattern| named_by(pattern, &published.subject))
        {
            return;
        }
        self.hold_again(Waiting {
            published: published.clone(),
            delivery: 0,
            due: Instant::now(),
        });
    }

    /// Holds `waiting` until its time, unless it was handed out as often
    /// as the share allows.
    fn hold_again(&self, waiting: Waiting) {
        if waiting.delivery >= self.max_deliver {
            return;
        }
        let Ok(mut held) = self.held.lock() else {
            return;
        };
        held.push_back(waiting);
        while held.len() > self.capacity {
            held.pop_front();
        }
        drop(held);
        self.arrived.notify_waiters();
    }

    /// The first event due now, taken out of the share and counted as
    /// handed out once more, or when the next one comes due.
    fn take(&self) -> Found {
        let Ok(mut held) = self.held.lock() else {
            return Found::Broken;
        };
        let now = Instant::now();
        let due = held.iter().position(|waiting| waiting.due <= now);
        if let Some(mut waiting) = due.and_then(|at| held.remove(at)) {
            waiting.delivery = waiting.delivery.saturating_add(1);
            return Found::Due(waiting);
        }
        held.iter()
            .map(|waiting| waiting.due)
            .min()
            .map_or(Found::Nothing, Found::Next)
    }
}

/// A reader of `share`.
pub(in crate::bus) fn reader(share: Arc<MemoryShare>) -> MemoryReader {
    MemoryReader { share }
}

/// One reader of a share of the in-process bus.
pub(in crate::bus) struct MemoryReader {
    share: Arc<MemoryShare>,
}

impl MemoryReader {
    /// `waiting`, handed to this reader.
    fn handed(&self, waiting: Waiting) -> Handed {
        let event = HeardEvent {
            subject: waiting.published.subject.clone(),
            payload: waiting.published.payload.clone(),
            seal: Some(waiting.published.seal.clone()),
        };
        let delivery = waiting.delivery;
        let settle = MemorySettle {
            share: Arc::clone(&self.share),
            redelivered_at: after(self.share.ack_wait),
            waiting: Some(waiting),
        };
        Handed::new(event, delivery, self.share.max_deliver, Box::new(settle))
    }
}

#[async_trait]
impl SharedFeed for MemoryReader {
    async fn next(&mut self) -> Option<Handed> {
        loop {
            let arrived = self.share.arrived.notified();
            tokio::pin!(arrived);
            arrived.as_mut().enable();
            match self.share.take() {
                Found::Due(waiting) => return Some(self.handed(waiting)),
                Found::Next(at) => {
                    tokio::select! {
                        () = &mut arrived => {}
                        () = tokio::time::sleep_until(at) => {}
                    }
                }
                Found::Nothing => arrived.await,
                Found::Broken => return None,
            }
        }
    }
}

/// The moment `wait` from now. A wait past the clock's range is held to
/// a day, which no share's wait comes near.
fn after(wait: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(wait)
        .or_else(|| now.checked_add(Duration::from_secs(86_400)))
        .unwrap_or(now)
}

/// Settles one event a reader of the in-process bus was handed, and puts
/// it back when it is dropped unsettled.
struct MemorySettle {
    share: Arc<MemoryShare>,
    redelivered_at: Instant,
    waiting: Option<Waiting>,
}

#[async_trait]
impl Settle for MemorySettle {
    async fn settle(mut self: Box<Self>, settled: Settled) -> Result<(), BusError> {
        let Some(mut waiting) = self.waiting.take() else {
            return Ok(());
        };
        let Settled::AgainAfter(wait) = settled else {
            return Ok(());
        };
        waiting.due = after(wait);
        self.share.hold_again(waiting);
        Ok(())
    }
}

impl Drop for MemorySettle {
    fn drop(&mut self) {
        let Some(mut waiting) = self.waiting.take() else {
            return;
        };
        waiting.due = self.redelivered_at;
        self.share.hold_again(waiting);
    }
}

/// Whether `subject` is one `pattern` names: `*` stands for one part, and
/// a final `>` for one part or more.
fn named_by(pattern: &str, subject: &str) -> bool {
    let mut wanted = pattern.split('.');
    let mut parts = subject.split('.');
    loop {
        match (wanted.next(), parts.next()) {
            (Some(">"), Some(_)) => return true,
            (Some("*"), Some(_)) => {}
            (Some(want), Some(part)) if want == part => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn share(max_deliver: u32, ack_wait: Duration) -> Arc<MemoryShare> {
        Arc::new(MemoryShare::new(
            &EventShare {
                name: "webhooks".to_owned(),
                subjects: vec!["ianua.tenant.>".to_owned()],
                max_deliver,
                ack_wait,
            },
            10,
        ))
    }

    fn published(subject: &str, id: &str) -> Published {
        Published {
            subject: subject.to_owned(),
            id: id.to_owned(),
            payload: id.as_bytes().to_vec(),
            seal: "seal".to_owned(),
        }
    }

    async fn next(reader: &mut MemoryReader) -> Option<Handed> {
        tokio::time::timeout(Duration::from_secs(5), reader.next())
            .await
            .ok()
            .flatten()
    }

    /// A subject is named by its whole parts, a star or a final `>`.
    #[test]
    fn subjects_are_matched_by_their_parts() {
        assert!(named_by(
            "ianua.tenant.>",
            "ianua.tenant.abc.identity.user_registered"
        ));
        assert!(named_by("ianua.*.abc", "ianua.tenant.abc"));
        assert!(!named_by("ianua.tenant.>", "ianua.tenant"));
        assert!(!named_by("ianua.tenant.>", "ianua.org.abc.x"));
        assert!(!named_by("ianua.tenant", "ianua.tenant.abc"));
    }

    /// Two readers of one share are handed one event between them, once.
    #[tokio::test]
    async fn an_event_goes_to_one_reader_of_a_share() {
        let held = share(5, Duration::from_secs(60));
        let mut first = reader(Arc::clone(&held));
        let mut second = reader(Arc::clone(&held));
        held.hold(&published("ianua.tenant.a.x", "1"));

        let handed = next(&mut first).await.unwrap();
        handed.acknowledge().await.unwrap();
        let again = tokio::time::timeout(Duration::from_millis(50), second.next()).await;

        assert!(again.is_err());
    }

    /// An event of another subject is not held.
    #[tokio::test]
    async fn an_event_of_another_subject_is_not_held() {
        let held = share(5, Duration::from_secs(60));
        held.hold(&published("ianua.platform.x", "1"));

        assert!(matches!(held.take(), Found::Nothing));
    }

    /// Retrying an event delivers it a second time with its final-attempt flag set.
    #[tokio::test]
    async fn an_event_failed_on_comes_again_counted() {
        let held = share(2, Duration::from_secs(60));
        let mut reading = reader(Arc::clone(&held));
        held.hold(&published("ianua.tenant.a.x", "1"));

        let first = next(&mut reading).await.unwrap();
        assert!(!first.last);
        first.again_after(Duration::ZERO).await.unwrap();
        let second = next(&mut reading).await.unwrap();

        assert_eq!(second.delivery, 2);
        assert!(second.last);
    }

    /// Requesting another retry on the final delivery leaves no event waiting.
    #[tokio::test]
    async fn an_event_is_not_held_past_its_last_delivery() {
        let held = share(1, Duration::from_secs(60));
        let mut reading = reader(Arc::clone(&held));
        held.hold(&published("ianua.tenant.a.x", "1"));

        next(&mut reading)
            .await
            .unwrap()
            .again_after(Duration::ZERO)
            .await
            .unwrap();

        assert!(matches!(held.take(), Found::Nothing));
    }

    /// Dropping an unsettled delivery returns the same payload on delivery two.
    #[tokio::test]
    async fn an_event_dropped_unsettled_comes_again() {
        let held = share(5, Duration::from_millis(10));
        let mut reading = reader(Arc::clone(&held));
        held.hold(&published("ianua.tenant.a.x", "1"));

        drop(next(&mut reading).await.unwrap());
        let again = next(&mut reading).await.unwrap();

        assert_eq!(again.delivery, 2);
        assert_eq!(again.event.payload, b"1");
    }

    /// An event set aside is not handed out again.
    #[tokio::test]
    async fn an_event_set_aside_is_gone() {
        let held = share(5, Duration::from_millis(10));
        let mut reading = reader(Arc::clone(&held));
        held.hold(&published("ianua.tenant.a.x", "1"));

        next(&mut reading).await.unwrap().set_aside().await.unwrap();

        assert!(matches!(held.take(), Found::Nothing));
    }
}

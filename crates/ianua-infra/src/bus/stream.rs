//! What the bus-shaped adapters ask of a message bus, behind one trait, so
//! they are written once and the bus can live in this process or on a bus
//! server every node reaches.
//!
//! Two kinds of message travel. An event is published durably, kept by
//! the bus and handed to every consumer at least once; it carries an id,
//! and the same id published twice is kept once. A broadcast is handed to
//! whoever listens now and kept nowhere: a live notification, or the word
//! that a cached entry changed. A follower hears every event published
//! after it began following, as the node's store caches do to drop what
//! an event changed. A share is read by every node under one name, each
//! event handed to one reader of it and handed again until one is done
//! with it, as the worker's consumers read them.

use std::time::Duration;

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;

/// Why the bus could not take or hand out a message. None of it names a
/// message's contents.
#[derive(Debug, thiserror::Error)]
pub enum BusError {
    /// The bus could not be reached or refused the message.
    #[error("the message bus could not be reached")]
    Unreachable(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The bus did not answer in time.
    #[error("the message bus did not answer in time")]
    TimedOut,
}

impl From<BusError> for DomainError {
    fn from(error: BusError) -> Self {
        DomainError::infra(error)
    }
}

/// An event on its way to the bus, sealed by its publisher.
#[derive(Debug, Clone, Copy)]
pub struct SealedEvent<'a> {
    /// The subject it is published on.
    pub subject: &'a str,
    /// The id the bus keeps one copy by.
    pub id: &'a str,
    /// What it carries.
    pub payload: &'a [u8],
    /// Its publisher's seal on the subject and the payload.
    pub seal: &'a str,
}

/// A message bus, as the bus-shaped adapters use it.
#[async_trait]
pub trait Bus: Send + Sync {
    /// Publishes `event` durably: the bus keeps it, with its seal, for its
    /// consumers, and keeps one copy when the same id is published again.
    ///
    /// # Errors
    ///
    /// Returns [`BusError`] when the bus did not take it.
    async fn publish(&self, event: &SealedEvent<'_>) -> Result<(), BusError>;

    /// Hands `payload` to whoever listens on `subject` now, and keeps it
    /// nowhere.
    ///
    /// # Errors
    ///
    /// Returns [`BusError`] when the bus did not take it.
    async fn broadcast(&self, subject: &str, payload: &[u8]) -> Result<(), BusError>;

    /// Listens on `subject` for broadcasts from now on.
    ///
    /// # Errors
    ///
    /// Returns [`BusError`] when the bus cannot be listened on.
    async fn listen(&self, subject: &str) -> Result<Box<dyn Listener>, BusError>;

    /// Follows every event published from now on, as this node's own
    /// reader: each follower hears every event, none is shared out between
    /// followers, and nothing is acknowledged.
    ///
    /// # Errors
    ///
    /// Returns [`BusError`] when the events cannot be followed.
    async fn follow(&self) -> Result<Box<dyn EventFeed>, BusError>;

    /// Reads `share` of the events: every reader under its name, on any
    /// node, takes part in one share, which holds each event published
    /// on its subjects since the share was first read. Each event is
    /// handed to one reader at a time, and handed again, to whichever
    /// reader asks next, until a reader settles it as done or set aside,
    /// or it was handed `max_deliver` times. An event a reader holds past
    /// `ack_wait` without settling it is taken to be held by a reader that
    /// stopped, and handed again.
    ///
    /// # Errors
    ///
    /// Returns [`BusError`] when the share cannot be made or read.
    async fn share(&self, share: &EventShare) -> Result<Box<dyn SharedFeed>, BusError>;

    /// Whether the bus answers now, for the readiness check.
    ///
    /// # Errors
    ///
    /// Returns [`BusError`] when the bus does not answer.
    async fn ping(&self) -> Result<(), BusError>;
}

/// The broadcasts on one subject, as they arrive.
#[async_trait]
pub trait Listener: Send {
    /// The next broadcast, or `None` once the bus closed the subscription.
    async fn next(&mut self) -> Option<Vec<u8>>;
}

/// An event as a follower heard it: unchecked until its seal is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeardEvent {
    /// The subject it was published on.
    pub subject: String,
    /// What it carries.
    pub payload: Vec<u8>,
    /// The seal it came with, if any.
    pub seal: Option<String>,
}

/// What a follower hears next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Heard {
    /// One event, in the order the bus kept them.
    Event(HeardEvent),
    /// Events went by that this follower did not hear, as when it fell
    /// behind: what it built on them may be out of date.
    Missed,
}

/// The events one follower hears, as they are published.
#[async_trait]
pub trait EventFeed: Send {
    /// What is heard next, or `None` once the bus ended the feed.
    async fn next(&mut self) -> Option<Heard>;
}

/// A share of the events, read under one name by every node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventShare {
    /// The share's name, the same on every node and never changed once
    /// deployed: lowercase letters, digits, `-` and `_`.
    pub name: String,
    /// The subjects it holds, `*` standing for one part of a subject and a
    /// final `>` for the rest.
    pub subjects: Vec<String>,
    /// The most times one event is handed out.
    pub max_deliver: u32,
    /// How long a reader may hold an event before it is handed to
    /// another.
    pub ack_wait: Duration,
}

/// The events one reader of a share is handed, as they come.
#[async_trait]
pub trait SharedFeed: Send {
    /// The next event handed to this reader, or `None` once the bus ended
    /// the feed.
    async fn next(&mut self) -> Option<Handed>;
}

/// How a reader settled an event it was handed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Settled {
    /// It is done with; it is not handed out again.
    Done,
    /// It failed; it is handed out again once the wait has passed, unless
    /// it was handed out as often as the share allows.
    AgainAfter(Duration),
    /// It can never be acted on; it is not handed out again.
    SetAside,
}

/// Settles one handed event on the bus it came from.
#[async_trait]
pub(crate) trait Settle: Send {
    /// Settles the event as `settled` says.
    async fn settle(self: Box<Self>, settled: Settled) -> Result<(), BusError>;
}

/// One event handed to a reader of a share, to be settled by it.
///
/// Dropped unsettled, it is handed out again once its wait has passed,
/// as the event of a reader that stopped.
pub struct Handed {
    /// The event, unchecked until its seal is.
    pub event: HeardEvent,
    /// How many times it has been handed out, this time included, from 1.
    pub delivery: u32,
    /// Whether this is the last time it is handed out.
    pub last: bool,
    settle: Box<dyn Settle>,
}

impl std::fmt::Debug for Handed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handed")
            .field("subject", &self.event.subject)
            .field("delivery", &self.delivery)
            .field("last", &self.last)
            .finish_non_exhaustive()
    }
}

impl Handed {
    /// `event` handed out for the `delivery`th time of at most
    /// `max_deliver`, settled through `settle`.
    pub(crate) fn new(
        event: HeardEvent,
        delivery: u32,
        max_deliver: u32,
        settle: Box<dyn Settle>,
    ) -> Self {
        Self {
            event,
            delivery,
            last: delivery >= max_deliver,
            settle,
        }
    }

    /// Settles the event as done with: it is not handed out again.
    ///
    /// # Errors
    ///
    /// Returns [`BusError`] when the bus did not take it; the event is
    /// handed out again then.
    pub async fn acknowledge(self) -> Result<(), BusError> {
        self.settle.settle(Settled::Done).await
    }

    /// Settles the event as failed: it is handed out again once `wait`
    /// has passed, unless this was its last time.
    ///
    /// # Errors
    ///
    /// Returns [`BusError`] when the bus did not take it; the event is
    /// handed out again once its wait for a stopped reader has passed.
    pub async fn again_after(self, wait: Duration) -> Result<(), BusError> {
        self.settle.settle(Settled::AgainAfter(wait)).await
    }

    /// Settles the event as one that can never be acted on: it is not
    /// handed out again.
    ///
    /// # Errors
    ///
    /// Returns [`BusError`] when the bus did not take it; the event is
    /// handed out again then.
    pub async fn set_aside(self) -> Result<(), BusError> {
        self.settle.settle(Settled::SetAside).await
    }
}

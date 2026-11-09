//! The agent message plane on the bus server: tenants' messages kept in a
//! persistent stream, a durable consumer per subscription or consumer
//! group, and the dead letters each consumer set aside, in a stream of
//! their own. The plane is opened once and shared by its three adapters,
//! one per port.
//!
//! Every subject and stream sits under the deployment's namespace, `ianua`
//! by default. Subjects read `<namespace>.msg.<tenant>.<topic>.<type>` for
//! a published message, the topic's dots written as underscores so it
//! stays one segment and the type left off when the message has none;
//! `<namespace>.replay.<tenant>.<consumer>` for a dead letter put back for
//! one consumer alone; and `<namespace>.dead.<tenant>.<consumer>` for the
//! dead letters, ids in their simple form. The streams are
//! `<namespace>-messages` and `<namespace>-dead-letters`, and each
//! consumer is kept inside the first. A subscription's filter becomes the
//! subjects its consumer reads, so the server hands out only the types it
//! lets through. The type also travels in a header of its own, so a dead
//! letter and its replay keep it.
//!
//! A message past its topic's retention is not handed out, whoever reads:
//! see `retention`.
//!
//! A dead letter is copied before its delivery is ended, and a replayed one
//! published before it is removed, both under an id the server keeps once,
//! so a step cut short and tried again loses nothing and doubles nothing.

mod consumer;
mod dead_letters;
mod headers;
mod names;
mod publisher;
mod receipt;
mod retention;

use std::time::Duration;

use async_nats::jetstream;
use async_nats::jetstream::consumer::{PullConsumer, pull};
use async_nats::jetstream::message::StreamMessage;
use async_nats::jetstream::stream::{self, LastRawMessageError, LastRawMessageErrorKind, Stream};
use futures_util::StreamExt as _;

pub use self::consumer::BusMessageConsumer;
pub use self::dead_letters::BusDeadLetters;
use self::names::{DEAD_SUBJECTS, Durable, MESSAGE_SUBJECTS, REPLAY_SUBJECTS};
pub use self::publisher::BusMessagePublisher;
use self::receipt::Delivery;
use crate::bus::server::{Publication, ServerBus, in_time, publish_and_confirm, unreachable_by};
use crate::bus::stream::BusError;
use crate::crypto::ReceiptSeal;
use crate::namespace::Namespace;

/// The role of the stream tenants' messages are kept in.
const MESSAGES: &str = "messages";

/// The role of the stream dead letters are kept in.
const DEAD_LETTERS: &str = "dead-letters";

/// How long a message is kept for consumers that have not taken it.
const MESSAGES_KEPT: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// How long a dead letter is kept for a person to look at and replay.
const DEAD_LETTERS_KEPT: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// How long the server remembers an id, to keep one copy of it.
const DUPLICATE_WINDOW: Duration = Duration::from_secs(120);

/// The header a published message's id travels in.
const ID_HEADER: &str = "Nats-Msg-Id";

/// The agent message plane on a bus server: its two streams, and the seal
/// its receipts are made under.
pub struct MessagePlane {
    bus: ServerBus,
    messages: Stream,
    dead_letters: Stream,
    seal: ReceiptSeal,
}

impl std::fmt::Debug for MessagePlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessagePlane").finish_non_exhaustive()
    }
}

impl MessagePlane {
    /// The message plane on `bus`'s server, its two streams made if they
    /// are not there yet, its receipts sealed with `seal`.
    ///
    /// # Errors
    ///
    /// Returns [`BusError`] when a stream cannot be made in time.
    pub async fn open(bus: ServerBus, seal: ReceiptSeal) -> Result<Self, BusError> {
        let namespace = &bus.namespace;
        let messages = stream::Config {
            name: namespace.stream(MESSAGES),
            subjects: vec![
                namespace.subject(MESSAGE_SUBJECTS),
                namespace.subject(REPLAY_SUBJECTS),
            ],
            max_age: MESSAGES_KEPT,
            duplicate_window: DUPLICATE_WINDOW,
            ..stream::Config::default()
        };
        let dead_letters = stream::Config {
            name: namespace.stream(DEAD_LETTERS),
            subjects: vec![namespace.subject(DEAD_SUBJECTS)],
            max_age: DEAD_LETTERS_KEPT,
            duplicate_window: DUPLICATE_WINDOW,
            ..stream::Config::default()
        };
        let messages = in_time(bus.deadline, bus.events.get_or_create_stream(messages)).await?;
        let dead_letters =
            in_time(bus.deadline, bus.events.get_or_create_stream(dead_letters)).await?;
        Ok(Self {
            bus,
            messages,
            dead_letters,
            seal,
        })
    }

    /// The namespace every subject of the plane sits under.
    fn namespace(&self) -> &Namespace {
        &self.bus.namespace
    }

    async fn consumer(&self, durable: &Durable) -> Result<PullConsumer, BusError> {
        in_time(
            self.bus.deadline,
            self.messages.get_consumer::<pull::Config>(durable.as_str()),
        )
        .await
    }

    /// Up to `most` messages `durable` hands out now, without waiting for
    /// more.
    async fn fetched(
        &self,
        durable: &Durable,
        most: usize,
    ) -> Result<Vec<jetstream::Message>, BusError> {
        let consumer = self.consumer(durable).await?;
        self.batch_of(&consumer, most).await
    }

    /// Up to `most` messages `consumer` hands out now, without waiting for
    /// more.
    async fn batch_of(
        &self,
        consumer: &PullConsumer,
        most: usize,
    ) -> Result<Vec<jetstream::Message>, BusError> {
        let fetched = async {
            let batch = consumer
                .fetch()
                .max_messages(most)
                .messages()
                .await
                .map_err(unreachable_by)?;
            let mut messages = Vec::with_capacity(most);
            let mut batch = std::pin::pin!(batch);
            while let Some(message) = batch.next().await {
                messages.push(message.map_err(BusError::Unreachable)?);
            }
            Ok::<_, BusError>(messages)
        };
        tokio::time::timeout(self.bus.deadline, fetched)
            .await
            .map_err(|_| BusError::TimedOut)?
    }

    /// Ends `delivery` as `how` says, once the server confirmed it.
    async fn settle(&self, delivery: &Delivery, how: &'static str) -> Result<(), BusError> {
        in_time(
            self.bus.deadline,
            self.bus.client.request(delivery.reply.clone(), how.into()),
        )
        .await?;
        Ok(())
    }

    /// Publishes the message under `id`, which the server keeps
    /// one copy of.
    async fn publish_kept(&self, id: &str, mut publication: Publication) -> Result<(), BusError> {
        publication.headers.insert(ID_HEADER, id);
        publish_and_confirm(&self.bus.events, self.bus.deadline, publication).await
    }
}

/// The message `lookup` reads, or `None` when the stream holds none there.
async fn found(
    deadline: Duration,
    lookup: impl Future<Output = Result<StreamMessage, LastRawMessageError>>,
) -> Result<Option<StreamMessage>, BusError> {
    let read = tokio::time::timeout(deadline, lookup)
        .await
        .map_err(|_| BusError::TimedOut)?;
    match read {
        Ok(message) => Ok(Some(message)),
        Err(error) if error.kind() == LastRawMessageErrorKind::NoMessageFound => Ok(None),
        Err(error) => Err(unreachable_by(error)),
    }
}

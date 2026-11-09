//! A topic's retention on the server. All of a deployment's topics share
//! one stream, so a topic's limit is applied by this code and not by the
//! stream's own limits, which hold for the whole stream.
//!
//! A read is what enforces a limit, as it is stored at that moment: a
//! count limit trims the topic before the read, so what falls outside is
//! gone before anyone can be handed it, and a delivery past an age limit is
//! never handed out. Being past is a property of the message and the
//! current rule alone, so a subscriber that was away for a week is treated
//! as one that never left, and a redelivery as a first delivery. A removal
//! that fails refuses the read rather than hand anything out.
//!
//! What a read finds past its limit is removed for every reader of the
//! topic, and so is everything older, which was published first and is past
//! it too. A message nobody reads leaves at the next read of its topic, or
//! at the stream's own seven-day limit, unreadable until then.

use std::time::Duration;

use async_nats::jetstream;
use async_nats::jetstream::consumer::{AckPolicy, DeliverPolicy, PullConsumer, pull};
use ianua_domain::domains::messaging::topic::RetentionPolicy;
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::shared::clock;
use ianua_domain::types::TenantId;
use time::OffsetDateTime;

use crate::bus::server::messaging::MessagePlane;
use crate::bus::server::messaging::headers::{FIRST_PUBLISHED_HEADER, first_published};
use crate::bus::server::messaging::names::{Durable, every_message_of};
use crate::bus::server::{in_time, unreachable_by};
use crate::bus::stream::BusError;

/// How long the short-lived reader that finds where an age limit falls may
/// sit idle before the server removes it by itself, should the plane stop
/// before removing it.
const FINDER_IDLE: Duration = Duration::from_secs(30);

/// One read of a topic: whose, through which consumer, under which rule as
/// it stands now.
pub(super) struct TopicRead<'a> {
    /// The tenant whose topic is read.
    pub(super) tenant_id: &'a TenantId,
    /// The topic whose rule the read is held to.
    pub(super) topic_name: &'a TopicName,
    /// The consumer reading.
    pub(super) durable: &'a Durable,
    /// What the topic keeps.
    pub(super) retention: RetentionPolicy,
}

/// What a read fetched, sorted by the topic's rule.
pub(super) struct Retained {
    /// The messages the rule still keeps, to be handed out.
    pub(super) inside: Vec<jetstream::Message>,
    /// The messages past the rule, which nobody is handed.
    pub(super) outside: Vec<jetstream::Message>,
}

impl MessagePlane {
    /// Up to `most` messages `read`'s consumer hands out now, sorted by the
    /// topic's rule. A count limit is applied to the topic first.
    pub(super) async fn read_retained(
        &self,
        read: &TopicRead<'_>,
        most: usize,
    ) -> Result<Retained, BusError> {
        if let RetentionPolicy::MessageCount(kept) = read.retention {
            self.keep_last(read.tenant_id, read.topic_name, kept.get())
                .await?;
        }
        let fetched = self.fetched(read.durable, most).await?;
        let now = clock::now();
        let (outside, inside) = fetched
            .into_iter()
            .partition(|message| is_outside(message, read.retention, now));
        Ok(Retained { inside, outside })
    }

    /// Ends the delivery of `message`, which a limit took: it is not
    /// delivered again.
    pub(super) async fn end_delivery(&self, message: &jetstream::Message) -> Result<(), BusError> {
        let Some(reply) = message.reply.as_ref() else {
            return Ok(());
        };
        in_time(
            self.bus.deadline,
            self.bus.client.request(reply.to_string(), "+TERM".into()),
        )
        .await?;
        Ok(())
    }

    /// Removes the topic's messages up to the newest of `outside`, for
    /// every reader: all of them were published first, so all are past the
    /// limit too. A replayed dead letter does not count: it sits late on
    /// the stream though it is old, so messages before it may be fresh.
    pub(super) async fn remove_outside(
        &self,
        read: &TopicRead<'_>,
        outside: &[jetstream::Message],
    ) -> Result<(), BusError> {
        let first_time = outside.iter().filter(|message| !is_replay(message));
        let Some(newest) = first_time.filter_map(stream_sequence).max() else {
            return Ok(());
        };
        self.remove_before(read.tenant_id, read.topic_name, newest.saturating_add(1))
            .await
    }

    /// Removes the topic's messages that `retention` no longer keeps.
    pub(super) async fn remove_lapsed(
        &self,
        tenant_id: &TenantId,
        topic_name: &TopicName,
        retention: RetentionPolicy,
    ) -> Result<(), BusError> {
        match retention {
            RetentionPolicy::Unlimited => Ok(()),
            RetentionPolicy::MessageCount(kept) => {
                self.keep_last(tenant_id, topic_name, kept.get()).await
            }
            RetentionPolicy::Duration(seconds) => {
                let since =
                    clock::now().saturating_sub(time::Duration::seconds(i64::from(seconds.get())));
                self.remove_older_than(tenant_id, topic_name, since).await
            }
        }
    }

    /// Keeps only the newest `kept` messages of the topic.
    async fn keep_last(
        &self,
        tenant_id: &TenantId,
        topic_name: &TopicName,
        kept: u64,
    ) -> Result<(), BusError> {
        let filter = every_message_of(self.namespace(), tenant_id, topic_name);
        in_time(
            self.bus.deadline,
            self.messages.purge().filter(filter).keep(kept),
        )
        .await?;
        Ok(())
    }

    /// Removes the topic's messages before `sequence`.
    async fn remove_before(
        &self,
        tenant_id: &TenantId,
        topic_name: &TopicName,
        sequence: u64,
    ) -> Result<(), BusError> {
        let filter = every_message_of(self.namespace(), tenant_id, topic_name);
        in_time(
            self.bus.deadline,
            self.messages.purge().filter(filter).sequence(sequence),
        )
        .await?;
        Ok(())
    }

    /// Removes the topic's messages published before `since`. Where nothing
    /// is that recent, stops at the stream's end as it stood, so a message
    /// published meanwhile stays.
    async fn remove_older_than(
        &self,
        tenant_id: &TenantId,
        topic_name: &TopicName,
        since: OffsetDateTime,
    ) -> Result<(), BusError> {
        let end = in_time(self.bus.deadline, self.messages.get_info())
            .await?
            .state
            .last_sequence;
        let first_kept = self
            .first_sequence_since(tenant_id, topic_name, since)
            .await?;
        let before = first_kept.unwrap_or_else(|| end.saturating_add(1));
        self.remove_before(tenant_id, topic_name, before).await
    }

    /// The stream sequence of the topic's first message published at
    /// `since` or later, found through a short-lived reader of its own.
    async fn first_sequence_since(
        &self,
        tenant_id: &TenantId,
        topic_name: &TopicName,
        since: OffsetDateTime,
    ) -> Result<Option<u64>, BusError> {
        let finder = pull::Config {
            filter_subject: every_message_of(self.namespace(), tenant_id, topic_name),
            deliver_policy: DeliverPolicy::ByStartTime { start_time: since },
            ack_policy: AckPolicy::None,
            inactive_threshold: FINDER_IDLE,
            ..pull::Config::default()
        };
        let reader = in_time(self.bus.deadline, self.messages.create_consumer(finder)).await?;
        let first = self.batch_of(&reader, 1).await?;
        self.discard_finder(&reader).await;
        let Some(message) = first.first() else {
            return Ok(None);
        };
        let info = message.info().map_err(unreachable_by)?;
        Ok(Some(info.stream_sequence))
    }

    /// Removes the short-lived `reader`. Left behind, the server removes
    /// it after [`FINDER_IDLE`], so a failure is only logged.
    async fn discard_finder(&self, reader: &PullConsumer) {
        let name = reader.cached_info().name.clone();
        if in_time(self.bus.deadline, self.messages.delete_consumer(&name))
            .await
            .is_err()
        {
            tracing::warn!("a short-lived reader of a topic was left for the server to remove");
        }
    }
}

/// Whether `message` is past `retention` at `now`, so no reader may have
/// it. A message the server's details cannot be read of is past, so
/// nothing unchecked is handed out.
fn is_outside(
    message: &jetstream::Message,
    retention: RetentionPolicy,
    now: OffsetDateTime,
) -> bool {
    let Ok(info) = message.info() else {
        return true;
    };
    let published = message.headers.as_ref().map_or(info.published, |headers| {
        first_published(headers, info.published)
    });
    retention.has_aged_out(published, now)
}

/// Whether `message` is a dead letter put back, which keeps when the bus
/// first took it.
fn is_replay(message: &jetstream::Message) -> bool {
    message
        .headers
        .as_ref()
        .is_some_and(|headers| headers.get(FIRST_PUBLISHED_HEADER).is_some())
}

/// Where `message` sits in the stream.
fn stream_sequence(message: &jetstream::Message) -> Option<u64> {
    message.info().ok().map(|info| info.stream_sequence)
}

#[cfg(test)]
mod tests {
    use std::num::{NonZeroU32, NonZeroU64};

    use ianua_app::ports::messaging::{
        Acknowledgement, ConsumerRead, ConsumerSpec, MessageConsumer as _,
    };

    use super::*;
    use crate::test_support::plane::{TestPlane, tenant};

    /// How long a limit is here, in seconds: as short as one can be.
    const LIMIT: u32 = 1;

    /// A limit of [`LIMIT`] seconds.
    fn limit() -> RetentionPolicy {
        RetentionPolicy::Duration(NonZeroU32::new(LIMIT).unwrap())
    }

    /// A limit of `count` messages.
    fn the_last(count: u64) -> RetentionPolicy {
        RetentionPolicy::MessageCount(NonZeroU64::new(count).unwrap())
    }

    /// Waits past [`LIMIT`].
    async fn limit_passed() {
        tokio::time::sleep(Duration::from_secs(u64::from(LIMIT) + 1)).await;
    }

    /// A message read within its limit is handed out.
    #[tokio::test]
    async fn a_message_inside_its_limit_is_handed_out() {
        let plane = TestPlane::open().await;
        let tenant_id = tenant();
        plane.subscribed(&tenant_id, "sub-a", None).await;
        plane.published(&tenant_id, b"order 7", None).await;

        let keeping_an_hour = RetentionPolicy::Duration(NonZeroU32::new(3600).unwrap());
        let pending = plane
            .handed_out_under(&tenant_id, "sub-a", keeping_an_hour)
            .await;

        assert_eq!(pending.len(), 1);
    }

    /// A subscriber that was away past the limit reads nothing, and the
    /// message is gone for good: a later read with no limit finds nothing,
    /// so it is removed and not only hidden.
    #[tokio::test]
    async fn a_message_past_its_limit_is_not_handed_out_and_is_removed() {
        let plane = TestPlane::open().await;
        let tenant_id = tenant();
        plane.subscribed(&tenant_id, "sub-a", None).await;
        plane.published(&tenant_id, b"order 7", None).await;
        limit_passed().await;

        let pending = plane.handed_out_under(&tenant_id, "sub-a", limit()).await;

        assert!(pending.is_empty());
        assert!(plane.handed_out(&tenant_id, "sub-a").await.is_empty());
    }

    /// A delivery handed out and not acknowledged comes round again past
    /// its limit: it is withheld as a first delivery would be, and does not
    /// come round after that.
    #[tokio::test]
    async fn a_redelivery_past_its_limit_is_withheld() {
        let plane = TestPlane::open().await;
        let tenant_id = tenant();
        plane.subscribed(&tenant_id, "sub-a", None).await;
        plane.published(&tenant_id, b"order 7", None).await;
        let first = plane.handed_out(&tenant_id, "sub-a").await.remove(0);
        plane
            .consumer
            .redeliver(&tenant_id, &plane.topic(), "sub-a", &first.receipt)
            .await
            .unwrap();
        limit_passed().await;

        let pending = plane.handed_out_under(&tenant_id, "sub-a", limit()).await;

        assert!(pending.is_empty());
        assert!(plane.handed_out(&tenant_id, "sub-a").await.is_empty());
    }

    /// A reader's own cursor is held to the limit as a subscription is.
    #[tokio::test]
    async fn a_cursor_reads_nothing_past_its_limit() {
        let plane = TestPlane::open().await;
        let tenant_id = tenant();
        let topic = plane.topic();
        plane
            .consumer
            .ensure_consumer(
                &tenant_id,
                &topic,
                &ConsumerSpec {
                    name: "agent-a",
                    filter: None,
                    acknowledgement: Acknowledgement::OnFetch,
                },
            )
            .await
            .unwrap();
        plane.published(&tenant_id, b"order 7", None).await;
        limit_passed().await;

        let read = plane
            .consumer
            .pull_messages(
                &tenant_id,
                ConsumerRead {
                    topic_name: &topic,
                    consumer_name: "agent-a",
                    retention: limit(),
                },
                10,
            )
            .await
            .unwrap();

        assert!(read.is_empty());
    }

    /// A count limit keeps the newest of the topic, typed and untyped
    /// messages counted together, so the oldest is gone before the read.
    #[tokio::test]
    async fn a_count_limit_keeps_only_the_newest() {
        let plane = TestPlane::open().await;
        let tenant_id = tenant();
        plane.subscribed(&tenant_id, "sub-a", None).await;
        plane.published(&tenant_id, b"order 1", None).await;
        plane
            .published(&tenant_id, b"order 2", Some("order.created"))
            .await;
        plane.published(&tenant_id, b"order 3", None).await;

        let pending = plane
            .handed_out_under(&tenant_id, "sub-a", the_last(2))
            .await;

        let payloads: Vec<&[u8]> = pending
            .iter()
            .map(|one| one.message.payload.as_slice())
            .collect();
        assert_eq!(payloads, [b"order 2".as_slice(), b"order 3".as_slice()]);
    }

    /// Removing what an age limit no longer keeps takes the older message
    /// and leaves the fresh one, for readers that read under no limit at all.
    #[tokio::test]
    async fn removing_what_a_limit_no_longer_keeps_leaves_the_fresh_message() {
        let plane = TestPlane::open().await;
        let tenant_id = tenant();
        plane.subscribed(&tenant_id, "sub-a", None).await;
        plane.published(&tenant_id, b"old", None).await;
        limit_passed().await;
        plane.published(&tenant_id, b"fresh", None).await;

        plane
            .consumer
            .remove_lapsed(&tenant_id, &plane.topic(), limit())
            .await
            .unwrap();

        let pending = plane.handed_out(&tenant_id, "sub-a").await;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].message.payload, b"fresh");
    }

    /// With nothing inside the limit everything is removed, and asking
    /// again changes nothing.
    #[tokio::test]
    async fn removing_twice_with_nothing_inside_the_limit_is_harmless() {
        let plane = TestPlane::open().await;
        let tenant_id = tenant();
        plane.subscribed(&tenant_id, "sub-a", None).await;
        plane.published(&tenant_id, b"old", None).await;
        limit_passed().await;

        for _ in 0..2 {
            plane
                .consumer
                .remove_lapsed(&tenant_id, &plane.topic(), limit())
                .await
                .unwrap();
        }

        assert!(plane.handed_out(&tenant_id, "sub-a").await.is_empty());
    }

    /// One tenant's limit never touches another tenant's messages.
    #[tokio::test]
    async fn a_limit_removes_nothing_of_another_tenant() {
        let plane = TestPlane::open().await;
        let elsewhere = tenant();
        let tenant_id = tenant();
        plane.subscribed(&elsewhere, "sub-a", None).await;
        plane.subscribed(&tenant_id, "sub-a", None).await;
        plane.published(&elsewhere, b"kept", None).await;
        plane.published(&tenant_id, b"old", None).await;
        limit_passed().await;

        plane
            .consumer
            .remove_lapsed(&tenant_id, &plane.topic(), limit())
            .await
            .unwrap();

        assert_eq!(plane.handed_out(&elsewhere, "sub-a").await.len(), 1);
    }
}

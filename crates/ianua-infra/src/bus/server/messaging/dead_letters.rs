//! The dead letters a consumer set aside: listed by the server's numbers,
//! oldest first, and replayed to that consumer alone, its delivery count
//! starting over.

use std::sync::Arc;

use async_nats::jetstream::message::StreamMessage;
use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortKey, SortOrder};
use ianua_app::ports::messaging::{
    ConsumerRead, DeadLetter, DeadLetterId, DeadLetterSortField, DeadLetters, MessageKey, Replay,
};
use ianua_domain::domains::messaging::topic::RetentionPolicy;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use crate::bus::server::messaging::headers::{
    delivered_of, first_published, received, replayed_headers,
};
use crate::bus::server::messaging::names::{Durable, dead_subject, replay_subject};
use crate::bus::server::messaging::{MessagePlane, found};
use crate::bus::server::{Publication, in_time};

/// The dead letters on the message plane.
#[derive(Debug, Clone)]
pub struct BusDeadLetters {
    plane: Arc<MessagePlane>,
}

impl BusDeadLetters {
    /// The dead letters on `plane`.
    #[must_use]
    pub fn new(plane: Arc<MessagePlane>) -> Self {
        Self { plane }
    }

    /// Removes the letter `message` when it is past `retention`, counted
    /// from when the bus first took it, and says whether it did.
    async fn removed_if_past(
        &self,
        message: &StreamMessage,
        retention: RetentionPolicy,
    ) -> Result<bool, DomainError> {
        let published = first_published(&message.headers, message.time);
        if !retention.has_aged_out(published, clock::now()) {
            return Ok(false);
        }
        in_time(
            self.plane.bus.deadline,
            self.plane.dead_letters.delete_message(message.sequence),
        )
        .await?;
        Ok(true)
    }
}

fn dead_letter_of(message: &StreamMessage) -> DeadLetter {
    DeadLetter {
        id: DeadLetterId::new(message.sequence),
        delivered: delivered_of(&message.headers),
        message: received(
            MessageKey::new(format!("dead-{}", message.sequence)),
            message.time,
            Some(&message.headers),
            &message.payload,
        ),
        set_aside_at: message.time,
    }
}

fn after_sequence(keys: Option<&[SortKey]>) -> u64 {
    match keys.and_then(<[SortKey]>::first) {
        Some(SortKey::Integer(sequence)) => u64::try_from(*sequence).unwrap_or(0),
        _ => 0,
    }
}

#[async_trait]
impl DeadLetters for BusDeadLetters {
    async fn list(
        &self,
        tenant_id: &TenantId,
        consumer_name: &str,
        retention: RetentionPolicy,
        page: &PageRequest,
    ) -> Result<Page<DeadLetter>, DomainError> {
        let durable = Durable::of(tenant_id, consumer_name);
        let order = SortOrder::<DeadLetterSortField>::default();
        let keyset = page.keyset(&order)?;
        let subject = dead_subject(self.plane.namespace(), tenant_id, &durable);
        let most = usize::try_from(keyset.fetch()).unwrap_or(usize::MAX);
        let mut letters = Vec::new();
        let mut from = after_sequence(keyset.after()).saturating_add(1);
        while letters.len() < most {
            let next = self
                .plane
                .dead_letters
                .get_first_raw_message_by_subject(&subject, from);
            let Some(message) = found(self.plane.bus.deadline, next).await? else {
                break;
            };
            from = message.sequence.saturating_add(1);
            if self.removed_if_past(&message, retention).await? {
                continue;
            }
            letters.push(dead_letter_of(&message));
        }
        Ok(keyset.seal(letters))
    }

    async fn replay(
        &self,
        tenant_id: &TenantId,
        read: ConsumerRead<'_>,
        id: DeadLetterId,
    ) -> Result<Replay, DomainError> {
        let durable = Durable::of(tenant_id, read.consumer_name);
        let subject = dead_subject(self.plane.namespace(), tenant_id, &durable);
        let held = found(
            self.plane.bus.deadline,
            self.plane.dead_letters.get_raw_message(id.get()),
        )
        .await?;
        let Some(message) = held.filter(|message| message.subject.as_str() == subject) else {
            return Ok(Replay::NotHeld);
        };
        if self.removed_if_past(&message, read.retention).await? {
            return Ok(Replay::NotHeld);
        }
        self.plane
            .publish_kept(
                &format!("replay.{}.{}", durable.as_str(), id.get()),
                Publication {
                    subject: replay_subject(self.plane.namespace(), tenant_id, &durable),
                    headers: replayed_headers(&message.headers),
                    payload: message.payload.to_vec(),
                },
            )
            .await?;
        in_time(
            self.plane.bus.deadline,
            self.plane.dead_letters.delete_message(id.get()),
        )
        .await?;
        Ok(Replay::Requeued)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::messaging::MessageConsumer as _;
    use ianua_domain::domains::messaging::message_type::MessageType;

    use super::*;
    use crate::test_support::plane::{TestPlane, tenant};

    /// A read of `consumer_name` on `topic_name` that keeps everything.
    fn unlimited<'a>(
        topic_name: &'a ianua_domain::domains::messaging::topic_name::TopicName,
        consumer_name: &'a str,
    ) -> ConsumerRead<'a> {
        ConsumerRead {
            topic_name,
            consumer_name,
            retention: RetentionPolicy::Unlimited,
        }
    }

    /// A message set aside is kept with its count among its consumer's dead
    /// letters alone, and once replayed it is handed to that consumer
    /// alone, its count starting over and its type kept.
    #[tokio::test]
    async fn a_dead_letter_is_kept_and_replayed_for_its_consumer() {
        let plane = TestPlane::open().await;
        let tenant_id = tenant();
        plane.subscribed(&tenant_id, "sub-a", None).await;
        plane.subscribed(&tenant_id, "sub-b", None).await;
        plane
            .published(&tenant_id, b"order 7", Some("order.created"))
            .await;
        let for_b = plane.handed_out(&tenant_id, "sub-b").await.remove(0);
        plane
            .consumer
            .acknowledge(&tenant_id, &plane.topic(), "sub-b", &for_b.receipt)
            .await
            .unwrap();
        let for_a = plane.handed_out(&tenant_id, "sub-a").await.remove(0);

        plane
            .consumer
            .dead_letter(&tenant_id, &plane.topic(), "sub-a", &for_a.receipt)
            .await
            .unwrap();

        let letters = plane.dead_letters_of(&tenant_id, "sub-a").await;
        assert_eq!(letters.len(), 1);
        assert_eq!(letters[0].delivered, 1);
        assert_eq!(letters[0].message.payload, b"order 7");
        assert!(plane.dead_letters_of(&tenant_id, "sub-b").await.is_empty());
        assert!(plane.handed_out(&tenant_id, "sub-a").await.is_empty());

        assert_replay(&plane, &tenant_id, letters[0].id).await;
    }

    /// Replays A's letter and checks its fresh delivery, retained headers and isolation from B.
    async fn assert_replay(plane: &TestPlane, tenant_id: &TenantId, id: DeadLetterId) {
        let replay = plane
            .dead_letters
            .replay(tenant_id, unlimited(&plane.topic(), "sub-a"), id)
            .await
            .unwrap();

        assert_eq!(replay, Replay::Requeued);
        assert!(plane.dead_letters_of(tenant_id, "sub-a").await.is_empty());
        let again = plane.handed_out(tenant_id, "sub-a").await;
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].delivered, 1);
        assert_eq!(
            again[0].message.headers,
            [("trace".to_owned(), "abc".to_owned())]
        );
        assert_eq!(
            again[0]
                .message
                .message_type
                .as_ref()
                .map(MessageType::as_str),
            Some("order.created")
        );
        assert!(plane.handed_out(tenant_id, "sub-b").await.is_empty());
    }

    /// Another consumer cannot replay a dead letter by id; the owner's letter stays stored.
    #[tokio::test]
    async fn a_dead_letter_of_another_consumer_is_not_held() {
        let plane = TestPlane::open().await;
        let tenant_id = tenant();
        plane.subscribed(&tenant_id, "sub-a", None).await;
        plane.subscribed(&tenant_id, "sub-b", None).await;
        plane.published(&tenant_id, b"order 7", None).await;
        let for_a = plane.handed_out(&tenant_id, "sub-a").await.remove(0);
        plane
            .consumer
            .dead_letter(&tenant_id, &plane.topic(), "sub-a", &for_a.receipt)
            .await
            .unwrap();
        let id = plane.dead_letters_of(&tenant_id, "sub-a").await[0].id;

        let replay = plane
            .dead_letters
            .replay(&tenant_id, unlimited(&plane.topic(), "sub-b"), id)
            .await
            .unwrap();

        assert_eq!(replay, Replay::NotHeld);
        assert_eq!(plane.dead_letters_of(&tenant_id, "sub-a").await.len(), 1);
    }

    /// A consumer removed takes its dead letters with it, and removing it
    /// again changes nothing.
    #[tokio::test]
    async fn a_removed_consumer_takes_its_dead_letters() {
        let plane = TestPlane::open().await;
        let tenant_id = tenant();
        plane.subscribed(&tenant_id, "sub-a", None).await;
        plane.published(&tenant_id, b"order 7", None).await;
        let for_a = plane.handed_out(&tenant_id, "sub-a").await.remove(0);
        plane
            .consumer
            .dead_letter(&tenant_id, &plane.topic(), "sub-a", &for_a.receipt)
            .await
            .unwrap();

        for _ in 0..2 {
            plane
                .consumer
                .delete_consumer(&tenant_id, &plane.topic(), "sub-a")
                .await
                .unwrap();
        }

        assert!(plane.dead_letters_of(&tenant_id, "sub-a").await.is_empty());
    }

    /// A limit of two seconds.
    fn limit() -> RetentionPolicy {
        RetentionPolicy::Duration(std::num::NonZeroU32::new(2).unwrap())
    }

    /// Waits past [`limit`].
    async fn limit_passed() {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }

    /// The first delivery to "sub-a" of the message published with
    /// `payload`, set aside as a dead letter; its id.
    async fn set_aside(plane: &TestPlane, tenant_id: &TenantId, payload: &[u8]) -> DeadLetterId {
        plane.published(tenant_id, payload, None).await;
        let delivery = plane.handed_out(tenant_id, "sub-a").await.remove(0);
        plane
            .consumer
            .dead_letter(tenant_id, &plane.topic(), "sub-a", &delivery.receipt)
            .await
            .unwrap();
        plane.dead_letters_of(tenant_id, "sub-a").await[0].id
    }

    /// Tess keeps a card-payment topic's messages for two seconds. A
    /// delivery failed and was set aside; once the limit is past it is
    /// neither listed nor replayable, and it is gone for good.
    #[tokio::test]
    async fn a_dead_letter_past_its_topics_limit_is_removed_when_read() {
        let plane = TestPlane::open().await;
        let tenant_id = tenant();
        plane.subscribed(&tenant_id, "sub-a", None).await;
        let id = set_aside(&plane, &tenant_id, b"card 4242").await;
        limit_passed().await;

        let replay = plane
            .dead_letters
            .replay(
                &tenant_id,
                ConsumerRead {
                    retention: limit(),
                    ..unlimited(&plane.topic(), "sub-a")
                },
                id,
            )
            .await
            .unwrap();

        assert_eq!(replay, Replay::NotHeld);
        assert!(plane.dead_letters_of(&tenant_id, "sub-a").await.is_empty());
    }

    /// A dead letter inside its limit is listed as ever.
    #[tokio::test]
    async fn a_dead_letter_inside_its_topics_limit_is_listed() {
        let plane = TestPlane::open().await;
        let tenant_id = tenant();
        plane.subscribed(&tenant_id, "sub-a", None).await;
        set_aside(&plane, &tenant_id, b"card 4242").await;
        let first = PageRequest::first(ianua_app::listing::Limit::new(10).unwrap());

        let page = plane
            .dead_letters
            .list(&tenant_id, "sub-a", limit(), &first)
            .await
            .unwrap();

        assert_eq!(page.items.len(), 1);
    }

    /// Replaying a letter does not start its limit over: once the limit
    /// from when the bus first took it is past, it is not handed out.
    #[tokio::test]
    async fn a_replay_keeps_the_age_of_the_message_it_puts_back() {
        let plane = TestPlane::open().await;
        let tenant_id = tenant();
        plane.subscribed(&tenant_id, "sub-a", None).await;
        let id = set_aside(&plane, &tenant_id, b"card 4242").await;
        plane
            .dead_letters
            .replay(&tenant_id, unlimited(&plane.topic(), "sub-a"), id)
            .await
            .unwrap();
        limit_passed().await;

        let handed = plane.handed_out_under(&tenant_id, "sub-a", limit()).await;

        assert!(handed.is_empty());
    }

    /// An old replay sits late on the stream, after a fresh message. The
    /// replay is withheld, and the fresh message is not removed with it.
    #[tokio::test]
    async fn an_old_replay_takes_no_fresh_message_with_it() {
        let plane = TestPlane::open().await;
        let tenant_id = tenant();
        plane.subscribed(&tenant_id, "sub-a", None).await;
        let id = set_aside(&plane, &tenant_id, b"old order").await;
        limit_passed().await;
        plane.published(&tenant_id, b"new order", None).await;
        plane
            .dead_letters
            .replay(&tenant_id, unlimited(&plane.topic(), "sub-a"), id)
            .await
            .unwrap();

        let handed = plane.handed_out_under(&tenant_id, "sub-a", limit()).await;

        assert_eq!(handed.len(), 1);
        assert_eq!(handed[0].message.payload, b"new order");
    }
}

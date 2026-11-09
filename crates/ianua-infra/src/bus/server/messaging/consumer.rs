//! Reading a topic through a durable consumer: one per subscription, or one
//! a consumer group shares, filtered by the server to the types it reads.
//!
//! A delivery reads as settled once the consumer's acknowledgement floor
//! passed it or its deadline ran out; one settled out of order reads open
//! until the floor reaches it, and settling it again changes nothing on
//! the server.
//!
//! A name already taken by a consumer that reads other subjects or settles
//! otherwise is refused, never joined: the server hands back the consumer
//! it holds under a name as it is, so joining it would read another
//! topic's messages and take them from the readers they were meant for.

use std::sync::Arc;
use std::time::Duration;

use async_nats::jetstream;
use async_nats::jetstream::ErrorCode;
use async_nats::jetstream::consumer::{self, AckPolicy, DeliverPolicy, pull};
use async_nats::jetstream::stream::{ConsumerError, ConsumerErrorKind};
use async_trait::async_trait;
use ianua_app::ports::messaging::{
    Acknowledgement, ConsumerRead, ConsumerSpec, DeliveryReceipt, MessageConsumer, OpenDelivery,
    PendingMessage, ReceivedMessage,
};
use ianua_domain::domains::messaging::topic::RetentionPolicy;
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use crate::bus::server::messaging::headers::{
    DELIVERED_HEADER, key_of, note_first_published, received,
};
use crate::bus::server::messaging::names::{
    Durable, Reading, dead_subject, read_subjects, replay_subject,
};
use crate::bus::server::messaging::receipt::{Delivery, unix_ms};
use crate::bus::server::messaging::retention::{Retained, TopicRead};
use crate::bus::server::messaging::{MessagePlane, found};
use crate::bus::server::{Publication, in_time, unreachable_by};
use crate::bus::stream::BusError;
use crate::namespace::Namespace;

/// Reading on the message plane.
#[derive(Debug, Clone)]
pub struct BusMessageConsumer {
    plane: Arc<MessagePlane>,
}

impl BusMessageConsumer {
    /// A consumer on `plane`.
    #[must_use]
    pub fn new(plane: Arc<MessagePlane>) -> Self {
        Self { plane }
    }

    /// The consumer held under `durable`, made as `config` says when there
    /// is none yet.
    async fn opened(
        &self,
        durable: &Durable,
        config: pull::Config,
    ) -> Result<consumer::Consumer<pull::Config>, BusError> {
        in_time(
            self.plane.bus.deadline,
            self.plane
                .messages
                .get_or_create_consumer(durable.as_str(), config),
        )
        .await
    }

    /// Purges the dead letters and the replays kept for `durable`.
    async fn purge_kept(&self, tenant_id: &TenantId, durable: &Durable) -> Result<(), BusError> {
        let namespace = self.plane.namespace();
        in_time(
            self.plane.bus.deadline,
            self.plane
                .dead_letters
                .purge()
                .filter(dead_subject(namespace, tenant_id, durable)),
        )
        .await?;
        in_time(
            self.plane.bus.deadline,
            self.plane
                .messages
                .purge()
                .filter(replay_subject(namespace, tenant_id, durable)),
        )
        .await?;
        Ok(())
    }

    fn delivery(
        &self,
        tenant_id: &TenantId,
        durable: &Durable,
        receipt: &DeliveryReceipt,
    ) -> Result<Delivery, DomainError> {
        Delivery::read(&self.plane.seal, tenant_id, durable, receipt).ok_or_else(|| {
            DomainError::invalid(message!(
                "infra-the-receipt-is-not-one-this",
                "the receipt is not one this consumer was given"
            ))
        })
    }

    fn pending(
        &self,
        tenant_id: &TenantId,
        durable: &Durable,
        message: &jetstream::Message,
    ) -> Option<PendingMessage> {
        let info = message.info().ok()?;
        let delivery = Delivery {
            reply: message.reply.as_ref()?.to_string(),
            delivered: u32::try_from(info.delivered).unwrap_or(u32::MAX),
            sequence: info.stream_sequence,
            fetched_at_ms: unix_ms(clock::now()),
        };
        Some(PendingMessage {
            message: received(
                key_of(&info),
                info.published,
                message.headers.as_ref(),
                &message.payload,
            ),
            receipt: delivery.receipt(&self.plane.seal, tenant_id, durable),
            delivered: delivery.delivered,
        })
    }
}

/// Refuses an existing consumer with different subjects or acknowledgement
/// policy than `wanted`.
fn ensure_reads_as_asked(
    held: &consumer::Config,
    wanted: &pull::Config,
) -> Result<(), DomainError> {
    let mut kept: Vec<&str> = held.filter_subjects.iter().map(String::as_str).collect();
    let mut asked: Vec<&str> = wanted.filter_subjects.iter().map(String::as_str).collect();
    kept.sort_unstable();
    asked.sort_unstable();
    if kept == asked && held.ack_policy == wanted.ack_policy {
        return Ok(());
    }
    Err(DomainError::conflict(message!(
        "infra-the-consumer-name-is-taken-by",
        "the consumer name is taken by a consumer that reads otherwise"
    )))
}

fn is_missing_consumer(error: &ConsumerError) -> bool {
    matches!(
        error.kind(),
        ConsumerErrorKind::JetStream(error) if error.error_code() == ErrorCode::CONSUMER_NOT_FOUND
    )
}

/// Configures the durable reader's subjects, delivery start and acknowledgement deadline.
fn consumer_config(
    namespace: &Namespace,
    reading: &Reading<'_>,
    acknowledgement: Acknowledgement,
) -> pull::Config {
    let (ack_policy, ack_wait) = match acknowledgement {
        Acknowledgement::OnFetch => (AckPolicy::None, Duration::ZERO),
        Acknowledgement::Explicit { deadline } => (AckPolicy::Explicit, deadline.std_duration()),
    };
    pull::Config {
        durable_name: Some(reading.durable.as_str().to_owned()),
        filter_subjects: read_subjects(namespace, reading),
        deliver_policy: DeliverPolicy::New,
        ack_policy,
        ack_wait,
        ..pull::Config::default()
    }
}

#[async_trait]
impl MessageConsumer for BusMessageConsumer {
    async fn ensure_consumer(
        &self,
        tenant_id: &TenantId,
        topic_name: &TopicName,
        consumer: &ConsumerSpec<'_>,
    ) -> Result<(), DomainError> {
        let durable = Durable::of(tenant_id, consumer.name);
        let reading = Reading {
            tenant_id,
            topic_name,
            filter: consumer.filter,
            durable: &durable,
        };
        let config = consumer_config(self.plane.namespace(), &reading, consumer.acknowledgement);
        let opened = self.opened(&durable, config.clone()).await?;
        ensure_reads_as_asked(&opened.cached_info().config, &config)
    }

    async fn pull_messages(
        &self,
        tenant_id: &TenantId,
        consumer: ConsumerRead<'_>,
        max_messages: usize,
    ) -> Result<Vec<ReceivedMessage>, DomainError> {
        let durable = Durable::of(tenant_id, consumer.consumer_name);
        let read = TopicRead {
            tenant_id,
            topic_name: consumer.topic_name,
            durable: &durable,
            retention: consumer.retention,
        };
        let Retained { inside, outside } = self.plane.read_retained(&read, max_messages).await?;
        self.plane.remove_outside(&read, &outside).await?;
        Ok(inside
            .iter()
            .filter_map(|message| {
                let info = message.info().ok()?;
                Some(received(
                    key_of(&info),
                    info.published,
                    message.headers.as_ref(),
                    &message.payload,
                ))
            })
            .collect())
    }

    async fn fetch_pending(
        &self,
        tenant_id: &TenantId,
        consumer: ConsumerRead<'_>,
        max_messages: usize,
    ) -> Result<Vec<PendingMessage>, DomainError> {
        let durable = Durable::of(tenant_id, consumer.consumer_name);
        let read = TopicRead {
            tenant_id,
            topic_name: consumer.topic_name,
            durable: &durable,
            retention: consumer.retention,
        };
        let Retained { inside, outside } = self.plane.read_retained(&read, max_messages).await?;
        for message in &outside {
            self.plane.end_delivery(message).await?;
        }
        self.plane.remove_outside(&read, &outside).await?;
        Ok(inside
            .iter()
            .filter_map(|message| self.pending(tenant_id, &durable, message))
            .collect())
    }

    async fn remove_lapsed(
        &self,
        tenant_id: &TenantId,
        topic_name: &TopicName,
        retention: RetentionPolicy,
    ) -> Result<(), DomainError> {
        Ok(self
            .plane
            .remove_lapsed(tenant_id, topic_name, retention)
            .await?)
    }

    async fn open_delivery(
        &self,
        tenant_id: &TenantId,
        _topic_name: &TopicName,
        consumer_name: &str,
        receipt: &DeliveryReceipt,
    ) -> Result<Option<OpenDelivery>, DomainError> {
        let durable = Durable::of(tenant_id, consumer_name);
        let Some(delivery) = Delivery::read(&self.plane.seal, tenant_id, &durable, receipt) else {
            return Ok(None);
        };
        let consumer = self.plane.consumer(&durable).await?;
        let info = consumer.cached_info();
        let deadline_ms = i128::try_from(info.config.ack_wait.as_millis()).unwrap_or(i128::MAX);
        let past_deadline =
            unix_ms(clock::now()) > delivery.fetched_at_ms.saturating_add(deadline_ms);
        let acknowledged = delivery.sequence <= info.ack_floor.stream_sequence;
        match past_deadline || acknowledged {
            true => Ok(None),
            false => Ok(Some(OpenDelivery {
                delivered: delivery.delivered,
            })),
        }
    }

    async fn acknowledge(
        &self,
        tenant_id: &TenantId,
        _topic_name: &TopicName,
        consumer_name: &str,
        receipt: &DeliveryReceipt,
    ) -> Result<(), DomainError> {
        let durable = Durable::of(tenant_id, consumer_name);
        let delivery = self.delivery(tenant_id, &durable, receipt)?;
        Ok(self.plane.settle(&delivery, "+ACK").await?)
    }

    async fn redeliver(
        &self,
        tenant_id: &TenantId,
        _topic_name: &TopicName,
        consumer_name: &str,
        receipt: &DeliveryReceipt,
    ) -> Result<(), DomainError> {
        let durable = Durable::of(tenant_id, consumer_name);
        let delivery = self.delivery(tenant_id, &durable, receipt)?;
        Ok(self.plane.settle(&delivery, "-NAK").await?)
    }

    async fn dead_letter(
        &self,
        tenant_id: &TenantId,
        _topic_name: &TopicName,
        consumer_name: &str,
        receipt: &DeliveryReceipt,
    ) -> Result<(), DomainError> {
        let durable = Durable::of(tenant_id, consumer_name);
        let delivery = self.delivery(tenant_id, &durable, receipt)?;
        let kept = found(
            self.plane.bus.deadline,
            self.plane.messages.get_raw_message(delivery.sequence),
        )
        .await?;
        if let Some(message) = kept {
            let mut headers = message.headers;
            headers.insert(DELIVERED_HEADER, delivery.delivered.to_string().as_str());
            note_first_published(&mut headers, message.time);
            self.plane
                .publish_kept(
                    &format!("{}.{}", durable.as_str(), delivery.sequence),
                    Publication {
                        subject: dead_subject(self.plane.namespace(), tenant_id, &durable),
                        headers,
                        payload: message.payload.to_vec(),
                    },
                )
                .await?;
        }
        Ok(self.plane.settle(&delivery, "+TERM").await?)
    }

    async fn delete_consumer(
        &self,
        tenant_id: &TenantId,
        _topic_name: &TopicName,
        consumer_name: &str,
    ) -> Result<(), DomainError> {
        let durable = Durable::of(tenant_id, consumer_name);
        let deleted = tokio::time::timeout(
            self.plane.bus.deadline,
            self.plane.messages.delete_consumer(durable.as_str()),
        )
        .await
        .map_err(|_| BusError::TimedOut)?;
        match deleted {
            Ok(_) => {}
            Err(error) if is_missing_consumer(&error) => {}
            Err(error) => return Err(unreachable_by(error).into()),
        }
        Ok(self.purge_kept(tenant_id, &durable).await?)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::messaging::message_type::MessageType;

    use super::*;
    use crate::test_support::plane::{TestPlane, tenant};

    /// A published message is handed to its subscription with its headers
    /// and its first delivery counted.
    #[tokio::test]
    async fn a_published_message_reaches_its_subscription() {
        let plane = TestPlane::open().await;
        let tenant_id = tenant();
        plane.subscribed(&tenant_id, "sub-a", None).await;

        plane.published(&tenant_id, b"order 7", None).await;

        let pending = plane.handed_out(&tenant_id, "sub-a").await;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].message.payload, b"order 7");
        assert_eq!(
            pending[0].message.headers,
            [("trace".to_owned(), "abc".to_owned())]
        );
        assert_eq!(pending[0].delivered, 1);
    }

    /// An acknowledged delivery is settled and not handed out again.
    #[tokio::test]
    async fn an_acknowledged_message_is_settled() {
        let plane = TestPlane::open().await;
        let tenant_id = tenant();
        plane.subscribed(&tenant_id, "sub-a", None).await;
        plane.published(&tenant_id, b"order 7", None).await;
        let receipt = plane
            .handed_out(&tenant_id, "sub-a")
            .await
            .remove(0)
            .receipt;

        plane
            .consumer
            .acknowledge(&tenant_id, &plane.topic(), "sub-a", &receipt)
            .await
            .unwrap();

        let open = plane
            .consumer
            .open_delivery(&tenant_id, &plane.topic(), "sub-a", &receipt)
            .await
            .unwrap();
        assert_eq!(open, None);
        assert!(plane.handed_out(&tenant_id, "sub-a").await.is_empty());
    }

    /// A delivery refused is handed out again at once, its count grown.
    #[tokio::test]
    async fn a_redelivered_message_comes_back_counted() {
        let plane = TestPlane::open().await;
        let tenant_id = tenant();
        plane.subscribed(&tenant_id, "sub-a", None).await;
        plane.published(&tenant_id, b"order 7", None).await;
        let first = plane.handed_out(&tenant_id, "sub-a").await.remove(0);
        let open = plane
            .consumer
            .open_delivery(&tenant_id, &plane.topic(), "sub-a", &first.receipt)
            .await
            .unwrap();

        plane
            .consumer
            .redeliver(&tenant_id, &plane.topic(), "sub-a", &first.receipt)
            .await
            .unwrap();

        assert_eq!(open, Some(OpenDelivery { delivered: 1 }));
        let again = plane.handed_out(&tenant_id, "sub-a").await;
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].delivered, 2);
    }

    /// Fetching another tenant's consumer fails while its owner can still receive the message.
    #[tokio::test]
    async fn a_tenant_never_reaches_anothers_consumer() {
        let plane = TestPlane::open().await;
        let owner = tenant();
        plane.subscribed(&owner, "sub-a", None).await;
        plane.published(&owner, b"order 7", None).await;

        let elsewhere = plane
            .consumer
            .fetch_pending(
                &tenant(),
                ConsumerRead {
                    topic_name: &plane.topic(),
                    consumer_name: "sub-a",
                    retention: RetentionPolicy::Unlimited,
                },
                10,
            )
            .await;

        assert!(elsewhere.is_err());
        assert_eq!(plane.handed_out(&owner, "sub-a").await.len(), 1);
    }

    /// A reader's own cursor takes what it fetches, and nothing comes back.
    #[tokio::test]
    async fn a_cursor_takes_what_it_fetches() {
        let plane = TestPlane::open().await;
        let tenant_id = tenant();
        plane
            .consumer
            .ensure_consumer(
                &tenant_id,
                &plane.topic(),
                &ConsumerSpec {
                    name: "agent-a",
                    filter: None,
                    acknowledgement: Acknowledgement::OnFetch,
                },
            )
            .await
            .unwrap();
        plane.published(&tenant_id, b"order 7", None).await;

        let topic = plane.topic();
        let pull = || {
            plane.consumer.pull_messages(
                &tenant_id,
                ConsumerRead {
                    topic_name: &topic,
                    consumer_name: "agent-a",
                    retention: RetentionPolicy::Unlimited,
                },
                10,
            )
        };
        let first = pull().await.unwrap();
        let second = pull().await.unwrap();

        assert_eq!(first.len(), 1);
        assert!(second.is_empty());
    }

    /// A subscription filtering on `order.refund` gets the refunds, and
    /// neither other types nor messages without a type; one filtering on
    /// nothing gets all three.
    #[tokio::test]
    async fn a_filter_hands_out_only_the_types_under_it() {
        let plane = TestPlane::open().await;
        let tenant_id = tenant();
        plane
            .subscribed(&tenant_id, "sub-refunds", Some("order.refund"))
            .await;
        plane.subscribed(&tenant_id, "sub-all", None).await;

        plane
            .published(&tenant_id, b"refund", Some("order.refund.requested"))
            .await;
        plane
            .published(&tenant_id, b"created", Some("order.created"))
            .await;
        plane.published(&tenant_id, b"plain", None).await;

        let refunds = plane.handed_out(&tenant_id, "sub-refunds").await;
        assert_eq!(refunds.len(), 1);
        assert_eq!(refunds[0].message.payload, b"refund");
        assert_eq!(
            refunds[0]
                .message
                .message_type
                .as_ref()
                .map(MessageType::as_str),
            Some("order.refund.requested")
        );
        assert_eq!(plane.handed_out(&tenant_id, "sub-all").await.len(), 3);
    }

    /// Reusing a consumer name for another topic returns a conflict instead of joining it.
    #[tokio::test]
    async fn a_name_taken_on_another_topic_is_refused() {
        let plane = TestPlane::open().await;
        let tenant_id = tenant();
        let name = "group-orders-x-billing";
        plane.subscribed(&tenant_id, name, None).await;
        let elsewhere = TopicName::new("orders-x").unwrap();
        let spec = ConsumerSpec {
            name,
            filter: None,
            acknowledgement: Acknowledgement::Explicit {
                deadline: ianua_domain::types::Seconds::new(30),
            },
        };

        let joined = plane
            .consumer
            .ensure_consumer(&tenant_id, &elsewhere, &spec)
            .await;

        assert!(matches!(joined, Err(DomainError::Conflict(_))));
    }

    /// The services of one group read through one consumer: a message goes
    /// to one of them, never to both.
    #[tokio::test]
    async fn a_group_shares_its_messages() {
        let plane = TestPlane::open().await;
        let tenant_id = tenant();
        let group = "group-orders.created-payment.workers";
        plane.subscribed(&tenant_id, group, None).await;
        plane.subscribed(&tenant_id, group, None).await;
        plane.published(&tenant_id, b"order 7", None).await;

        let first = plane.handed_out(&tenant_id, group).await;
        let second = plane.handed_out(&tenant_id, group).await;

        assert_eq!(first.len() + second.len(), 1);
    }
}

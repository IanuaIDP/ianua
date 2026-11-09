//! The message plane on the test bus server, through its three adapters,
//! with the steps the bus adapters' tests take on it.

#![cfg(test)]

use std::sync::Arc;

use ianua_app::listing::{Limit, PageRequest};
use ianua_app::ports::messaging::{
    Acknowledgement, ConsumerRead, ConsumerSpec, DeadLetter, DeadLetters as _,
    MessageConsumer as _, MessagePublisher as _, OutgoingMessage, PendingMessage,
};
use ianua_domain::domains::messaging::message_type::{MessageFilter, MessageType};
use ianua_domain::domains::messaging::topic::RetentionPolicy;
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::types::{Seconds, TenantId};
use uuid::Uuid;

use crate::bus::{BusDeadLetters, BusMessageConsumer, BusMessagePublisher, MessagePlane};
use crate::crypto::ReceiptSeal;
use crate::crypto::keys::tests::test_root;
use crate::test_support::bus::test_server;

/// A tenant no other test uses.
pub(crate) fn tenant() -> TenantId {
    TenantId::from_uuid(Uuid::now_v7())
}

/// The message plane on the test server, through its three adapters.
pub(crate) struct TestPlane {
    pub(crate) publisher: BusMessagePublisher,
    pub(crate) consumer: BusMessageConsumer,
    pub(crate) dead_letters: BusDeadLetters,
}

impl TestPlane {
    /// The plane, its streams made if they are not there yet.
    pub(crate) async fn open() -> Self {
        let plane = MessagePlane::open(test_server().await, ReceiptSeal::new(&test_root()))
            .await
            .expect("the test bus makes its streams");
        let plane = Arc::new(plane);
        Self {
            publisher: BusMessagePublisher::new(Arc::clone(&plane)),
            consumer: BusMessageConsumer::new(Arc::clone(&plane)),
            dead_letters: BusDeadLetters::new(plane),
        }
    }

    /// The topic every test publishes to.
    pub(crate) fn topic(&self) -> TopicName {
        TopicName::new("orders.created").expect("a valid topic name")
    }

    /// A consumer `name` of the topic that waits 30 seconds for each
    /// acknowledgement, reading the types under `filter`.
    pub(crate) async fn subscribed(&self, tenant_id: &TenantId, name: &str, filter: Option<&str>) {
        let filter = filter.map(|value| MessageFilter::new(value).expect("a valid filter"));
        let spec = ConsumerSpec {
            name,
            filter: filter.as_ref(),
            acknowledgement: Acknowledgement::Explicit {
                deadline: Seconds::new(30),
            },
        };
        self.consumer
            .ensure_consumer(tenant_id, &self.topic(), &spec)
            .await
            .expect("the consumer is made");
    }

    /// Publishes `payload` with the header `trace: abc`, as `message_type`.
    pub(crate) async fn published(
        &self,
        tenant_id: &TenantId,
        payload: &[u8],
        message_type: Option<&str>,
    ) {
        let headers = [("trace".to_owned(), "abc".to_owned())];
        let message_type = message_type.map(|value| MessageType::new(value).expect("a valid type"));
        let message = OutgoingMessage {
            payload,
            headers: &headers,
            message_type: message_type.as_ref(),
        };
        self.publisher
            .publish(tenant_id, &self.topic(), &message)
            .await
            .expect("the message is published");
    }

    /// What consumer `name` hands out now, up to ten, of a topic with no
    /// limit.
    pub(crate) async fn handed_out(&self, tenant_id: &TenantId, name: &str) -> Vec<PendingMessage> {
        self.handed_out_under(tenant_id, name, RetentionPolicy::Unlimited)
            .await
    }

    /// What consumer `name` hands out now, up to ten, of a topic keeping
    /// messages under `retention`.
    pub(crate) async fn handed_out_under(
        &self,
        tenant_id: &TenantId,
        name: &str,
        retention: RetentionPolicy,
    ) -> Vec<PendingMessage> {
        self.consumer
            .fetch_pending(
                tenant_id,
                ConsumerRead {
                    topic_name: &self.topic(),
                    consumer_name: name,
                    retention,
                },
                10,
            )
            .await
            .expect("the consumer hands out")
    }

    /// The first ten dead letters of consumer `name`.
    pub(crate) async fn dead_letters_of(
        &self,
        tenant_id: &TenantId,
        name: &str,
    ) -> Vec<DeadLetter> {
        let first = PageRequest::first(Limit::new(10).expect("a valid limit"));
        self.dead_letters
            .list(tenant_id, name, RetentionPolicy::Unlimited, &first)
            .await
            .expect("the dead letters are read")
            .items
    }
}

//! Fakes for writing to the tenant messaging bus: what is published, and
//! the shape a message is held to.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::messaging::message_type::MessageType;
use ianua_domain::domains::messaging::schema::SchemaDefinition;
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use crate::ports::messaging::{MessagePublisher, MessageShape, OutgoingMessage};
use crate::test_support::Fake;

/// One message a [`FakeMessagePublisher`] was asked to publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedMessage {
    /// The tenant it was published in.
    pub tenant_id: TenantId,
    /// The topic it was published to.
    pub topic_name: TopicName,
    /// The raw bytes submitted by the publisher.
    pub payload: Vec<u8>,
    /// The headers it carried.
    pub headers: Vec<(String, String)>,
    /// The type it was published as.
    pub message_type: Option<MessageType>,
}

/// Message publisher that records every message instead of sending it.
#[derive(Default)]
pub struct FakeMessagePublisher {
    published: Mutex<Vec<PublishedMessage>>,
}

impl FakeMessagePublisher {
    /// A publisher that has published nothing.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// How many messages were published.
    #[must_use]
    pub fn count(&self) -> usize {
        self.published.lock().unwrap().len()
    }

    /// Every message published, in order.
    #[must_use]
    pub fn published(&self) -> Vec<PublishedMessage> {
        self.published.lock().unwrap().clone()
    }
}

#[async_trait]
impl MessagePublisher for FakeMessagePublisher {
    async fn publish(
        &self,
        tenant_id: &TenantId,
        topic_name: &TopicName,
        message: &OutgoingMessage<'_>,
    ) -> Result<(), DomainError> {
        self.published.lock().unwrap().push(PublishedMessage {
            tenant_id: *tenant_id,
            topic_name: topic_name.clone(),
            payload: message.payload.to_vec(),
            headers: message.headers.to_vec(),
            message_type: message.message_type.cloned(),
        });
        Ok(())
    }
}

impl Fake for Arc<dyn MessagePublisher> {
    fn fake() -> Self {
        Arc::new(FakeMessagePublisher::empty())
    }
}

/// Accepts only JSON objects and strips every space, standing in for the
/// real canonical form, whatever the schema.
pub struct ObjectsWithoutSpaces;

impl MessageShape for ObjectsWithoutSpaces {
    fn conform(&self, _schema: &SchemaDefinition, payload: &[u8]) -> Result<Vec<u8>, DomainError> {
        if payload.first() != Some(&b'{') {
            return Err(DomainError::invalid("the payload is not a JSON object"));
        }
        Ok(payload.iter().copied().filter(|b| *b != b' ').collect())
    }
}

impl Fake for Arc<dyn MessageShape> {
    fn fake() -> Self {
        Arc::new(ObjectsWithoutSpaces)
    }
}

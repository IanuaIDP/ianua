//! The topic, subscription or schema a messaging request names.

use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::types::{EventSchemaId, MessageSubscriptionId, TopicId};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::ApiError;

/// `.../messaging/topics/{id}/...`.
#[derive(Deserialize)]
pub(crate) struct TopicPath {
    id: Uuid,
}

impl TopicPath {
    /// The topic named.
    #[must_use]
    pub(crate) fn topic(&self) -> TopicId {
        TopicId::from_uuid(self.id)
    }
}

/// `.../messaging/topics/{name}/publish` and `.../stream`: a topic by its
/// topic name.
#[derive(Deserialize)]
pub(crate) struct TopicNamePath {
    name: String,
}

impl TopicNamePath {
    /// The topic name.
    ///
    /// # Errors
    ///
    /// `ApiError` (422) when the path segment is not a valid topic name.
    pub(crate) fn topic_name(&self) -> Result<TopicName, ApiError> {
        TopicName::new(self.name.as_str()).map_err(ApiError::validation)
    }
}

/// `.../messaging/subscriptions/{id}/...`.
#[derive(Deserialize)]
pub(crate) struct SubscriptionPath {
    id: Uuid,
}

impl SubscriptionPath {
    /// The subscription named.
    #[must_use]
    pub(crate) fn subscription(&self) -> MessageSubscriptionId {
        MessageSubscriptionId::from_uuid(self.id)
    }
}

/// `.../messaging/subscriptions/{id}/dead-letters/{dead_letter_id}/...`.
#[derive(Deserialize)]
pub(crate) struct DeadLetterPath {
    id: Uuid,
    dead_letter_id: u64,
}

impl DeadLetterPath {
    /// The subscription named.
    #[must_use]
    pub(crate) fn subscription(&self) -> MessageSubscriptionId {
        MessageSubscriptionId::from_uuid(self.id)
    }

    /// The dead letter named, by the id its listing gave it.
    #[must_use]
    pub(crate) fn dead_letter(&self) -> u64 {
        self.dead_letter_id
    }
}

/// `.../messaging/schemas/{id}/...`.
#[derive(Deserialize)]
pub(crate) struct SchemaPath {
    id: Uuid,
}

impl SchemaPath {
    /// The schema named.
    #[must_use]
    pub(crate) fn schema(&self) -> EventSchemaId {
        EventSchemaId::from_uuid(self.id)
    }
}

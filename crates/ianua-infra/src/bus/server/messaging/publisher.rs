//! Publishing to a tenant's topic: the message kept on the subject of its
//! topic and type, once the server confirmed it.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::messaging::{MessagePublisher, OutgoingMessage};
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use crate::bus::server::messaging::MessagePlane;
use crate::bus::server::messaging::headers::{TYPE_HEADER, checked_headers};
use crate::bus::server::messaging::names::message_subject;
use crate::bus::server::{Publication, publish_and_confirm};

/// Publishing on the message plane.
#[derive(Debug, Clone)]
pub struct BusMessagePublisher {
    plane: Arc<MessagePlane>,
}

impl BusMessagePublisher {
    /// A publisher on `plane`.
    #[must_use]
    pub fn new(plane: Arc<MessagePlane>) -> Self {
        Self { plane }
    }
}

#[async_trait]
impl MessagePublisher for BusMessagePublisher {
    async fn publish(
        &self,
        tenant_id: &TenantId,
        topic_name: &TopicName,
        message: &OutgoingMessage<'_>,
    ) -> Result<(), DomainError> {
        let mut headers = checked_headers(message.headers)?;
        if let Some(message_type) = message.message_type {
            headers.insert(TYPE_HEADER, message_type.as_str());
        }
        Ok(publish_and_confirm(
            &self.plane.bus.events,
            self.plane.bus.deadline,
            Publication {
                subject: message_subject(
                    self.plane.namespace(),
                    tenant_id,
                    topic_name,
                    message.message_type,
                ),
                headers,
                payload: message.payload.to_vec(),
            },
        )
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::plane::{TestPlane, tenant};

    /// Publishing with a caller-supplied message-type header is refused.
    #[tokio::test]
    async fn a_reserved_header_is_refused() {
        let plane = TestPlane::open().await;
        let headers = [("Ianua-Message-Type".to_owned(), "x".to_owned())];
        let message = OutgoingMessage {
            payload: b"x",
            headers: &headers,
            message_type: None,
        };

        let published = plane
            .publisher
            .publish(&tenant(), &plane.topic(), &message)
            .await;

        assert!(published.is_err());
    }
}

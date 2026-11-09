//! The agent message plane where there is none: a deployment whose bus
//! lives in its own process keeps no durable consumers and no dead
//! letters, so every message is refused rather than taken and lost.

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest};
use ianua_app::ports::messaging::{
    ConsumerRead, ConsumerSpec, DeadLetter, DeadLetterId, DeadLetters, DeliveryReceipt,
    MessageConsumer, MessagePublisher, OpenDelivery, OutgoingMessage, PendingMessage,
    ReceivedMessage, Replay,
};
use ianua_domain::domains::messaging::topic::RetentionPolicy;
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

/// A message handed to a deployment with no message plane.
#[derive(Debug, thiserror::Error)]
#[error("the agent message plane runs on a bus server, and this deployment's bus is in process")]
struct NoPlane;

/// The refusal every call answers.
fn refused<T>() -> Result<T, DomainError> {
    Err(DomainError::infra(NoPlane))
}

/// No message plane to publish on: every publish refused.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoMessagePublisher;

/// No message plane to pull from: every pull and settle refused.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoMessageConsumer;

/// No message plane keeping dead letters: every list and replay refused.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDeadLetters;

#[async_trait]
impl MessagePublisher for NoMessagePublisher {
    async fn publish(
        &self,
        _tenant_id: &TenantId,
        _topic_name: &TopicName,
        _message: &OutgoingMessage<'_>,
    ) -> Result<(), DomainError> {
        refused()
    }
}

#[async_trait]
impl MessageConsumer for NoMessageConsumer {
    async fn ensure_consumer(
        &self,
        _tenant_id: &TenantId,
        _topic_name: &TopicName,
        _consumer: &ConsumerSpec<'_>,
    ) -> Result<(), DomainError> {
        refused()
    }

    async fn pull_messages(
        &self,
        _tenant_id: &TenantId,
        _read: ConsumerRead<'_>,
        _max_messages: usize,
    ) -> Result<Vec<ReceivedMessage>, DomainError> {
        refused()
    }

    async fn fetch_pending(
        &self,
        _tenant_id: &TenantId,
        _read: ConsumerRead<'_>,
        _max_messages: usize,
    ) -> Result<Vec<PendingMessage>, DomainError> {
        refused()
    }

    async fn remove_lapsed(
        &self,
        _tenant_id: &TenantId,
        _topic_name: &TopicName,
        _retention: RetentionPolicy,
    ) -> Result<(), DomainError> {
        refused()
    }

    async fn open_delivery(
        &self,
        _tenant_id: &TenantId,
        _topic_name: &TopicName,
        _consumer_name: &str,
        _receipt: &DeliveryReceipt,
    ) -> Result<Option<OpenDelivery>, DomainError> {
        refused()
    }

    async fn acknowledge(
        &self,
        _tenant_id: &TenantId,
        _topic_name: &TopicName,
        _consumer_name: &str,
        _receipt: &DeliveryReceipt,
    ) -> Result<(), DomainError> {
        refused()
    }

    async fn redeliver(
        &self,
        _tenant_id: &TenantId,
        _topic_name: &TopicName,
        _consumer_name: &str,
        _receipt: &DeliveryReceipt,
    ) -> Result<(), DomainError> {
        refused()
    }

    async fn dead_letter(
        &self,
        _tenant_id: &TenantId,
        _topic_name: &TopicName,
        _consumer_name: &str,
        _receipt: &DeliveryReceipt,
    ) -> Result<(), DomainError> {
        refused()
    }

    async fn delete_consumer(
        &self,
        _tenant_id: &TenantId,
        _topic_name: &TopicName,
        _consumer_name: &str,
    ) -> Result<(), DomainError> {
        refused()
    }
}

#[async_trait]
impl DeadLetters for NoDeadLetters {
    async fn list(
        &self,
        _tenant_id: &TenantId,
        _consumer_name: &str,
        _retention: RetentionPolicy,
        _page: &PageRequest,
    ) -> Result<Page<DeadLetter>, DomainError> {
        refused()
    }

    async fn replay(
        &self,
        _tenant_id: &TenantId,
        _read: ConsumerRead<'_>,
        _id: DeadLetterId,
    ) -> Result<Replay, DomainError> {
        refused()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pulling messages without a message plane returns an infrastructure error.
    #[tokio::test]
    async fn a_message_is_refused_rather_than_lost() {
        let topic = TopicName::new("orders").unwrap();
        let consumed = NoMessageConsumer
            .pull_messages(
                &TenantId::new(),
                ConsumerRead {
                    topic_name: &topic,
                    consumer_name: "worker",
                    retention: RetentionPolicy::Unlimited,
                },
                10,
            )
            .await;

        assert!(matches!(consumed, Err(DomainError::Infrastructure(_))));
    }
}

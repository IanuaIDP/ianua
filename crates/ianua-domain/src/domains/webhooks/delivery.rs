use time::OffsetDateTime;

use crate::types::{
    DeliveryOutcome, DeliveryResult, EventType, WebhookDeliveryId, WebhookMessageId,
    WebhookSubscriptionId,
};

/// The outcome of a webhook delivery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum WebhookDeliveryStatus {
    /// The upstream returned a 2xx response.
    Success,
    /// The upstream returned a non-2xx response.
    Failed,
    /// The request timed out.
    Timeout,
    /// The request could not be sent, for example after a DNS failure or a
    /// refused connection.
    Unreachable,
}

impl From<DeliveryResult> for WebhookDeliveryStatus {
    fn from(result: DeliveryResult) -> Self {
        match result {
            DeliveryResult::Success => Self::Success,
            DeliveryResult::Failed => Self::Failed,
            DeliveryResult::Timeout => Self::Timeout,
            DeliveryResult::Unreachable => Self::Unreachable,
        }
    }
}

/// A record of one try at delivering a webhook.
///
/// Each try is kept for debugging and audit. One event has several
/// records when its delivery is retried.
#[derive(Debug, Clone)]
pub struct DeliveryAttempt {
    /// Unique attempt identifier.
    pub id: WebhookDeliveryId,
    /// The message sent, the same on each attempt to deliver it, so the
    /// receiver handles it once.
    pub message_id: WebhookMessageId,
    /// The subscription this delivery was for.
    pub subscription_id: WebhookSubscriptionId,
    /// The event type that triggered the delivery.
    pub event_type: EventType,
    /// How the attempt ended, with the code the upstream answered with.
    pub outcome: DeliveryOutcome,
    /// How long the request took in milliseconds.
    pub duration_ms: u32,
    /// Which try this is. The first try is 0.
    pub attempt_number: u8,
    /// When the attempt was made.
    pub attempted_at: OffsetDateTime,
}

impl DeliveryAttempt {
    /// The outcome of the attempt, read from how it ended.
    #[must_use]
    pub fn status(&self) -> WebhookDeliveryStatus {
        self.outcome.result().into()
    }
}

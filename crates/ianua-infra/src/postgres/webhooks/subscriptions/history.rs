//! A webhook's delivery history as its rows hold it, the body of each
//! message and every try at sending one: read back into the port's
//! values, and written out from them.

use ianua_app::ports::webhooks::WebhookMessage;
use ianua_domain::domains::webhooks::delivery::{DeliveryAttempt, WebhookDeliveryStatus};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    DeliveryOutcome, DeliveryResult, WebhookDeliveryId, WebhookMessageId, WebhookSubscriptionId,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};
use crate::postgres::webhooks::subscriptions::record::event_type_from;

const DELIVERY: Stored = Stored("webhook delivery");

const MESSAGE: Stored = Stored("webhook message");

/// A try as it is read. The store's checked queries fill it.
pub(super) struct DeliveryRecord {
    pub(super) id: Uuid,
    pub(super) subscription_id: Uuid,
    pub(super) message_id: Uuid,
    pub(super) event_type: String,
    pub(super) status: String,
    pub(super) response_code: Option<i32>,
    pub(super) duration_ms: i64,
    pub(super) attempt_number: i16,
    pub(super) attempted_at: OffsetDateTime,
}

impl DeliveryRecord {
    /// The try the record holds, its outcome read through the domain's
    /// rule that the code fits the result.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a word or an event type
    /// is unknown, a number is out of range, or the code contradicts the
    /// outcome.
    pub(super) fn into_attempt(self) -> Result<DeliveryAttempt, DomainError> {
        let out_of_range = || DomainError::corrupt_row(DELIVERY.0, "a number out of range");
        let code = self
            .response_code
            .map(u16::try_from)
            .transpose()
            .map_err(|_| out_of_range())?;
        let status: WebhookDeliveryStatus = DELIVERY.choice(&self.status)?;
        Ok(DeliveryAttempt {
            id: WebhookDeliveryId::from_uuid(self.id),
            message_id: WebhookMessageId::from_uuid(self.message_id),
            subscription_id: WebhookSubscriptionId::from_uuid(self.subscription_id),
            event_type: event_type_from(DELIVERY, &self.event_type)?,
            outcome: DeliveryOutcome::from_stored(result_of(status), code)?,
            duration_ms: u32::try_from(self.duration_ms).map_err(|_| out_of_range())?,
            attempt_number: u8::try_from(self.attempt_number).map_err(|_| out_of_range())?,
            attempted_at: self.attempted_at,
        })
    }
}

/// The result a stored status reads as.
fn result_of(status: WebhookDeliveryStatus) -> DeliveryResult {
    match status {
        WebhookDeliveryStatus::Success => DeliveryResult::Success,
        WebhookDeliveryStatus::Failed => DeliveryResult::Failed,
        WebhookDeliveryStatus::Timeout => DeliveryResult::Timeout,
        WebhookDeliveryStatus::Unreachable => DeliveryResult::Unreachable,
    }
}

/// A try's columns, as they are written.
pub(super) struct DeliveryColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) subscription_id: &'a Uuid,
    pub(super) message_id: &'a Uuid,
    pub(super) event_type: &'static str,
    pub(super) status: &'static str,
    pub(super) response_code: Option<i32>,
    pub(super) duration_ms: i64,
    pub(super) attempt_number: i16,
    pub(super) attempted_at: OffsetDateTime,
}

impl<'a> DeliveryColumns<'a> {
    /// The columns `attempt` is written to.
    pub(super) fn of(attempt: &'a DeliveryAttempt) -> Self {
        Self {
            id: attempt.id.as_uuid(),
            subscription_id: attempt.subscription_id.as_uuid(),
            message_id: attempt.message_id.as_uuid(),
            event_type: attempt.event_type.as_str(),
            status: attempt.status().word(),
            response_code: attempt.outcome.response_code().map(i32::from),
            duration_ms: i64::from(attempt.duration_ms),
            attempt_number: i16::from(attempt.attempt_number),
            attempted_at: attempt.attempted_at,
        }
    }
}

/// A kept message as it is read. The store's checked queries fill it.
pub(super) struct MessageRecord {
    pub(super) id: Uuid,
    pub(super) subscription_id: Uuid,
    pub(super) event_type: String,
    pub(super) payload: Vec<u8>,
}

impl MessageRecord {
    /// The message the record holds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the event type is
    /// unknown.
    pub(super) fn into_message(self) -> Result<WebhookMessage, DomainError> {
        Ok(WebhookMessage {
            id: WebhookMessageId::from_uuid(self.id),
            subscription_id: WebhookSubscriptionId::from_uuid(self.subscription_id),
            event_type: event_type_from(MESSAGE, &self.event_type)?,
            payload: self.payload,
        })
    }
}

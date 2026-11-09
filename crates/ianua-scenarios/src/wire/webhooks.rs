//! A tenant's webhooks, as its administrators manage them: subscriptions,
//! their signing secret, the events they may receive and how each
//! delivery attempt ended.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `POST …/webhooks`: the endpoint to send events to.
#[derive(Debug, Clone, Serialize)]
pub struct NewWebhook {
    /// The HTTPS address on the public internet events are posted to.
    pub url: String,
    /// The events received, such as `{"Identity":"UserRegistered"}`. Empty
    /// means every event the creator may see now.
    pub event_types: Vec<Value>,
    /// What it is for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// `Standard`, `Aggressive` or `Patient`; `Standard` when left out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry: Option<String>,
}

/// A subscription just made.
#[derive(Clone, Deserialize)]
pub struct WebhookCreated {
    /// The id its later calls name it by.
    pub id: String,
    /// The signing secret, shown this once.
    pub signing_secret: String,
}

/// A webhook subscription, as read back: never its secret.
#[derive(Debug, Clone, Deserialize)]
pub struct Webhook {
    /// The id the webhook's own endpoints take in their path.
    pub id: String,
    /// Where events go.
    pub url: String,
    /// `Active`, `Paused` or `Disabled`.
    pub status: String,
    /// What it is for.
    #[serde(default)]
    pub description: Option<String>,
    /// How hard failed deliveries are retried.
    pub retry: String,
    /// Deliveries that failed in a row.
    pub consecutive_failures: u32,
}

/// `PATCH …/webhooks/{id}`: a field left out keeps its value.
#[derive(Debug, Clone, Default, Serialize)]
pub struct WebhookChange {
    /// A new address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// A new description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// `POST …/webhooks/{id}/rotate-secret`: how long the old secret keeps
/// signing, or at once when left out.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct RotateWebhookSecret {
    /// Seconds the old secret keeps signing beside the new one.
    pub overlap_seconds: i64,
}

/// A secret just issued.
#[derive(Clone, Deserialize)]
pub struct WebhookSecret {
    /// The new signing secret, shown this once.
    pub signing_secret: String,
}

/// `POST …/webhooks/{id}/test`: which listed event the sample stands for.
#[derive(Debug, Clone, Serialize)]
pub struct WebhookTestEvent {
    /// The event, such as `{"Identity":"UserRegistered"}`.
    pub event_type: Value,
}

/// One event a webhook may be subscribed to.
#[derive(Debug, Clone, Deserialize)]
pub struct WebhookEventType {
    /// The event as a subscription lists it.
    pub event_type: Value,
    /// Its dotted name.
    pub name: String,
}

/// One delivery attempt.
#[derive(Debug, Clone, Deserialize)]
pub struct WebhookDelivery {
    /// The id a resend names the attempt by.
    pub id: String,
    /// The message sent: the same on every try to deliver it, and on a
    /// resend.
    pub message_id: String,
    /// The subscription it was for.
    pub subscription_id: String,
    /// How it ended: `Success`, `Failed`, `Timeout` or `Unreachable`.
    pub status: String,
    /// The code the receiver answered with, when it answered.
    #[serde(default)]
    pub response_status: Option<u16>,
    /// Which try this was, the first being 0.
    pub attempt_number: u8,
}

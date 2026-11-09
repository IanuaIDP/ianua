//! Webhook bodies: a subscription, its signing secret, the events it may
//! receive, and its delivery history.

use ianua_app::use_cases::webhooks::delivery::{ResendRequest, SendTestEventRequest};
use ianua_app::use_cases::webhooks::subscriptions::{
    CreateRequest, CreatedSubscription, RotateSecretRequest, UpdateRequest,
};
use ianua_domain::domains::webhooks::catalog::CatalogEntry;
use ianua_domain::domains::webhooks::delivery::{DeliveryAttempt, WebhookDeliveryStatus};
use ianua_domain::domains::webhooks::retry_policy::RetryPreset;
use ianua_domain::domains::webhooks::subscription::{WebhookSubscription, WebhookUpdate};
use ianua_domain::domains::webhooks::subscription_status::WebhookSubscriptionStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    EventType, PublicHttpsUrl, Setting, Text, WebhookDeliveryId, WebhookSubscriptionId,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;
use crate::extractors::time::rotation_overlap;

/// Request body for creating a webhook subscription.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateSubscriptionBody {
    /// The HTTPS URL on the public internet to deliver events to.
    pub url: String,
    /// Event types to subscribe to, such as `{"Tenant":"StatusChanged"}`.
    /// Empty means every event the creator may see now.
    #[serde(default)]
    #[schema(value_type = Vec<Object>)]
    pub event_types: Vec<EventType>,
    /// Optional description.
    pub description: Option<String>,
    /// How hard failed deliveries are retried: `Standard` (the default),
    /// `Aggressive` (few, quick retries) or `Patient` (many, spread over an
    /// hour).
    #[serde(default)]
    #[schema(schema_with = crate::dto::schemas::retry_preset)]
    pub retry: Option<RetryPreset>,
}

impl TryFrom<CreateSubscriptionBody> for CreateRequest {
    type Error = ApiError;

    fn try_from(body: CreateSubscriptionBody) -> Result<Self, Self::Error> {
        Ok(Self {
            url: public_url(body.url)?,
            event_types: body.event_types,
            description: body.description.map(description).transpose()?,
            retry: body.retry.unwrap_or(RetryPreset::Standard),
        })
    }
}

/// Request body for changing a webhook subscription. A field left out keeps
/// what the subscription has.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateSubscriptionBody {
    /// A new HTTPS URL on the public internet. Its failure count starts
    /// again from nothing.
    pub url: Option<String>,
    /// New event types. Empty means every event the caller may see now.
    #[schema(value_type = Option<Vec<Object>>)]
    pub event_types: Option<Vec<EventType>>,
    /// A new description, or `null` to clear it.
    #[serde(default, deserialize_with = "crate::patch::nullable::deserialize")]
    #[schema(value_type = Option<String>)]
    pub description: Option<Option<String>>,
    /// A new retry policy: `Standard`, `Aggressive` or `Patient`.
    #[schema(schema_with = crate::dto::schemas::retry_preset)]
    pub retry: Option<RetryPreset>,
}

impl UpdateSubscriptionBody {
    /// The change this body makes to `subscription_id`.
    ///
    /// # Errors
    ///
    /// `ApiError` (422) when the URL is not public HTTPS or the description
    /// is not valid.
    pub(crate) fn update_of(
        self,
        subscription_id: WebhookSubscriptionId,
    ) -> Result<UpdateRequest, ApiError> {
        Ok(UpdateRequest {
            subscription_id,
            update: WebhookUpdate {
                url: self.url.map(public_url).transpose()?,
                event_types: self.event_types,
                description: self.description.map(description_setting).transpose()?,
                retry: self.retry,
            },
        })
    }
}

/// `url` as a public HTTPS address deliveries may reach.
fn public_url(url: String) -> Result<PublicHttpsUrl, ApiError> {
    PublicHttpsUrl::new(url).map_err(ApiError::validation)
}

/// `text` as a subscription's description.
fn description(text: String) -> Result<Text, ApiError> {
    Text::new("description", text).map_err(ApiError::validation)
}

/// A new description, or none for `null`.
fn description_setting(text: Option<String>) -> Result<Setting<Text>, ApiError> {
    Ok(Setting::from_stored(text.map(description).transpose()?))
}

/// Request body for rotating a signing secret.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RotateSecretBody {
    /// How long, in seconds, the old secret keeps signing beside the new
    /// one, at most seven days, while the receiving servers move over.
    /// Left out, the old secret stops at once, as after a leak.
    pub overlap_seconds: Option<i64>,
}

impl RotateSecretBody {
    /// The rotation of `subscription_id`'s secret `body` asks for: with no
    /// body, the old secret stops at once.
    ///
    /// # Errors
    ///
    /// `ApiError` (422) when the overlap is not a positive number of seconds.
    pub(crate) fn rotation_of(
        subscription_id: WebhookSubscriptionId,
        body: Option<Self>,
    ) -> Result<RotateSecretRequest, ApiError> {
        Ok(RotateSecretRequest {
            subscription_id,
            overlap: rotation_overlap(body.and_then(|body| body.overlap_seconds))?,
        })
    }
}

/// Request body for sending a test event.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SendTestEventBody {
    /// The event the sample stands for, such as
    /// `{"Identity":"UserRegistered"}`. The subscription must list it.
    #[schema(value_type = Object)]
    pub event_type: EventType,
}

impl SendTestEventBody {
    /// A test of `subscription_id` with this event.
    #[must_use]
    pub(crate) fn test_of(self, subscription_id: WebhookSubscriptionId) -> SendTestEventRequest {
        SendTestEventRequest {
            subscription_id,
            event_type: self.event_type,
        }
    }
}

/// Resending attempt `delivery_id` of `subscription_id`.
#[must_use]
pub(crate) fn resend_of(
    subscription_id: WebhookSubscriptionId,
    delivery_id: WebhookDeliveryId,
) -> ResendRequest {
    ResendRequest {
        subscription_id,
        delivery_id,
    }
}

/// Query parameters for listing webhook subscriptions.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct SubscriptionFilterParams {
    /// Only subscriptions in this status: `Active`, `Paused` or `Disabled`.
    /// Left out for every status.
    #[param(value_type = Option<String>)]
    pub status: Option<WebhookSubscriptionStatus>,
}

/// A webhook subscription.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SubscriptionResponse {
    /// Unique subscription identifier.
    pub id: Uuid,
    /// The delivery target URL.
    pub url: String,
    /// Event types this subscription receives.
    #[schema(value_type = Vec<Object>)]
    pub event_types: Vec<EventType>,
    /// Current delivery status.
    #[schema(schema_with = crate::dto::schemas::webhook_subscription_status)]
    pub status: WebhookSubscriptionStatus,
    /// Optional description.
    pub description: Option<String>,
    /// How hard failed deliveries are retried: `Standard`, `Aggressive` or
    /// `Patient`.
    #[schema(schema_with = crate::dto::schemas::retry_preset)]
    pub retry: RetryPreset,
    /// Deliveries that failed in a row.
    pub consecutive_failures: u32,
    /// When the last successful delivery was made.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_delivered_at: Option<OffsetDateTime>,
    /// When this subscription was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl From<WebhookSubscription<ResolvedTenant>> for SubscriptionResponse {
    fn from(subscription: WebhookSubscription<ResolvedTenant>) -> Self {
        Self {
            id: *subscription.id().as_uuid(),
            url: subscription.url().as_str().to_owned(),
            event_types: subscription.event_types().to_vec(),
            status: subscription.status(),
            description: subscription.description().map(|t| t.as_str().to_owned()),
            retry: subscription.retry(),
            consecutive_failures: subscription.consecutive_failures(),
            last_delivered_at: subscription.last_delivered_at(),
            created_at: subscription.created_at(),
        }
    }
}

/// Answer to creating a subscription, with its signing secret.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CreateSubscriptionResponse {
    /// The subscription's unique identifier.
    pub id: Uuid,
    /// The raw signing secret. It is shown this once; store it to verify
    /// deliveries.
    pub signing_secret: String,
}

impl From<CreatedSubscription> for CreateSubscriptionResponse {
    fn from(created: CreatedSubscription) -> Self {
        Self {
            id: *created.subscription_id.as_uuid(),
            signing_secret: created.signing_secret.expose().to_owned(),
        }
    }
}

/// Answer to rotating a signing secret.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RotateSecretResponse {
    /// The new raw signing secret. It is shown this once; store it to verify
    /// deliveries.
    pub signing_secret: String,
}

impl From<Secret> for RotateSecretResponse {
    fn from(secret: Secret) -> Self {
        Self {
            signing_secret: secret.expose().to_owned(),
        }
    }
}

/// One event a webhook may be subscribed to.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct EventTypeResponse {
    /// The event, as a subscription lists it, such as
    /// `{"Identity":"UserRegistered"}`.
    #[schema(value_type = Object)]
    pub event_type: EventType,
    /// Its dotted name, such as `identity.user_registered`.
    pub name: &'static str,
    /// What it means.
    pub description: &'static str,
}

impl From<CatalogEntry> for EventTypeResponse {
    fn from(entry: CatalogEntry) -> Self {
        Self {
            event_type: entry.event_type(),
            name: entry.name(),
            description: entry.description(),
        }
    }
}

/// One webhook delivery attempt.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct DeliveryAttemptResponse {
    /// Unique attempt identifier.
    pub id: Uuid,
    /// The message sent: the same on every attempt to deliver it, and on a
    /// resend, so a receiver handles it once. Sent as `webhook-id`.
    pub message_id: Uuid,
    /// The subscription this delivery was for.
    pub subscription_id: Uuid,
    /// The event type that caused the delivery.
    #[schema(value_type = Object)]
    pub event_type: EventType,
    /// How the attempt ended: `Success`, `Failed`, `Timeout` or
    /// `Unreachable`.
    #[schema(schema_with = crate::dto::schemas::webhook_delivery_status)]
    pub status: WebhookDeliveryStatus,
    /// The HTTP status code the receiver answered with, if it answered.
    pub response_status: Option<u16>,
    /// How long the request took, in milliseconds.
    pub duration_ms: u32,
    /// Which try this is (0 is the first).
    pub attempt_number: u8,
    /// When the attempt was made.
    #[serde(with = "time::serde::rfc3339")]
    pub attempted_at: OffsetDateTime,
}

impl From<DeliveryAttempt> for DeliveryAttemptResponse {
    fn from(attempt: DeliveryAttempt) -> Self {
        Self {
            id: *attempt.id.as_uuid(),
            message_id: *attempt.message_id.as_uuid(),
            subscription_id: *attempt.subscription_id.as_uuid(),
            event_type: attempt.event_type,
            status: attempt.status(),
            response_status: attempt.outcome.response_code(),
            duration_ms: attempt.duration_ms,
            attempt_number: attempt.attempt_number,
            attempted_at: attempt.attempted_at,
        }
    }
}

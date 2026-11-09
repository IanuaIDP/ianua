//! Webhook subscription lifecycle events.

use time::OffsetDateTime;

use crate::domains::webhooks::delivery::WebhookDeliveryStatus;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{EventType, UrlOrigin, WebhookSubscriptionId};

/// A new webhook subscription was created.
#[derive(Debug)]
pub(crate) struct WebhookSubscriptionCreated {
    /// The newly created subscription.
    pub(crate) subscription_id: WebhookSubscriptionId,
    /// Where deliveries go, as its origin only.
    pub(crate) endpoint: UrlOrigin,
    /// When the subscription was created.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WebhookSubscriptionCreated => crate::types::event_type::WebhooksEvent::SubscriptionCreated,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "subscription",
            Reference::new(
                RefKind::WEBHOOK,
                self.subscription_id.to_string(),
                self.endpoint.as_str(),
            ),
        )
    }
}

/// A webhook subscription was paused by an admin.
///
/// Events raised while it is paused are not delivered, then or later.
#[derive(Debug)]
pub(crate) struct WebhookSubscriptionPaused {
    /// The paused subscription.
    pub(crate) subscription_id: WebhookSubscriptionId,
    /// Where deliveries go, as the origin only. It is copied when the event
    /// is written, so the audit entry stays readable after the subscription
    /// changes or is removed.
    pub(crate) endpoint: UrlOrigin,
    /// When the pause occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WebhookSubscriptionPaused => crate::types::event_type::WebhooksEvent::SubscriptionPaused,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "subscription",
            Reference::new(
                RefKind::WEBHOOK,
                self.subscription_id.to_string(),
                self.endpoint.as_str(),
            ),
        )
    }
}

/// A paused webhook subscription was resumed.
///
/// New events are delivered again. Events raised during the pause are not
/// sent.
#[derive(Debug)]
pub(crate) struct WebhookSubscriptionResumed {
    /// The resumed subscription.
    pub(crate) subscription_id: WebhookSubscriptionId,
    /// Where deliveries go, as the origin only. It is copied when the event
    /// is written, so the audit entry stays readable after the subscription
    /// changes or is removed.
    pub(crate) endpoint: UrlOrigin,
    /// When the resume occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WebhookSubscriptionResumed => crate::types::event_type::WebhooksEvent::SubscriptionResumed,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "subscription",
            Reference::new(
                RefKind::WEBHOOK,
                self.subscription_id.to_string(),
                self.endpoint.as_str(),
            ),
        )
    }
}

/// A webhook subscription was disabled for good after too many
/// consecutive delivery failures.
///
/// A disabled subscription cannot be turned back on. The tenant replaces it
/// with a new one.
#[derive(Debug)]
pub(crate) struct WebhookSubscriptionDisabled {
    /// The disabled subscription.
    pub(crate) subscription_id: WebhookSubscriptionId,
    /// Where deliveries go, as the origin only. It is copied when the event
    /// is written, so the audit entry stays readable after the subscription
    /// changes or is removed.
    pub(crate) endpoint: UrlOrigin,
    /// Number of consecutive failures that triggered the disable.
    pub(crate) consecutive_failures: u32,
    /// When the disable occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WebhookSubscriptionDisabled => crate::types::event_type::WebhooksEvent::SubscriptionDisabled,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "subscription",
                Reference::new(
                    RefKind::WEBHOOK,
                    self.subscription_id.to_string(),
                    self.endpoint.as_str(),
                ),
            )
            .field(
                "consecutive_failures",
                self.consecutive_failures.to_string(),
            )
    }
}

/// A webhook subscription was permanently deleted.
///
/// Deleting stops all future deliveries and removes the delivery history.
/// Without this record, nothing would show what the endpoint had received
/// or that it ever existed.
#[derive(Debug)]
pub(crate) struct WebhookSubscriptionDeleted {
    /// The deleted subscription.
    pub(crate) subscription_id: WebhookSubscriptionId,
    /// Where deliveries go, as the origin only. It is copied when the event
    /// is written, so the audit entry stays readable after the subscription
    /// changes or is removed.
    pub(crate) endpoint: UrlOrigin,
    /// When the delete occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WebhookSubscriptionDeleted => crate::types::event_type::WebhooksEvent::SubscriptionDeleted,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "subscription",
            Reference::new(
                RefKind::WEBHOOK,
                self.subscription_id.to_string(),
                self.endpoint.as_str(),
            ),
        )
    }
}

/// A webhook subscription's signing secret was rotated.
///
/// Deliveries are signed with the new secret, and with the old one until
/// the overlap ends, so the receiving endpoint can move to the new one
/// without refusing a delivery. After a leak the old one ends at once.
#[derive(Debug)]
pub(crate) struct WebhookSecretRotated {
    /// The subscription whose secret was rotated.
    pub(crate) subscription_id: WebhookSubscriptionId,
    /// Where deliveries go, as the origin only. It is copied when the event
    /// is written, so the audit entry stays readable after the subscription
    /// changes or is removed.
    pub(crate) endpoint: UrlOrigin,
    /// When the old secret stops signing: the rotation itself when it
    /// stopped at once.
    pub(crate) old_secret_ends_at: OffsetDateTime,
    /// When the rotation occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WebhookSecretRotated => crate::types::event_type::WebhooksEvent::SecretRotated,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "subscription",
                Reference::new(
                    RefKind::WEBHOOK,
                    self.subscription_id.to_string(),
                    self.endpoint.as_str(),
                ),
            )
            .field("expires_at", self.old_secret_ends_at.to_string())
    }
}

/// A part of a webhook subscription a person changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChangedWebhookField {
    /// Where deliveries go.
    Url,
    /// Which events it receives.
    EventTypes,
    /// What it is for.
    Description,
    /// How hard delivery retries.
    Retry,
}

impl ChangedWebhookField {
    /// The name the record lists it under.
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Url => "url",
            Self::EventTypes => "event_types",
            Self::Description => "description",
            Self::Retry => "retry",
        }
    }
}

/// A webhook subscription's address, events, description or retry policy
/// was changed.
///
/// The record names which parts changed, and where deliveries go now as an
/// origin only, never the full address, which may carry a secret.
#[derive(Debug)]
pub(crate) struct WebhookSubscriptionUpdated {
    /// The changed subscription.
    pub(crate) subscription_id: WebhookSubscriptionId,
    /// Where deliveries go after the change, as the origin only.
    pub(crate) endpoint: UrlOrigin,
    /// Which parts changed.
    pub(crate) fields: Vec<ChangedWebhookField>,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WebhookSubscriptionUpdated => crate::types::event_type::WebhooksEvent::SubscriptionUpdated,
    fn payload(&self) -> EventData {
        let fields: Vec<&str> = self.fields.iter().map(|field| field.as_str()).collect();
        EventData::new()
            .reference(
                "subscription",
                Reference::new(
                    RefKind::WEBHOOK,
                    self.subscription_id.to_string(),
                    self.endpoint.as_str(),
                ),
            )
            .field("fields", fields.join(","))
    }
}

/// An event was sent to a webhook subscription's endpoint.
///
/// Recorded for every attempt, whatever its outcome. The audit trail then
/// shows which of the tenant's events left the platform, and where to.
#[derive(Debug)]
pub(crate) struct WebhookDeliveryAttempted {
    /// The subscription the event was sent to.
    pub(crate) subscription_id: WebhookSubscriptionId,
    /// Where deliveries go, as the origin only. It is copied when the event
    /// is written, so the audit entry stays readable after the subscription
    /// changes or is removed.
    pub(crate) endpoint: UrlOrigin,
    /// The event that was sent.
    pub(crate) delivered_event: EventType,
    /// How the attempt ended.
    pub(crate) status: WebhookDeliveryStatus,
    /// When the attempt was made.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WebhookDeliveryAttempted => crate::types::event_type::WebhooksEvent::DeliveryAttempted,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "subscription",
                Reference::new(
                    RefKind::WEBHOOK,
                    self.subscription_id.to_string(),
                    self.endpoint.as_str(),
                ),
            )
            .field("event_type", self.delivered_event.as_str().to_owned())
            .field("status", delivery_status_label(self.status).to_owned())
    }
}

/// The word an audit entry uses for a delivery outcome.
fn delivery_status_label(status: WebhookDeliveryStatus) -> &'static str {
    match status {
        WebhookDeliveryStatus::Success => "success",
        WebhookDeliveryStatus::Failed => "failed",
        WebhookDeliveryStatus::Timeout => "timeout",
        WebhookDeliveryStatus::Unreachable => "unreachable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;

    fn origin(url: &str) -> UrlOrigin {
        crate::types::HttpsUrl::new(url).unwrap().origin()
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    fn subscription(payload: &EventData) -> (String, String) {
        match payload.value("subscription") {
            Some(FieldValue::Reference(reference)) => {
                assert_eq!(reference.kind(), RefKind::WEBHOOK);
                (reference.id().to_owned(), reference.label().to_owned())
            }
            other => panic!("subscription is not an entity reference: {other:?}"),
        }
    }

    fn text(payload: &EventData, key: &str) -> String {
        match payload.value(key) {
            Some(FieldValue::Text(value)) => value.clone(),
            other => panic!("{key} is not a scalar: {other:?}"),
        }
    }

    /// Creation, pause and resume records name the subscription by origin,
    /// excluding the secret path in its endpoint.
    #[test]
    fn every_subscription_event_names_the_subscription() {
        let id = WebhookSubscriptionId::new();
        let url = "https://hooks.acme.com/services/T0/B0/s3cret";

        let events: Vec<Box<dyn DomainEventCore>> = vec![
            Box::new(WebhookSubscriptionCreated {
                subscription_id: id,
                endpoint: origin(url),
                occurred_at: now(),
            }),
            Box::new(WebhookSubscriptionPaused {
                subscription_id: id,
                endpoint: origin(url),
                occurred_at: now(),
            }),
            Box::new(WebhookSubscriptionResumed {
                subscription_id: id,
                endpoint: origin(url),
                occurred_at: now(),
            }),
        ];

        assert_subscription_origins(events, id);
    }

    /// Deletion, secret rotation and update records exclude the endpoint's secret path.
    #[test]
    fn subscription_changes_keep_only_the_origin() {
        let id = WebhookSubscriptionId::new();
        let url = "https://hooks.acme.com/services/T0/B0/s3cret";
        let events: Vec<Box<dyn DomainEventCore>> = vec![
            Box::new(WebhookSubscriptionDeleted {
                subscription_id: id,
                endpoint: origin(url),
                occurred_at: now(),
            }),
            Box::new(WebhookSecretRotated {
                subscription_id: id,
                endpoint: origin(url),
                old_secret_ends_at: now(),
                occurred_at: now(),
            }),
            Box::new(WebhookSubscriptionUpdated {
                subscription_id: id,
                endpoint: origin(url),
                fields: vec![ChangedWebhookField::Url],
                occurred_at: now(),
            }),
        ];

        assert_subscription_origins(events, id);
    }

    /// Each event must retain the subscription ID and only the endpoint's origin.
    fn assert_subscription_origins(
        events: Vec<Box<dyn DomainEventCore>>,
        id: WebhookSubscriptionId,
    ) {
        for event in events {
            let kind = event.event_type();
            assert_eq!(
                subscription(&event.payload()),
                (id.to_string(), "https://hooks.acme.com".to_owned()),
                "{kind}"
            );
        }
    }

    /// A subscription-created event is sent to a hook and times out. The
    /// record names the subscription by origin, the event type sent and
    /// the outcome `timeout`.
    #[test]
    fn a_delivery_attempt_records_the_event_sent_and_how_it_ended() {
        let id = WebhookSubscriptionId::new();

        let event = WebhookDeliveryAttempted {
            subscription_id: id,
            endpoint: origin("https://hooks.acme.com/ianua"),
            delivered_event: crate::types::event_type::WebhooksEvent::SubscriptionCreated.into(),
            status: WebhookDeliveryStatus::Timeout,
            occurred_at: now(),
        };

        let payload = event.payload();
        assert_eq!(
            subscription(&payload),
            (id.to_string(), "https://hooks.acme.com".to_owned())
        );
        assert_eq!(
            text(&payload, "event_type"),
            "webhooks.subscription_created"
        );
        assert_eq!(text(&payload, "status"), "timeout");
    }

    /// Ann moves a webhook to a new address and narrows its events. The
    /// record lists `url,event_types`, and none of the values.
    #[test]
    fn an_update_records_which_parts_changed() {
        let event = WebhookSubscriptionUpdated {
            subscription_id: WebhookSubscriptionId::new(),
            endpoint: origin("https://hooks.acme.com/new?token=s3cret"),
            fields: vec![ChangedWebhookField::Url, ChangedWebhookField::EventTypes],
            occurred_at: now(),
        };

        let payload = event.payload();

        assert_eq!(text(&payload, "fields"), "url,event_types");
        assert!(!format!("{payload:?}").contains("s3cret"));
    }

    /// Ann rotates a webhook's secret with a day's overlap. The record says
    /// when the old secret stops signing.
    #[test]
    fn a_rotation_records_when_the_old_secret_stops() {
        let ends = now() + time::Duration::days(1);
        let event = WebhookSecretRotated {
            subscription_id: WebhookSubscriptionId::new(),
            endpoint: origin("https://hooks.acme.com/ianua"),
            old_secret_ends_at: ends,
            occurred_at: now(),
        };

        assert_eq!(text(&event.payload(), "expires_at"), ends.to_string());
    }

    /// A subscription is disabled after 20 failures in a row. No person
    /// asked for that, so the record says the 20 failures caused it.
    #[test]
    fn a_subscription_disabled_for_failing_records_how_many_failures() {
        let id = WebhookSubscriptionId::new();

        let event = WebhookSubscriptionDisabled {
            subscription_id: id,
            endpoint: origin("https://hooks.acme.com/ianua"),
            consecutive_failures: 20,
            occurred_at: now(),
        };

        let payload = event.payload();
        assert_eq!(
            subscription(&payload),
            (id.to_string(), "https://hooks.acme.com".to_owned())
        );
        assert_eq!(text(&payload, "consecutive_failures"), "20");
    }
}

//! Rows the webhooks store tests build from.

use ianua_app::ports::webhooks::WebhookMessage;
use ianua_domain::domains::webhooks::delivery::DeliveryAttempt;
use ianua_domain::domains::webhooks::retry_policy::RetryPreset;
use ianua_domain::domains::webhooks::subscription::WebhookSubscriptionRow;
use ianua_domain::domains::webhooks::subscription_status::WebhookSubscriptionStatus;
use ianua_domain::types::event_type::IdentityEvent;
use ianua_domain::types::{
    DeliveryOutcome, PreviousSigningSecret, PrincipalRef, PublicHttpsUrl, UserId,
    WebhookDeliveryId, WebhookMessageId, WebhookSubscriptionId,
};

use crate::test_support::rows::at;
use crate::test_support::rows::branding::sealed;

/// An active webhook at `url` for user registrations, signed with a sealed
/// secret never rotated, retried as standard, made at the fixed moment by
/// a tenant user.
///
/// # Panics
///
/// When `url` is not a public HTTPS URL, which is a mistake in the test.
#[must_use]
pub fn webhook_row(url: &str) -> WebhookSubscriptionRow {
    WebhookSubscriptionRow {
        id: WebhookSubscriptionId::new(),
        url: PublicHttpsUrl::new(url).expect("a public HTTPS URL"),
        signing_secret: sealed("signing-secret"),
        previous_secret: PreviousSigningSecret::Retired,
        event_types: vec![IdentityEvent::UserRegistered.into()],
        status: WebhookSubscriptionStatus::Active,
        description: None,
        retry: RetryPreset::Standard,
        created_by: PrincipalRef::User(UserId::new()),
        consecutive_failures: 0,
        last_delivered_at: None,
        created_at: at(0),
        updated_at: at(0),
    }
}

/// A user registration sent to `subscription_id`, under a fresh message
/// id.
#[must_use]
pub fn message_to(subscription_id: WebhookSubscriptionId) -> WebhookMessage {
    WebhookMessage {
        id: WebhookMessageId::new(),
        subscription_id,
        event_type: IdentityEvent::UserRegistered.into(),
        payload: br#"{"type":"identity.user_registered"}"#.to_vec(),
    }
}

/// A try at sending `message`, the `number`th, at `seconds` after the fixed
/// moment, that its endpoint answered with `code`.
#[must_use]
pub fn attempt_of(
    message: &WebhookMessage,
    number: u8,
    seconds: i64,
    code: u16,
) -> DeliveryAttempt {
    DeliveryAttempt {
        id: WebhookDeliveryId::new(),
        message_id: message.id,
        subscription_id: message.subscription_id,
        event_type: message.event_type,
        outcome: DeliveryOutcome::Answered { code },
        duration_ms: 40,
        attempt_number: number,
        attempted_at: at(seconds),
    }
}

//! What a person changes about a webhook after creating it: its address,
//! events, description and retry policy, and its signing secret.

use crate::domains::authorization::permission::WebhooksAction;
use crate::domains::webhooks::catalog::subscribed;
use crate::domains::webhooks::control::WebhookControl;
use crate::domains::webhooks::events::{
    ChangedWebhookField, WebhookSecretRotated, WebhookSubscriptionUpdated,
};
use crate::domains::webhooks::retry_policy::RetryPreset;
use crate::domains::webhooks::subscription::{WebhookSubscription, WebhookUpdate};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{
    EventType, PreviousSigningSecret, PublicHttpsUrl, RotationOverlap, SealedSecret, Setting, Text,
};

impl<T: TenantScope> WebhookSubscription<T> {
    /// Applies every change `update` names, for the person `control` names.
    /// Raises one `webhooks.subscription_updated` naming the parts that
    /// changed; an update that changes nothing raises nothing.
    ///
    /// New event types are checked against what the person updating may
    /// see, as at creation, and delivery still asks what the creator may
    /// see. A new address starts with no failures counted.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not update webhooks.
    /// - [`DomainError::InvalidTransition`] when the webhook is disabled. A
    ///   disabled webhook is replaced, not changed.
    /// - [`DomainError::Validation`] when the new event types name the
    ///   webhook delivery event.
    /// - [`DomainError::Forbidden`] when they name an event the person may
    ///   not see.
    pub fn update(
        &mut self,
        update: WebhookUpdate,
        control: &WebhookControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(WebhooksAction::Update)?;
        if self.status.is_disabled() {
            return Err(DomainError::invalid_transition(message!(
                "webhooks-a-disabled-webhook-is-replaced-not-2",
                "a disabled webhook is replaced, not changed"
            )));
        }
        let event_types = update
            .event_types
            .map(|asked| subscribed(asked, &control.visibility()))
            .transpose()?;
        let fields = self.apply(WebhookUpdate {
            event_types,
            ..update
        });
        if fields.is_empty() {
            return Ok(());
        }
        self.touch();
        self.raised.raise(WebhookSubscriptionUpdated {
            subscription_id: self.id,
            endpoint: self.url.origin(),
            fields,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Rotates the signing secret to `new_secret`, keeping the old one
    /// signing for `overlap`. Raises `webhooks.secret_rotated`.
    ///
    /// Whoever sets the new secret can sign messages the receiving server
    /// takes for the tenant's own deliveries. So this needs the full
    /// webhooks right, not only the right to pause and resume. A rotation
    /// during an overlap ends the older secret at once: only the secret
    /// just replaced keeps signing.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person does not manage
    ///   webhooks.
    /// - [`DomainError::Validation`] when `overlap` is longer than seven
    ///   days.
    pub fn rotate_secret(
        &mut self,
        new_secret: SealedSecret,
        overlap: RotationOverlap,
        control: &WebhookControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(WebhooksAction::Manage)?;
        let now = crate::shared::clock::now();
        self.previous_secret =
            PreviousSigningSecret::after_rotation(overlap, self.signing_secret.clone(), now)?;
        self.signing_secret = new_secret;
        self.touch();
        self.raised.raise(WebhookSecretRotated {
            subscription_id: self.id,
            endpoint: self.url.origin(),
            old_secret_ends_at: self.previous_secret.ends(now),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Applies `update`, its event types already checked, and names the
    /// parts that changed.
    fn apply(&mut self, update: WebhookUpdate) -> Vec<ChangedWebhookField> {
        [
            update.url.and_then(|url| self.change_url(url)),
            update
                .event_types
                .and_then(|types| self.change_event_types(types)),
            update
                .description
                .and_then(|text| self.change_description(text)),
            update.retry.and_then(|retry| self.change_retry(retry)),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    /// Moves deliveries to `url`, with no failure counted against it yet.
    fn change_url(&mut self, url: PublicHttpsUrl) -> Option<ChangedWebhookField> {
        if url == self.url {
            return None;
        }
        self.url = url;
        self.failures.reset();
        Some(ChangedWebhookField::Url)
    }

    /// Replaces the event types, already checked.
    fn change_event_types(&mut self, event_types: Vec<EventType>) -> Option<ChangedWebhookField> {
        if event_types == self.event_types {
            return None;
        }
        self.event_types = event_types;
        Some(ChangedWebhookField::EventTypes)
    }

    /// Replaces the description, or clears it.
    fn change_description(&mut self, description: Setting<Text>) -> Option<ChangedWebhookField> {
        let description = match description {
            Setting::Set(text) => Some(text),
            Setting::Unset => None,
        };
        if description == self.description {
            return None;
        }
        self.description = description;
        Some(ChangedWebhookField::Description)
    }

    /// Picks another retry policy.
    fn change_retry(&mut self, retry: RetryPreset) -> Option<ChangedWebhookField> {
        if retry == self.retry {
            return None;
        }
        self.retry = retry;
        Some(ChangedWebhookField::Retry)
    }
}

event_types! {
    /// The events the webhooks context publishes.
    pub enum WebhooksEvent {
        /// A webhook subscription was created.
        SubscriptionCreated => "webhooks.subscription_created",
        /// A webhook subscription was paused.
        SubscriptionPaused => "webhooks.subscription_paused",
        /// A webhook subscription was resumed.
        SubscriptionResumed => "webhooks.subscription_resumed",
        /// A webhook subscription was disabled after too many failures.
        SubscriptionDisabled => "webhooks.subscription_disabled",
        /// A webhook subscription was permanently deleted.
        SubscriptionDeleted => "webhooks.subscription_deleted",
        /// A webhook subscription's address, events, description or retry
        /// policy was changed.
        SubscriptionUpdated => "webhooks.subscription_updated",
        /// A webhook subscription's signing secret was rotated.
        SecretRotated => "webhooks.secret_rotated",
        /// An event was sent to a webhook subscription's endpoint.
        DeliveryAttempted => "webhooks.delivery_attempted",
    }
}

impl WebhooksEvent {
    /// Whether the tenant's members hear about this event.
    ///
    /// A delivery attempt is the platform doing what a subscription asked
    /// for, once per event sent. It goes in the audit trail but not in
    /// anybody's feed, which it would flood.
    #[must_use]
    pub fn is_notifiable(&self) -> bool {
        !matches!(self, Self::DeliveryAttempted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The platform tries to deliver one event to a subscriber. That
    /// attempt is audited but reaches no one's feed.
    #[test]
    fn a_delivery_attempt_reaches_nobodys_feed() {
        assert!(!WebhooksEvent::DeliveryAttempted.is_notifiable());
    }

    /// An admin deletes a webhook subscription. Colleagues are notified.
    #[test]
    fn a_change_to_a_subscription_is_notified() {
        assert!(WebhooksEvent::SubscriptionDeleted.is_notifiable());
    }
}

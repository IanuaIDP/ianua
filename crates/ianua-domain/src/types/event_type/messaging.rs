event_types! {
    /// The events the messaging context publishes.
    pub enum MessagingEvent {
        /// A topic was created.
        TopicCreated => "messaging.topic_created",
        /// A topic was paused.
        TopicPaused => "messaging.topic_paused",
        /// A topic was resumed.
        TopicResumed => "messaging.topic_resumed",
        /// A topic was archived.
        TopicArchived => "messaging.topic_archived",
        /// A topic's message schema was replaced.
        TopicSchemaChanged => "messaging.topic_schema_changed",
        /// A topic's retention policy was replaced.
        TopicRetentionChanged => "messaging.topic_retention_changed",
        /// A topic's data class was raised.
        TopicDataClassRaised => "messaging.topic_data_class_raised",
        /// A topic was deleted.
        TopicDeleted => "messaging.topic_deleted",
        /// A subscription was created.
        SubscriptionCreated => "messaging.subscription_created",
        /// A subscription was paused.
        SubscriptionPaused => "messaging.subscription_paused",
        /// A subscription was resumed.
        SubscriptionResumed => "messaging.subscription_resumed",
        /// A subscription was deleted.
        SubscriptionDeleted => "messaging.subscription_deleted",
        /// A push subscription's signing secret was replaced.
        SubscriptionSecretRotated => "messaging.subscription_secret_rotated",
        /// A dead letter was put back in front of its service.
        DeadLetterReplayed => "messaging.dead_letter_replayed",
        /// A message was published.
        MessagePublished => "messaging.message_published",
        /// An event schema was registered.
        SchemaRegistered => "messaging.schema_registered",
        /// A new version was added to an event schema.
        SchemaEvolved => "messaging.schema_evolved",
        /// An event schema was deleted.
        SchemaDeleted => "messaging.schema_deleted",
        /// A person opened a channel from one agent's area to another agent.
        ChannelOpened => "messaging.channel_opened",
        /// A channel between two agents was closed.
        ChannelClosed => "messaging.channel_closed",
    }
}

impl MessagingEvent {
    /// Whether other members hear about this event.
    ///
    /// Publishing a message is traffic on the bus, not a change to anything
    /// colleagues share. It goes in the audit trail but not in their feeds.
    #[must_use]
    pub fn is_notifiable(&self) -> bool {
        !matches!(self, Self::MessagePublished)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An agent publishes a message, and an admin deletes a topic. Only the
    /// deleted topic reaches colleagues' feeds.
    #[test]
    fn a_published_message_is_not_notified_but_a_topic_change_is() {
        assert!(!MessagingEvent::MessagePublished.is_notifiable());
        assert!(MessagingEvent::TopicDeleted.is_notifiable());
    }
}

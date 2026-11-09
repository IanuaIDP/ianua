//! Ids of what is sent out: topics, webhooks, security signals and notifications.

/// Id of a messaging event schema.
pub(crate) mod event_schema;
/// Id of a subscription to a messaging topic.
pub(crate) mod message_subscription;
/// Id of a notification sent to a person.
pub(crate) mod notification;
/// Id of a place outside the app an organization's notifications go to.
pub(crate) mod notification_destination;
/// Id of a security signal.
pub(crate) mod signal;
/// Id of one attempt to deliver a security signal.
pub(crate) mod signal_delivery;
/// Id of a security signal stream.
pub(crate) mod signal_stream;
/// Id of a messaging topic.
pub(crate) mod topic;
/// Id of one attempt to deliver a webhook.
pub(crate) mod webhook_delivery;
/// Id of one event sent to a webhook, kept across its retries.
pub(crate) mod webhook_message;
/// Id of a webhook subscription.
pub(crate) mod webhook_subscription;

pub use event_schema::EventSchemaId;
pub use message_subscription::MessageSubscriptionId;
pub use notification::NotificationId;
pub use notification_destination::NotificationDestinationId;
pub use signal::SignalId;
pub use signal_delivery::SignalDeliveryId;
pub use signal_stream::SignalStreamId;
pub use topic::TopicId;
pub use webhook_delivery::WebhookDeliveryId;
pub use webhook_message::WebhookMessageId;
pub use webhook_subscription::WebhookSubscriptionId;

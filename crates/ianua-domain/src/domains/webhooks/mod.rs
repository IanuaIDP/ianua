/// The events a webhook may be subscribed to, with what each means.
pub mod catalog;
/// Who may create and change webhook subscriptions.
pub mod control;
pub mod creator;
/// Webhook delivery attempts and their outcomes.
pub mod delivery;
pub mod events;
pub mod retry_policy;
/// How deliveries are signed, and how an old secret keeps signing after a
/// rotation.
pub mod signing;
/// A tenant's subscription to event notifications by HTTP callback.
pub mod subscription;
/// Webhook subscription delivery status: active, paused, disabled.
pub mod subscription_status;

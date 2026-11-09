//! The stores of the webhooks context: a tenant's webhook subscriptions,
//! the body of every message sent to each and every try at sending one,
//! each table under row-level security.

mod subscriptions;

pub use subscriptions::PgWebhookStore;

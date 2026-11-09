//! The stores of the messaging context: a tenant's topics, the
//! subscriptions of its services to them, its versioned event schemas and
//! the channels people open between its agents, each table under
//! row-level security. The messages themselves and the dead letters live
//! on the message bus, not here.
//!
//! `creators` and `signing` hold the two mappings more than one store
//! shares: who made a topic or a schema, and the secret a rotation keeps
//! signing, which webhooks keep the same way.

mod channels;
mod creators;
mod schemas;
pub(crate) mod signing;
mod subscriptions;
mod topics;

pub use channels::PgAgentChannelStore;
pub use schemas::PgSchemaStore;
pub use subscriptions::PgSubscriptionStore;
pub use topics::PgTopicStore;

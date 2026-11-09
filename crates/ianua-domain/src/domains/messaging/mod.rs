//! Publish and subscribe messaging between services of one tenant.
//!
//! Topics are named channels within a tenant. Services publish messages to
//! topics and subscribe to receive them. A service in one tenant cannot
//! reach another tenant's topics.

/// Who may change topics, subscriptions and schemas.
pub mod control;
/// Push endpoints, acknowledgement deadlines and dead letters.
pub mod delivery;
/// Events raised by topics, subscriptions and schemas.
pub mod events;
/// Message types, and the filters a subscription reads some types through.
pub mod message_type;
/// Versioned message schemas, for generated types and validation.
pub mod schema;
/// A service's subscription to a topic.
pub mod subscription;
/// Topics, the named and typed message channels of a tenant.
pub mod topic;
/// Checked topic names.
pub mod topic_name;

#[cfg(test)]
pub(crate) mod fixtures;

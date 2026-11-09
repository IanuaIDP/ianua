//! Messaging use cases: topic management, publishing, subscriptions, schemas.

/// The message plane: publishing and pulling.
pub mod broker;
mod bus;
/// Who acts in messaging: a person or a consumer that signed in.
pub mod caller;
mod changes;
/// Channels people open between agents, and the relay that carries agent messages.
pub mod channels;
mod lookup;
mod push_secret;
/// Event schemas and their versions.
pub mod schemas;
mod settling;
/// Services' subscriptions to topics.
pub mod subscriptions;
/// Topics messages are published to.
pub mod topics;

//! Channels a person opens so one agent may read what another publishes or holds.

/// An agent's own topic area. It is the only place the agent may publish.
pub mod area;
/// A person's permission for two agents to exchange messages or share an object.
pub mod channel;

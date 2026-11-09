//! Agent domain events.

/// Events about what an agent may do: delegations, resource grants and task templates.
pub mod authority;
/// Events from the channels a person opens between two agents.
pub mod channels;
/// Events about an agent's credentials and the short-lived ones an
/// attestation earns.
pub mod credentials;
/// Events about agents seen at work that nobody registered.
pub mod discovery;
/// Events recording what the gateway let an agent do, and what it refused.
pub mod enforcement;
/// Events from an agent at work: runs, tools and model providers.
pub mod execution;
/// Events about who an agent is: its identity, attestation and ownership.
pub mod identity;
/// Events from people and agents checking an agent: approvals and reviews.
pub mod oversight;
/// Events about tools and model providers changed after they were added.
pub mod setup;
/// Events from people steering a run: pausing it, resuming it, and
/// revising the call it holds.
pub mod steering;

//! AI agents: who they are, what they may do, and how people check them.
//!
//! An [`AgentIdentity`](identity::agent::AgentIdentity) is a machine principal.
//! It acts for a person, or on its own, through a
//! [`Delegation`](authority::delegation::Delegation). A delegation is narrowed,
//! ends at a set time and can be revoked. Delegations are the only source of an
//! agent's authority. The HTTP proxy and the message plane enforce them.

/// What an agent may do: delegations, capabilities, intent and the templates that bound them.
pub mod authority;
/// Channels a person opens so one agent may read what another publishes or holds.
pub mod channels;
pub mod events;
/// An agent at work: runs, tools, model providers and chat.
pub mod execution;
/// Who an agent is: its identity, how it proves it, and whether it may act.
pub mod identity;
/// People and agents checking an agent: approvals and independent review.
pub mod oversight;
/// The runner beside an agent's sandbox: where its requests go and what crosses.
pub mod runner;

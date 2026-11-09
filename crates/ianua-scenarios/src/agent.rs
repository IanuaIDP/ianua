//! The agent harness: agents that behave as one an LLM SDK runs, and the
//! model they and the platform reason with.
//!
//! - [`model`]: the scripted model server, speaking Anthropic's and
//!   OpenAI's wire formats from a [`Script`](model::Script), keeping every
//!   request it received.
//! - [`external`]: an [`ExternalAgent`](external::ExternalAgent), which
//!   holds its own key, signs its assertions and DPoP proofs, asks for its
//!   own tokens, publishes through the relay, backs off on `Status::TOO_MANY_REQUESTS`, and
//!   misbehaves on purpose.
//! - [`r#loop`]: the [`AgentLoop`](r#loop::AgentLoop), asking the model,
//!   carrying out the calls it makes through a
//!   [`ToolBelt`](r#loop::ToolBelt), feeding back the results, stopping
//!   when it ends its turn.
//! - [`keys`]: the P-256 keys and what is signed with them.
//! - [`tool_upstream`]: the app a platform-run agent's tool calls reach.

pub mod external;
pub mod keys;
pub mod r#loop;
pub mod model;
pub mod tool_upstream;

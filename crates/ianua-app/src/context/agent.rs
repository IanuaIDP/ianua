//! What an agent presents to act in its own name.

use ianua_domain::types::AgentId;

/// What an agent presents to act in its own name: the agent it says it is,
/// and an assertion its own key signed.
pub struct AgentAssertion {
    /// The agent it says it is.
    pub agent_id: AgentId,
    /// The assertion its key signed.
    pub assertion: String,
}

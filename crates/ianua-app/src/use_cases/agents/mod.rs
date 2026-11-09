//! Agent use cases: who an agent is, what it acts under, how it runs and
//! the watch people keep over it.

use ianua_domain::message;
use ianua_domain::types::AgentId;

use crate::error::AppError;

/// Refuses a sub-resource that belongs to a different agent than the one the
/// URL named.
///
/// Store lookups scope children to a tenant, not their URL's parent agent.
/// A mismatch is hidden as absent to avoid revealing a child at another address.
///
/// # Errors
///
/// Returns [`AppError::NotFound`] when `owner` is not `parent`.
pub(crate) fn reject_foreign_child(parent: &AgentId, owner: &AgentId) -> Result<(), AppError> {
    if parent == owner {
        return Ok(());
    }

    Err(AppError::NotFound(message!("api-not-found", "not found")))
}

/// Deciding whether an agent may make a call.
pub mod access;
/// Calls held for a person to approve.
pub mod approvals;
mod audit_labels;
/// Agent credentials, token exchange and attestation.
pub mod credentials;
/// Authority people hand to agents, and the resources it covers.
pub mod delegation;
/// What the gateway lets an agent do, and the record of each decision.
pub mod enforcement;
/// An agent's activity and audit evidence.
pub mod evidence;
/// An agent's stated purpose, drift from it, and exposure.
pub mod intent;
/// Creating, changing, suspending and retiring agents.
pub mod lifecycle;
mod lookup;
/// The model providers runs are sent to.
pub mod model_providers;
mod people;
/// Reviewers checking agents and their evidence.
pub mod reviews;
/// The runner beside an agent's sandbox and what its requests carry.
pub mod runner;
/// Agent runs: starting, driving, approving and stopping them.
pub mod runs;
/// Agents seen at work that nobody registered.
pub mod sightings;
/// Reusable task templates.
pub mod task_templates;
/// The tools agents may call.
pub mod tools;

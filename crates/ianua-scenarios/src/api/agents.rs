//! The agents area: what people call to make, empower and oversee agents,
//! and what agents call in their own name.
//!
//! - [`lifecycle`], [`credentials`], [`delegation`] and [`approvals`]: a
//!   person with a session, making an agent, enrolling and revoking its
//!   keys, granting it authority, and deciding its held calls.
//! - [`token`], [`attestation`] and [`relay`]: the agent itself, with an
//!   assertion its key signed, a platform attestation, or its task token.
//! - [`runs`], [`models`], [`tools`] and [`messaging`]: what platform-run
//!   agents and the relay need set up first.
//! - [`reviews`]: one agent set by a person to watch another, reading its
//!   evidence at the review desk.

pub mod approvals;
pub mod attestation;
pub mod credentials;
pub mod delegation;
pub mod lifecycle;
pub mod messaging;
pub mod models;
pub mod relay;
pub mod reviews;
pub mod runs;
pub mod token;
pub mod tools;

use super::TenantPath;

/// The header an agent's assertion travels in where the body has no room
/// for it: passing a delegation on, asking for one, the review desk.
pub const ASSERTION_HEADER: &str = "ianua-agent-assertion";

/// `rest` under the agent `agent_id`'s endpoints in `tenant`.
fn of_agent(tenant: &TenantPath, agent_id: &str, rest: &str) -> String {
    tenant.at(&format!("/agents/{agent_id}{rest}"))
}

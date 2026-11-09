//! The agents area on the wire: agents and their keys, the delegations a
//! person grants and an agent passes on, the task tokens an agent asks for
//! itself, approvals, runs, the model providers and tools runs use, and the
//! message relay.
//!
//! As everywhere in [`wire`](crate::wire), these are this crate's own
//! types, written from the API's agent routes. A type holding a token, a
//! key or an assertion has no derived `Debug`.

pub mod approvals;
pub mod attestation;
pub mod authority;
pub mod identity;
pub mod messaging;
pub mod models;
pub mod reviews;
pub mod runs;
pub mod token;
pub mod tools;

use serde::{Deserialize, Serialize};

/// What kind of principal an id names, as every agents body says beside
/// the id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    /// A tenant user.
    User,
    /// An organization member.
    OrgUser,
    /// A workload acting with delegated authority.
    Agent,
    /// A service identity authenticated with its own credentials.
    Consumer,
}

/// A principal: its kind and its id, and its name where the API adds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// What kind it is.
    pub kind: PrincipalKind,
    /// Identifier interpreted within the accompanying principal kind.
    pub id: String,
    /// Its name, when the answer names it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// The id a creating request answered with.
#[derive(Debug, Clone, Deserialize)]
pub struct Created {
    /// The new thing's id.
    pub id: String,
}

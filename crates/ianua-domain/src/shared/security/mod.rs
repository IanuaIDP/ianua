//! Security primitives: changes only a person may make, constant-time comparison, internal-address screening and secrets.

/// Changes only a person may make, never an agent or a machine caller.
pub(crate) mod acting_person;
/// How many requests a caller may make, refilled at a steady pace.
pub mod allowance;
/// Comparing secrets in a time that does not reveal where they differ.
pub(crate) mod constant_time;
pub mod secret;
pub mod ssrf;

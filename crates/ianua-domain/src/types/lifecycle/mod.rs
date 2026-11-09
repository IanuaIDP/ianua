//! Where something single-use, revocable or delivered stands.
//!
//! It covers use, revocation, ending, joining and expiry, and how
//! deliveries to an endpoint went.

pub mod credential_change;
pub mod delivery_outcome;
pub mod ending;
pub mod expiry;
/// Consecutive failed deliveries to one endpoint.
pub mod failure_streak;
pub mod joining;
/// What an emailed link is worth before it is followed.
pub mod link_status;
pub mod revocation;
/// What presenting a single-use token gets you.
pub mod token_state;
pub mod usage;

//! Access policies: rules with conditions and actions that a tenant defines.
//!
//! The simulator runs a made-up request against the policy set. It shows
//! what would happen before the policy goes live.

pub mod action;
/// The attributes and token claims a rule can compare.
pub mod claims;
pub mod condition;
pub mod review;
pub mod rule;
/// A policy's rules, in the order they are checked.
pub(crate) mod rule_list;
pub mod set;
pub mod simulator;
/// Access policy lifecycle: draft, review, active, archived.
pub mod status;
/// Times of day a rule names, read in a timezone.
pub mod time_window;
/// Versions of a tenant's policy: a live one, a draft beside it, and the
/// past ones.
pub mod version;

//! Workflow bodies: integration accounts and their connections by signing
//! in, the catalog's operations and events, definitions and their graphs,
//! webhook secrets, services' deliveries, executions and their approvals,
//! agent flows, and raised operation risks.
//!
//! The workflows domain keeps no wire format of its own, so every body here
//! is the API's, mapped to and from the domain at this boundary.

pub mod accounts;
pub mod builder;
pub mod catalog;
pub mod data;
pub mod definitions;
pub mod evaluations;
pub mod events;
pub mod executions;
pub mod flows;
pub mod graph;
pub mod guardrail;
pub mod hours;
pub mod loop_approvals;
pub mod memories;
pub mod sandboxes;
pub mod triggers;

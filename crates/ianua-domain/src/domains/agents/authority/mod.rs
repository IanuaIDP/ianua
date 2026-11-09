//! What an agent may do and on whose authority it acts.
//!
//! This covers delegations, the delegations agents ask people for,
//! capabilities, intent, the task templates that bound a delegation, the
//! provenance each agent message carries, and the relations people hand
//! each other on resources.

pub mod capability;
pub mod delegation;
pub mod delegation_request;
pub mod intent;
pub mod provenance;
pub mod relation_change;
pub mod task_template;

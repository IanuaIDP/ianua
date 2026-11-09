//! What a workflow is made of: its versions, the graph of steps and edges,
//! each kind of step and condition, agent flows' stages, its authors, and
//! the rules a version must keep to be published.

pub mod also_ask;
pub mod authors;
pub mod condition;
pub mod graph;
pub mod node;
pub(super) mod publish_rules;
pub mod stages;
pub mod workflow;
pub mod working_hours;

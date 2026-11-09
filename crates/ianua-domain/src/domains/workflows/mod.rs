//! Workflows: a graph of steps a tenant designs, publishes and runs.
//!
//! A [`Workflow`](design::workflow::Workflow) is one version of a graph of steps:
//! agent runs, integration actions, conditions, transforms, approvals and
//! waits. Each run of a published version is a
//! [`WorkflowExecution`](execution::WorkflowExecution) that acts for one
//! person and never exceeds their authority.
//!
//! The domain knows integrations only by what they declare: an
//! [`OperationSpec`](integration::OperationSpec) names its inputs, its
//! effect, whether it needs an account and the most sensitive data it may
//! be handed. Which integrations exist, and the work they do, live outside
//! the domain. An [`IntegrationAccount`](account::IntegrationAccount) holds
//! the credential reference an action uses, and only grants its use to the
//! people and operations it allows.
//!
//! An agent flow is a workflow too: stages of agent runs, laid out by
//! [`stages`](design::stages), made and published at once by
//! [`Workflow::flow`](design::workflow::Workflow::flow). A webhook starts a run
//! only with its [`WorkflowTriggerSecret`](triggers::secret::WorkflowTriggerSecret),
//! and a service's event only through the
//! [`ServiceSubscription`](triggers::subscription::ServiceSubscription) registered
//! for the version in service. An account may be connected by signing in
//! at its service, through a [`PendingConnection`](account::connection::PendingConnection).
//! A [`Sandbox`](sandbox::Sandbox) is a named recipe of code and pinned
//! packages, saved as versions whose package bundles are built and checked.
//! A [`Memory`](memory::Memory) is a named store of texts and their vectors
//! that steps add to and search for the most similar.
//! A [`guardrail`] step checks a text from an earlier step for personal
//! data, attempts to trick a model and banned words before the run goes on.
//! An [`EvaluationSet`](evaluation::set::EvaluationSet) holds a workflow's
//! sample cases, and an [`Evaluation`](evaluation::run::Evaluation) tries a
//! version against all of them as test runs.

pub mod account;
pub mod control;
pub mod data;
pub mod design;
pub mod evaluation;
pub mod events;
pub mod execution;
pub mod guardrail;
pub mod integration;
pub mod memory;
pub mod redaction;
pub mod sandbox;
#[cfg(feature = "serde")]
mod stored;
pub mod triggers;

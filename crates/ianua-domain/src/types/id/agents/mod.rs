//! Ids of agents and what they hold: runs, tools, channels, delegations and approvals.

/// Id of an agent identity.
pub(crate) mod agent;
/// Id of a human-in-the-loop approval request.
pub(crate) mod approval;
/// Id of a channel a person opened between two agents.
pub(crate) mod channel;
/// Id of an agent's durable signing credential.
pub(crate) mod credential;
/// Id of a delegation between agents.
pub(crate) mod delegation;
/// Id of a delegation an agent asked a person for.
pub(crate) mod delegation_request;
/// Id of a tenant's model provider connection.
pub(crate) mod model_provider;
/// Id of a person's assignment of one agent to review another.
pub(crate) mod review_assignment;
/// Id of one agent run toward a goal.
pub(crate) mod run;
/// Id of a sighting of an agent nobody registered.
pub(crate) mod sighting;
/// Id of a human-approved task template.
pub(crate) mod task_template;
/// Id of a registered tool an agent may call.
pub(crate) mod tool;

pub use agent::AgentId;
pub use approval::ApprovalId;
pub use channel::AgentChannelId;
pub use credential::AgentCredentialId;
pub use delegation::DelegationId;
pub use delegation_request::DelegationRequestId;
pub use model_provider::ModelProviderId;
pub use review_assignment::ReviewAssignmentId;
pub use run::AgentRunId;
pub use sighting::AgentSightingId;
pub use task_template::TaskTemplateId;
pub use tool::AgentToolId;

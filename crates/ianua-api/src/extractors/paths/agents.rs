//! The agents, and what hangs off them, an agents request names.

use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::types::{
    AgentChannelId, AgentCredentialId, AgentId, AgentRunId, AgentSightingId, AgentToolId,
    ApprovalId, DelegationId, DelegationRequestId, ModelProviderId, ReviewAssignmentId,
    TaskTemplateId,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::ApiError;

/// `.../agents/{id}/...`, and `.../agents/review-desk/{id}/...`, where `id`
/// is the agent under review.
#[derive(Deserialize)]
pub(crate) struct AgentPath {
    id: Uuid,
}

impl AgentPath {
    /// The agent named.
    #[must_use]
    pub(crate) fn agent(&self) -> AgentId {
        AgentId::from_uuid(self.id)
    }
}

/// `.../agents/{id}/delegations/{delegation_id}/...`.
#[derive(Deserialize)]
pub(crate) struct AgentDelegationPath {
    id: Uuid,
    delegation_id: Uuid,
}

impl AgentDelegationPath {
    /// The agent named.
    #[must_use]
    pub(crate) fn agent(&self) -> AgentId {
        AgentId::from_uuid(self.id)
    }

    /// The delegation named, one of the agent's own.
    #[must_use]
    pub(crate) fn delegation(&self) -> DelegationId {
        DelegationId::from_uuid(self.delegation_id)
    }
}

/// `.../agents/{id}/delegation-requests/{request_id}/...`.
#[derive(Deserialize)]
pub(crate) struct AgentDelegationRequestPath {
    id: Uuid,
    request_id: Uuid,
}

impl AgentDelegationRequestPath {
    /// The agent named.
    #[must_use]
    pub(crate) fn agent(&self) -> AgentId {
        AgentId::from_uuid(self.id)
    }

    /// The request named, one the agent made.
    #[must_use]
    pub(crate) fn request(&self) -> DelegationRequestId {
        DelegationRequestId::from_uuid(self.request_id)
    }
}

/// `.../agents/sightings/{id}/...`.
#[derive(Deserialize)]
pub(crate) struct SightingPath {
    id: Uuid,
}

impl SightingPath {
    /// The sighting named.
    #[must_use]
    pub(crate) fn sighting(&self) -> AgentSightingId {
        AgentSightingId::from_uuid(self.id)
    }
}

/// `.../agents/{id}/credentials/{credential_id}/...`.
#[derive(Deserialize)]
pub(crate) struct AgentCredentialPath {
    id: Uuid,
    credential_id: Uuid,
}

impl AgentCredentialPath {
    /// The agent named.
    #[must_use]
    pub(crate) fn agent(&self) -> AgentId {
        AgentId::from_uuid(self.id)
    }

    /// The credential named, one of the agent's own.
    #[must_use]
    pub(crate) fn credential(&self) -> AgentCredentialId {
        AgentCredentialId::from_uuid(self.credential_id)
    }
}

/// `.../agents/{id}/approvals/{approval_id}/...`.
#[derive(Deserialize)]
pub(crate) struct AgentApprovalPath {
    id: Uuid,
    approval_id: Uuid,
}

impl AgentApprovalPath {
    /// The agent named.
    #[must_use]
    pub(crate) fn agent(&self) -> AgentId {
        AgentId::from_uuid(self.id)
    }

    /// The approval request named, one raised for the agent.
    #[must_use]
    pub(crate) fn approval(&self) -> ApprovalId {
        ApprovalId::from_uuid(self.approval_id)
    }
}

/// `.../agents/{id}/runs/{run_id}/...`.
#[derive(Deserialize)]
pub(crate) struct AgentRunPath {
    id: Uuid,
    run_id: Uuid,
}

impl AgentRunPath {
    /// The agent named.
    #[must_use]
    pub(crate) fn agent(&self) -> AgentId {
        AgentId::from_uuid(self.id)
    }

    /// The run named, one of the agent's own.
    #[must_use]
    pub(crate) fn run(&self) -> AgentRunId {
        AgentRunId::from_uuid(self.run_id)
    }
}

/// `.../agents/{id}/reviews/{assignment_id}/...`.
#[derive(Deserialize)]
pub(crate) struct AgentReviewPath {
    id: Uuid,
    assignment_id: Uuid,
}

impl AgentReviewPath {
    /// The agent under review.
    #[must_use]
    pub(crate) fn reviewed(&self) -> AgentId {
        AgentId::from_uuid(self.id)
    }

    /// The review assignment named.
    #[must_use]
    pub(crate) fn assignment(&self) -> ReviewAssignmentId {
        ReviewAssignmentId::from_uuid(self.assignment_id)
    }
}

/// `.../agents/task-templates/{id}/...`.
#[derive(Deserialize)]
pub(crate) struct TaskTemplatePath {
    id: Uuid,
}

impl TaskTemplatePath {
    /// The template named.
    #[must_use]
    pub(crate) fn template(&self) -> TaskTemplateId {
        TaskTemplateId::from_uuid(self.id)
    }
}

/// `.../tools/{id}`.
#[derive(Deserialize)]
pub(crate) struct ToolPath {
    id: Uuid,
}

impl ToolPath {
    /// The tool named.
    #[must_use]
    pub(crate) fn tool(&self) -> AgentToolId {
        AgentToolId::from_uuid(self.id)
    }
}

/// `.../model-providers/{id}/...`.
#[derive(Deserialize)]
pub(crate) struct ModelProviderPath {
    id: Uuid,
}

impl ModelProviderPath {
    /// The model provider named.
    #[must_use]
    pub(crate) fn provider(&self) -> ModelProviderId {
        ModelProviderId::from_uuid(self.id)
    }
}

/// `.../messaging/channels/{id}/...`.
#[derive(Deserialize)]
pub(crate) struct ChannelPath {
    id: Uuid,
}

impl ChannelPath {
    /// The channel named.
    #[must_use]
    pub(crate) fn channel(&self) -> AgentChannelId {
        AgentChannelId::from_uuid(self.id)
    }
}

/// `.../agents/messages/{topic}`.
#[derive(Deserialize)]
pub(crate) struct AgentTopicPath {
    topic: String,
}

impl AgentTopicPath {
    /// The topic named.
    ///
    /// # Errors
    ///
    /// - A validation error when the path names no valid topic.
    pub(crate) fn topic(&self) -> Result<TopicName, ApiError> {
        TopicName::new(self.topic.as_str()).map_err(ApiError::validation)
    }
}

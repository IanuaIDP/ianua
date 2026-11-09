//! The workflows, executions, accounts, connections, registrations,
//! risks, sandboxes and memories a workflow request names.

use ianua_app::error::AppError;
use ianua_domain::domains::workflows::data::FieldName;
use ianua_domain::domains::workflows::design::node::NodeKey;
use ianua_domain::domains::workflows::integration::{IntegrationKey, OperationKey};
use ianua_domain::types::{
    AccountChannelId, EvaluationId, ImageRegistryId, IntegrationAccountId, MemoryId,
    OperationRiskOverrideId, PendingConnectionId, SandboxId, SandboxTrialId, SandboxVersionId,
    ServiceSubscriptionId, WorkflowExecutionId, WorkflowId, WorkflowTriggerId,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::ApiError;

/// `.../memories/{memory_id}/...`.
#[derive(Deserialize)]
pub(crate) struct MemoryPath {
    memory_id: Uuid,
}

impl MemoryPath {
    /// The memory named.
    #[must_use]
    pub(crate) fn memory(&self) -> MemoryId {
        MemoryId::from_uuid(self.memory_id)
    }
}

/// `.../sandboxes/registries/{registry_id}`.
#[derive(Deserialize)]
pub(crate) struct RegistryPath {
    registry_id: Uuid,
}

impl RegistryPath {
    /// The image registry named.
    #[must_use]
    pub(crate) fn registry(&self) -> ImageRegistryId {
        ImageRegistryId::from_uuid(self.registry_id)
    }
}

/// `.../sandboxes/{sandbox_id}/...`.
#[derive(Deserialize)]
pub(crate) struct SandboxPath {
    sandbox_id: Uuid,
}

impl SandboxPath {
    /// The sandbox named.
    #[must_use]
    pub(crate) fn sandbox(&self) -> SandboxId {
        SandboxId::from_uuid(self.sandbox_id)
    }
}

/// `.../sandboxes/{sandbox_id}/versions/{version_id}/...`.
#[derive(Deserialize)]
pub(crate) struct SandboxVersionPath {
    sandbox_id: Uuid,
    version_id: Uuid,
}

impl SandboxVersionPath {
    /// The sandbox named.
    #[must_use]
    pub(crate) fn sandbox(&self) -> SandboxId {
        SandboxId::from_uuid(self.sandbox_id)
    }

    /// The version of it named.
    #[must_use]
    pub(crate) fn version(&self) -> SandboxVersionId {
        SandboxVersionId::from_uuid(self.version_id)
    }
}

/// `.../sandboxes/{sandbox_id}/trials/{trial_id}`.
#[derive(Deserialize)]
pub(crate) struct SandboxTrialPath {
    sandbox_id: Uuid,
    trial_id: Uuid,
}

impl SandboxTrialPath {
    /// The sandbox named.
    #[must_use]
    pub(crate) fn sandbox(&self) -> SandboxId {
        SandboxId::from_uuid(self.sandbox_id)
    }

    /// The trial named.
    #[must_use]
    pub(crate) fn trial(&self) -> SandboxTrialId {
        SandboxTrialId::from_uuid(self.trial_id)
    }
}

/// `.../workflows/{workflow_id}/...`.
#[derive(Deserialize)]
pub(crate) struct WorkflowPath {
    workflow_id: Uuid,
}

impl WorkflowPath {
    /// The workflow named.
    #[must_use]
    pub(crate) fn workflow(&self) -> WorkflowId {
        WorkflowId::from_uuid(self.workflow_id)
    }
}

/// `.../workflows/{workflow_id}/evaluations/{evaluation_id}`.
#[derive(Deserialize)]
pub(crate) struct WorkflowEvaluationPath {
    workflow_id: Uuid,
    evaluation_id: Uuid,
}

impl WorkflowEvaluationPath {
    /// The workflow named.
    #[must_use]
    pub(crate) fn workflow(&self) -> WorkflowId {
        WorkflowId::from_uuid(self.workflow_id)
    }

    /// The evaluation named.
    #[must_use]
    pub(crate) fn evaluation(&self) -> EvaluationId {
        EvaluationId::from_uuid(self.evaluation_id)
    }
}

/// `.../workflows/{workflow_id}/versions/{version}/...`.
#[derive(Deserialize)]
pub(crate) struct WorkflowVersionPath {
    workflow_id: Uuid,
    version: u32,
}

impl WorkflowVersionPath {
    /// The workflow named.
    #[must_use]
    pub(crate) fn workflow(&self) -> WorkflowId {
        WorkflowId::from_uuid(self.workflow_id)
    }

    /// The version of it named.
    #[must_use]
    pub(crate) fn version(&self) -> u32 {
        self.version
    }
}

/// `.../workflows/executions/{execution_id}/...`.
#[derive(Deserialize)]
pub(crate) struct ExecutionPath {
    execution_id: Uuid,
}

impl ExecutionPath {
    /// The execution named.
    #[must_use]
    pub(crate) fn execution(&self) -> WorkflowExecutionId {
        WorkflowExecutionId::from_uuid(self.execution_id)
    }
}

/// `.../workflows/executions/{execution_id}/approvals/{step}/...`.
#[derive(Deserialize)]
pub(crate) struct ApprovalPath {
    execution_id: Uuid,
    step: String,
}

impl ApprovalPath {
    /// The execution named.
    #[must_use]
    pub(crate) fn execution(&self) -> WorkflowExecutionId {
        WorkflowExecutionId::from_uuid(self.execution_id)
    }

    /// The approval step named.
    ///
    /// # Errors
    ///
    /// - `422` when the step is not a step key.
    pub(crate) fn step(&self) -> Result<NodeKey, ApiError> {
        NodeKey::new(self.step.as_str()).map_err(ApiError::validation)
    }
}

/// `.../workflows/accounts/{account_id}`.
#[derive(Deserialize)]
pub(crate) struct AccountPath {
    account_id: Uuid,
}

impl AccountPath {
    /// The account named.
    #[must_use]
    pub(crate) fn account(&self) -> IntegrationAccountId {
        IntegrationAccountId::from_uuid(self.account_id)
    }
}

/// `.../workflows/accounts/connections/{connection_id}/...`.
#[derive(Deserialize)]
pub(crate) struct ConnectionPath {
    connection_id: Uuid,
}

impl ConnectionPath {
    /// The connection named.
    #[must_use]
    pub(crate) fn connection(&self) -> PendingConnectionId {
        PendingConnectionId::from_uuid(self.connection_id)
    }
}

/// `/api/v1/integrations/events/channels/{channel_id}`: one account's
/// address for its service's events.
#[derive(Deserialize)]
pub(crate) struct ChannelPath {
    channel_id: Uuid,
}

impl ChannelPath {
    /// The channel named.
    #[must_use]
    pub(crate) fn channel(&self) -> AccountChannelId {
        AccountChannelId::from_uuid(self.channel_id)
    }
}

/// `/api/v1/integrations/events/{subscription_id}`: one registration's own
/// address for its service's events.
#[derive(Deserialize)]
pub(crate) struct SubscriptionPath {
    subscription_id: Uuid,
}

impl SubscriptionPath {
    /// The registration named.
    #[must_use]
    pub(crate) fn subscription(&self) -> ServiceSubscriptionId {
        ServiceSubscriptionId::from_uuid(self.subscription_id)
    }
}

/// `.../workflows/operations/{integration}/{operation}/inputs/{input}/...`:
/// one input of an operation, as its step's form asks for it.
#[derive(Deserialize)]
pub(crate) struct OperationInputPath {
    integration: String,
    operation: String,
    input: String,
}

impl OperationInputPath {
    /// The integration named.
    ///
    /// # Errors
    ///
    /// - `422` when it is not an integration's name.
    pub(crate) fn integration(&self) -> Result<IntegrationKey, ApiError> {
        IntegrationKey::new(self.integration.as_str()).map_err(ApiError::validation)
    }

    /// The operation named.
    ///
    /// # Errors
    ///
    /// - `422` when it is not an operation's name.
    pub(crate) fn operation(&self) -> Result<OperationKey, ApiError> {
        OperationKey::new(self.operation.as_str()).map_err(ApiError::validation)
    }

    /// The input named.
    ///
    /// # Errors
    ///
    /// - `422` when it is not a field name.
    pub(crate) fn input(&self) -> Result<FieldName, ApiError> {
        FieldName::new(self.input.as_str()).map_err(ApiError::validation)
    }
}

/// `/api/v1/integrations/{integration}/events`: the one address an
/// integration's app receives every event at.
#[derive(Deserialize)]
pub(crate) struct IntegrationEventsPath {
    integration: String,
}

impl IntegrationEventsPath {
    /// The integration named.
    ///
    /// # Errors
    ///
    /// - `401` when it is not an integration's name, answered as a
    ///   delivery nothing admits, so a guess learns nothing.
    pub(crate) fn integration(self) -> Result<IntegrationKey, ApiError> {
        IntegrationKey::new(self.integration).map_err(|_| ApiError(AppError::Unauthenticated))
    }
}

/// `.../workflows/triggers/{trigger_id}`: a workflow's webhook.
#[derive(Deserialize)]
pub(crate) struct TriggerPath {
    trigger_id: Uuid,
}

impl TriggerPath {
    /// The webhook secret named.
    #[must_use]
    pub(crate) fn trigger(&self) -> WorkflowTriggerId {
        WorkflowTriggerId::from_uuid(self.trigger_id)
    }
}

/// `.../flows/{flow_id}/...`.
#[derive(Deserialize)]
pub(crate) struct FlowPath {
    flow_id: Uuid,
}

impl FlowPath {
    /// The flow named, by the id of the workflow it is.
    #[must_use]
    pub(crate) fn flow(&self) -> WorkflowId {
        WorkflowId::from_uuid(self.flow_id)
    }
}

/// `.../workflows/risks/{risk_id}`.
#[derive(Deserialize)]
pub(crate) struct RiskPath {
    risk_id: Uuid,
}

impl RiskPath {
    /// The raised risk named.
    #[must_use]
    pub(crate) fn risk(&self) -> OperationRiskOverrideId {
        OperationRiskOverrideId::from_uuid(self.risk_id)
    }
}

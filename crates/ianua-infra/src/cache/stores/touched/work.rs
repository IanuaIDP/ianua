//! What the events of agents, automation, messaging and the gateway's
//! configuration touch.
//!
//! Agents, consumers of topics and webhooks sign in and are judged through
//! records of their own, read apart from the bearer lookup; the gateway
//! keeps its own route tables and reloads them on these events. So none of
//! them touches a store cache, but for an agent removed for good, whose
//! assignments cascade away, and a change to a tenant's classification
//! rules, which the gateway reads through a cache.

use ianua_domain::types::event_type::{
    AgentsEvent, MessagingEvent, NotificationsEvent, ProxyEvent, RoutingEvent, SignalsEvent,
    WebhooksEvent, WorkflowsEvent,
};

use crate::cache::stores::touched::{CLASSIFICATIONS, HOLDINGS, NOTHING};
use crate::cache::stores::versions::Cached;

/// Agents: only a deletion changes what a holdings read finds.
/// This single exhaustive mapping keeps new events from silently missing cache invalidation.
#[allow(clippy::too_many_lines)]
pub(super) fn agents(event: AgentsEvent) -> &'static [Cached] {
    match event {
        AgentsEvent::AgentDeleted => HOLDINGS,
        AgentsEvent::AgentCreated
        | AgentsEvent::AgentUpdated
        | AgentsEvent::AgentSuspended
        | AgentsEvent::AllAgentsSuspended
        | AgentsEvent::AgentResumed
        | AgentsEvent::AgentRevoked
        | AgentsEvent::AgentContained
        | AgentsEvent::ReattestationRequired
        | AgentsEvent::DelegationGranted
        | AgentsEvent::DelegationRevoked
        | AgentsEvent::DelegationResourceGranted
        | AgentsEvent::DelegationResourceRevoked
        | AgentsEvent::TokenIssued
        | AgentsEvent::CredentialMinted
        | AgentsEvent::CredentialRotated
        | AgentsEvent::CredentialRevoked
        | AgentsEvent::AgentBootstrapped
        | AgentsEvent::ApprovalRequested
        | AgentsEvent::ApprovalGranted
        | AgentsEvent::ApprovalSigned
        | AgentsEvent::ReviewerAssigned
        | AgentsEvent::ReviewEnded
        | AgentsEvent::ReviewVerdict
        | AgentsEvent::EgressDenied
        | AgentsEvent::ExposureReset
        | AgentsEvent::TaskTemplateProposed
        | AgentsEvent::TaskTemplateApproved
        | AgentsEvent::TaskTemplateRetired
        | AgentsEvent::ApprovalDenied
        | AgentsEvent::ApprovalWithdrawn
        | AgentsEvent::ActionAuthorized
        | AgentsEvent::ActionDenied
        | AgentsEvent::MessageAuthorized
        | AgentsEvent::MessageDenied
        | AgentsEvent::IntentDrift
        | AgentsEvent::Converged
        | AgentsEvent::ModelProviderConnected
        | AgentsEvent::ToolRegistered
        | AgentsEvent::ToolStatusChanged
        | AgentsEvent::ToolDeleted
        | AgentsEvent::ModelProviderStatusChanged
        | AgentsEvent::ModelProviderDeleted
        | AgentsEvent::ModelProviderTested
        | AgentsEvent::ResourceRelationGranted
        | AgentsEvent::ResourceRelationRevoked
        | AgentsEvent::AttestationChallengeIssued
        | AgentsEvent::RunStarted
        | AgentsEvent::RunAwaitingApproval
        | AgentsEvent::RunFinished
        | AgentsEvent::RunCancelRequested
        | AgentsEvent::AgentOwnershipTransferred
        | AgentsEvent::AgentOwnershipOffered
        | AgentsEvent::AgentOwnershipOfferWithdrawn
        | AgentsEvent::ModelProviderClearanceChanged
        | AgentsEvent::DelegationRenewed
        | AgentsEvent::DelegationRequested
        | AgentsEvent::DelegationRequestApproved
        | AgentsEvent::DelegationRequestDenied
        | AgentsEvent::ModelProviderKeyRotated
        | AgentsEvent::ModelProviderModelChanged
        | AgentsEvent::ModelProviderEmbeddingsChanged
        | AgentsEvent::ToolEdited
        | AgentsEvent::RunPaused
        | AgentsEvent::RunResumed
        | AgentsEvent::RunHeldAtSpend
        | AgentsEvent::RunStoppedOverBudget
        | AgentsEvent::HeldCallRevised
        | AgentsEvent::AgentSighted
        | AgentsEvent::AgentSightingRegistered
        | AgentsEvent::AgentSightingDismissed
        | AgentsEvent::TokenAttackRefused => NOTHING,
    }
}

/// Workflows run under records of their own.
/// This single exhaustive mapping keeps new events from silently missing cache invalidation.
#[allow(clippy::too_many_lines)]
pub(super) fn workflows(event: WorkflowsEvent) -> &'static [Cached] {
    match event {
        WorkflowsEvent::WorkflowCreated
        | WorkflowsEvent::VersionDrafted
        | WorkflowsEvent::DraftRenamed
        | WorkflowsEvent::DraftStepsReplaced
        | WorkflowsEvent::DraftTriggerChanged
        | WorkflowsEvent::DraftRunLimitChanged
        | WorkflowsEvent::DraftDescribed
        | WorkflowsEvent::DraftFailureAlertChanged
        | WorkflowsEvent::VersionPublished
        | WorkflowsEvent::VersionArchived
        | WorkflowsEvent::ExecutionStarted
        | WorkflowsEvent::StartRefused
        | WorkflowsEvent::StepStarted
        | WorkflowsEvent::StepSucceeded
        | WorkflowsEvent::StepFailed
        | WorkflowsEvent::StepCallTurnedAway
        | WorkflowsEvent::StepDeferred
        | WorkflowsEvent::StepSkipped
        | WorkflowsEvent::StepAbandoned
        | WorkflowsEvent::StepStoodIn
        | WorkflowsEvent::TestStepFailed
        | WorkflowsEvent::GuardrailFound
        | WorkflowsEvent::ApprovalGranted
        | WorkflowsEvent::ExecutionEnded
        | WorkflowsEvent::TestEnded
        | WorkflowsEvent::EvaluationSetSaved
        | WorkflowsEvent::EvaluationStarted
        | WorkflowsEvent::EvaluationEnded
        | WorkflowsEvent::PassStarted
        | WorkflowsEvent::PassEnded
        | WorkflowsEvent::SandboxCreated
        | WorkflowsEvent::SandboxVersionSaved
        | WorkflowsEvent::SandboxVersionBuilt
        | WorkflowsEvent::SandboxVersionFailed
        | WorkflowsEvent::SandboxVersionPushed
        | WorkflowsEvent::SandboxTrialStarted
        | WorkflowsEvent::SandboxArchived
        | WorkflowsEvent::ImageRegistryAllowed
        | WorkflowsEvent::ImageRegistryRemoved
        | WorkflowsEvent::MemoryCreated
        | WorkflowsEvent::MemoryDeletionRequested
        | WorkflowsEvent::MemoryRestored
        | WorkflowsEvent::MemoryPurged
        | WorkflowsEvent::AccountConnected
        | WorkflowsEvent::AccountChanged
        | WorkflowsEvent::AccountDisabled
        | WorkflowsEvent::AccountEnabled
        | WorkflowsEvent::VersionHeld
        | WorkflowsEvent::AccountCredentialRenewed
        | WorkflowsEvent::AccountConnectionStarted
        | WorkflowsEvent::AccountConnectionRefused
        | WorkflowsEvent::SubscriptionRegistered
        | WorkflowsEvent::SubscriptionLapsed
        | WorkflowsEvent::SubscriptionRemoved
        | WorkflowsEvent::ChannelReady
        | WorkflowsEvent::ChannelLapsed
        | WorkflowsEvent::ChannelClosed
        | WorkflowsEvent::ChannelTokenShown
        | WorkflowsEvent::OperationRiskRaised
        | WorkflowsEvent::OperationRiskOverrideRemoved
        | WorkflowsEvent::FlowCreated
        | WorkflowsEvent::FlowDeleted
        | WorkflowsEvent::TriggerSecretIssued
        | WorkflowsEvent::TriggerSecretRotated
        | WorkflowsEvent::TriggerSecretRevoked => NOTHING,
    }
}

/// Topics, subscriptions, schemas and channels.
pub(super) fn messaging(event: MessagingEvent) -> &'static [Cached] {
    match event {
        MessagingEvent::TopicCreated
        | MessagingEvent::TopicPaused
        | MessagingEvent::TopicResumed
        | MessagingEvent::TopicArchived
        | MessagingEvent::TopicSchemaChanged
        | MessagingEvent::TopicRetentionChanged
        | MessagingEvent::TopicDataClassRaised
        | MessagingEvent::TopicDeleted
        | MessagingEvent::SubscriptionCreated
        | MessagingEvent::SubscriptionPaused
        | MessagingEvent::SubscriptionResumed
        | MessagingEvent::SubscriptionDeleted
        | MessagingEvent::SubscriptionSecretRotated
        | MessagingEvent::DeadLetterReplayed
        | MessagingEvent::MessagePublished
        | MessagingEvent::SchemaRegistered
        | MessagingEvent::SchemaEvolved
        | MessagingEvent::SchemaDeleted
        | MessagingEvent::ChannelOpened
        | MessagingEvent::ChannelClosed => NOTHING,
    }
}

/// Webhook subscriptions and their deliveries.
pub(super) fn webhooks(event: WebhooksEvent) -> &'static [Cached] {
    match event {
        WebhooksEvent::SubscriptionCreated
        | WebhooksEvent::SubscriptionPaused
        | WebhooksEvent::SubscriptionResumed
        | WebhooksEvent::SubscriptionDisabled
        | WebhooksEvent::SubscriptionDeleted
        | WebhooksEvent::SubscriptionUpdated
        | WebhooksEvent::SecretRotated
        | WebhooksEvent::DeliveryAttempted => NOTHING,
    }
}

/// Notifications and where they go.
pub(super) fn notifications(event: NotificationsEvent) -> &'static [Cached] {
    match event {
        NotificationsEvent::NotificationRead
        | NotificationsEvent::AllNotificationsRead
        | NotificationsEvent::PreferencesUpdated
        | NotificationsEvent::MailUndelivered
        | NotificationsEvent::DestinationAdded
        | NotificationsEvent::DestinationChanged
        | NotificationsEvent::DestinationPaused
        | NotificationsEvent::DestinationResumed
        | NotificationsEvent::DestinationRemoved
        | NotificationsEvent::MemberPreferencesUpdated
        | NotificationsEvent::OperatorPreferencesUpdated
        | NotificationsEvent::NoticeSent
        | NotificationsEvent::AccessOffered => NOTHING,
    }
}

/// Security signal streams.
pub(super) fn signals(event: SignalsEvent) -> &'static [Cached] {
    match event {
        SignalsEvent::StreamRegistered
        | SignalsEvent::StreamPaused
        | SignalsEvent::StreamResumed
        | SignalsEvent::StreamDisabled
        | SignalsEvent::StreamUpdated
        | SignalsEvent::StreamDeleted
        | SignalsEvent::SubjectAdded
        | SignalsEvent::SubjectRemoved
        | SignalsEvent::VerificationRequested
        | SignalsEvent::SignalReported => NOTHING,
    }
}

/// The gateway's pipelines, stages and what it detects, and a tenant's
/// classification rules, which drop the rule set the gateway keeps.
pub(super) fn proxy(event: ProxyEvent) -> &'static [Cached] {
    match event {
        ProxyEvent::ClassificationRuleAdded
        | ProxyEvent::ClassificationRuleRemoved
        | ProxyEvent::ClassificationRuleChanged => CLASSIFICATIONS,
        ProxyEvent::PipelineCreated
        | ProxyEvent::PipelineDeleted
        | ProxyEvent::PipelineRenamed
        | ProxyEvent::PipelineActivated
        | ProxyEvent::PipelineDisabled
        | ProxyEvent::StageAdded
        | ProxyEvent::StageRemoved
        | ProxyEvent::StageEnabled
        | ProxyEvent::StageDisabled
        | ProxyEvent::StageReconfigured
        | ProxyEvent::PipelineReordered
        | ProxyEvent::HoneypotHit
        | ProxyEvent::PersonTurnedAway
        | ProxyEvent::AutomatedThreatDetected
        | ProxyEvent::CanaryTokenTriggered
        | ProxyEvent::CanaryTokenLeaked
        | ProxyEvent::CanaryTokenGenerated
        | ProxyEvent::WasmModuleUploaded
        | ProxyEvent::LogTargetCreated
        | ProxyEvent::LogTargetChanged
        | ProxyEvent::LogTargetPaused
        | ProxyEvent::LogTargetResumed
        | ProxyEvent::LogTargetDeleted => NOTHING,
    }
}

/// Routes, services, connectors and egress policies.
/// This single exhaustive mapping keeps new events from silently missing cache invalidation.
#[allow(clippy::too_many_lines)]
pub(super) fn routing(event: RoutingEvent) -> &'static [Cached] {
    match event {
        RoutingEvent::RouteCreated
        | RoutingEvent::RouteUpdated
        | RoutingEvent::RouteDeleted
        | RoutingEvent::RouteActivated
        | RoutingEvent::RouteDisabled
        | RoutingEvent::RouteOpenedToWorkflows
        | RoutingEvent::RouteClosedToWorkflows
        | RoutingEvent::RouteAttackModeStarted
        | RoutingEvent::RouteAttackModeEnded
        | RoutingEvent::ServiceCreated
        | RoutingEvent::ServiceUpdated
        | RoutingEvent::ServiceDeleted
        | RoutingEvent::AppSignInChanged
        | RoutingEvent::StreamRouteCreated
        | RoutingEvent::StreamRouteUpdated
        | RoutingEvent::StreamRouteDeleted
        | RoutingEvent::StreamRouteActivated
        | RoutingEvent::StreamRouteDisabled
        | RoutingEvent::StreamRouteOpenedToWorkflows
        | RoutingEvent::StreamRouteClosedToWorkflows
        | RoutingEvent::EgressPolicyCreated
        | RoutingEvent::EgressPolicyUpdated
        | RoutingEvent::EgressPolicyDeleted
        | RoutingEvent::GatewayConfigImported
        | RoutingEvent::ConnectorCreated
        | RoutingEvent::ConnectorEnrolled
        | RoutingEvent::ConnectorRenewed
        | RoutingEvent::ConnectorUpdated
        | RoutingEvent::ConnectorRevoked
        | RoutingEvent::ConnectorDeleted => NOTHING,
    }
}

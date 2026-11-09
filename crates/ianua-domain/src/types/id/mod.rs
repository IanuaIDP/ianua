/// Declares a UUID-backed identifier.
///
/// Every such id has the same shape. It is a `UUIDv7` that sorts by
/// creation time. It is serialized and printed as the bare UUID, and turns
/// into and out of it at the storage boundary. One definition keeps all the
/// ids alike.
macro_rules! uuid_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name(uuid::Uuid);

        impl $name {
            /// A fresh id. It is a `UUIDv7` of a timestamp and random bits,
            /// so ids made later sort later.
            #[must_use]
            pub fn new() -> Self {
                Self(uuid::Uuid::now_v7())
            }

            /// Wraps a raw UUID, such as one read from a database row.
            #[must_use]
            pub fn from_uuid(uuid: uuid::Uuid) -> Self {
                Self(uuid)
            }

            /// The underlying UUID, for binding into a query.
            #[must_use]
            pub fn as_uuid(&self) -> &uuid::Uuid {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

/// Ids of who may do what: roles, groups, relationships and the governance around them.
mod access;
/// Ids of agents and what they hold: runs, tools, channels, delegations and approvals.
mod agents;
/// Ids of what the gateway serves and who calls through it.
mod gateway;
/// Ids of what is sent out: topics, webhooks, security signals and notifications.
mod messaging;
/// Ids of OAuth clients, their requests and API keys.
mod oauth;
/// Ids of a tenant's people and what they ask for: invitations, devices, exports, erasure.
mod people;
/// Ids of the platform itself: operators, processes, jobs, the audit trail and data
/// classification.
mod platform;
/// Ids SAML messages carry, and of the apps signed in to over SAML.
mod saml;
/// Ids of how people sign in and stay signed in: sessions, passkeys, outside providers, tokens.
mod sign_in;
/// Ids of organizations, their members and tenants, and the domains tenants own.
mod tenancy;
/// Ids of workflows, their runs and the integrations they call.
mod workflows;

pub use access::{
    AccessRequestId, AccessReviewId, BreakGlassGrantId, DecisionRecordId, GroupId, RelationshipId,
    ResourceTypeId, RoleId, SeparationRuleId,
};
pub use agents::{
    AgentChannelId, AgentCredentialId, AgentId, AgentRunId, AgentSightingId, AgentToolId,
    ApprovalId, DelegationId, DelegationRequestId, ModelProviderId, ReviewAssignmentId,
    TaskTemplateId,
};
pub use gateway::{
    ConnectorId, ConsumerId, DirectoryServiceAccountId, EgressPolicyId, LdapCertificateId,
    LogShippingTargetId, PipelineId, RouteId, ServiceId, StageId, StreamRouteId,
};
pub use messaging::{
    EventSchemaId, MessageSubscriptionId, NotificationDestinationId, NotificationId,
    SignalDeliveryId, SignalId, SignalStreamId, TopicId, WebhookDeliveryId, WebhookMessageId,
    WebhookSubscriptionId,
};
pub use oauth::{
    ApiKeyId, ClientId, InitialAccessTokenId, KeyPrefix, OAuthClientId, PushedRequestId,
};
pub use people::{
    AttributeDefinitionId, ConsentId, DataExportId, ErasureRequestId, InvitationId,
    LinkedIdentityId, PasswordResetId, PrincipalId, SupportImpersonationId, TrustedDeviceId,
    UserId, UserImportId,
};
pub use platform::{
    AuditExportId, AuditRecordId, AuditStreamId, ClassificationRuleId, ClassificationRuleSetId,
    CorrelationId, EvidenceId, ImpersonationGrantId, JobId, NodeId, OperatorId,
};
pub use saml::{
    SamlArrivalId, SamlAssertionId, SamlRequestId, SamlResponseId, SamlServiceProviderId,
    SessionIndex,
};
pub use sign_in::{
    CeremonyId, ConnectionId, FederatedSubject, KeyId, PasskeyCredentialId, PasskeyId,
    RefreshFamilyId, SessionId, TokenId,
};
pub use tenancy::{
    CertificateId, DomainId, OrgApiKeyId, OrgInvitationId, OrgUserId, OrganizationId,
    TenantCloneId, TenantId,
};
pub use workflows::{
    AccountChannelId, ActionCallId, CodeRunId, EvaluationId, ImageRegistryId, IntegrationAccountId,
    MemoryEntryId, MemoryId, OperationRiskOverrideId, PendingConnectionId, SandboxId,
    SandboxTrialId, SandboxVersionId, ServiceSubscriptionId, WorkflowExecutionId, WorkflowId,
    WorkflowTriggerId,
};

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    /// One test per id type: the id gives back the UUID it was built from,
    /// and prints as that UUID.
    macro_rules! id_carries_its_uuid {
        ($($name:ident: $type:ty),* $(,)?) => {
            $(
                /// An id built from a UUID gives back that UUID, which a
                /// repository binds into a query. It prints as the same UUID
                /// in audit records, logs and URLs.
                #[test]
                fn $name() {
                    let uuid = Uuid::now_v7();

                    let id = <$type>::from_uuid(uuid);

                    assert_eq!(id.as_uuid(), &uuid);
                    assert_eq!(id.to_string(), uuid.to_string());
                }
            )*
        };
    }

    /// One test per id type: two fresh ids differ, and each is a `UUIDv7`.
    macro_rules! fresh_ids_are_distinct_v7 {
        ($($name:ident: $type:ty),* $(,)?) => {
            $(
                /// Two ids made one after the other differ, and each is a
                /// version 7 UUID with random bits, so the next id cannot be
                /// guessed.
                #[test]
                fn $name() {
                    let first = <$type>::new();
                    let second = <$type>::new();

                    assert_ne!(first, second);
                    assert_eq!(first.as_uuid().get_version_num(), 7);
                }
            )*
        };
    }

    fresh_ids_are_distinct_v7! {
        fresh_access_request_id: AccessRequestId,
        fresh_access_review_id: AccessReviewId,
        fresh_decision_record_id: DecisionRecordId,
        fresh_relationship_id: RelationshipId,
        fresh_separation_rule_id: SeparationRuleId,
        fresh_action_call_id: ActionCallId,
        fresh_code_run_id: CodeRunId,
        fresh_agent_channel_id: AgentChannelId,
        fresh_agent_credential_id: AgentCredentialId,
        fresh_agent_id: AgentId,
        fresh_agent_run_id: AgentRunId,
        fresh_agent_sighting_id: AgentSightingId,
        fresh_agent_tool_id: AgentToolId,
        fresh_api_key_id: ApiKeyId,
        fresh_approval_id: ApprovalId,
        fresh_ceremony_id: CeremonyId,
        fresh_connection_id: ConnectionId,
        fresh_connector_id: ConnectorId,
        fresh_consumer_id: ConsumerId,
        fresh_egress_policy_id: EgressPolicyId,
        fresh_delegation_id: DelegationId,
        fresh_delegation_request_id: DelegationRequestId,
        fresh_directory_service_account_id: DirectoryServiceAccountId,
        fresh_data_export_id: DataExportId,
        fresh_user_import_id: UserImportId,
        fresh_support_impersonation_id: SupportImpersonationId,
        fresh_job_id: JobId,
        fresh_model_provider_id: ModelProviderId,
        fresh_oauth_client_id: OAuthClientId,
        fresh_operation_risk_override_id: OperationRiskOverrideId,
        fresh_sandbox_id: SandboxId,
        fresh_memory_id: MemoryId,
        fresh_memory_entry_id: MemoryEntryId,
        fresh_sandbox_version_id: SandboxVersionId,
        fresh_sandbox_trial_id: SandboxTrialId,
        fresh_image_registry_id: ImageRegistryId,
        fresh_evaluation_id: EvaluationId,
        fresh_operator_id: OperatorId,
        fresh_org_user_id: OrgUserId,
        fresh_organization_id: OrganizationId,
        fresh_resource_type_id: ResourceTypeId,
        fresh_review_assignment_id: ReviewAssignmentId,
        fresh_role_id: RoleId,
        fresh_service_id: ServiceId,
        fresh_session_id: SessionId,
        fresh_stream_route_id: StreamRouteId,
        fresh_task_template_id: TaskTemplateId,
        fresh_tenant_id: TenantId,
        fresh_tenant_clone_id: TenantCloneId,
        fresh_user_id: UserId,
        fresh_attribute_definition_id: AttributeDefinitionId,
        fresh_audit_record_id: AuditRecordId,
        fresh_audit_stream_id: AuditStreamId,
        fresh_audit_export_id: AuditExportId,
        fresh_correlation_id: CorrelationId,
        fresh_break_glass_grant_id: BreakGlassGrantId,
        fresh_certificate_id: CertificateId,
        fresh_classification_rule_id: ClassificationRuleId,
        fresh_classification_rule_set_id: ClassificationRuleSetId,
        fresh_consent_id: ConsentId,
        fresh_domain_id: DomainId,
        fresh_erasure_request_id: ErasureRequestId,
        fresh_event_schema_id: EventSchemaId,
        fresh_evidence_id: EvidenceId,
        fresh_group_id: GroupId,
        fresh_impersonation_grant_id: ImpersonationGrantId,
        fresh_invitation_id: InvitationId,
        fresh_ldap_certificate_id: LdapCertificateId,
        fresh_linked_identity_id: LinkedIdentityId,
        fresh_log_shipping_target_id: LogShippingTargetId,
        fresh_message_subscription_id: MessageSubscriptionId,
        fresh_notification_destination_id: NotificationDestinationId,
        fresh_notification_id: NotificationId,
        fresh_org_api_key_id: OrgApiKeyId,
        fresh_org_invitation_id: OrgInvitationId,
        fresh_passkey_id: PasskeyId,
        fresh_password_reset_id: PasswordResetId,
        fresh_pipeline_id: PipelineId,
        fresh_refresh_family_id: RefreshFamilyId,
        fresh_initial_access_token_id: InitialAccessTokenId,
        fresh_pushed_request_id: PushedRequestId,
        fresh_route_id: RouteId,
        fresh_saml_arrival_id: SamlArrivalId,
        fresh_saml_service_provider_id: SamlServiceProviderId,
        fresh_signal_delivery_id: SignalDeliveryId,
        fresh_signal_id: SignalId,
        fresh_signal_stream_id: SignalStreamId,
        fresh_stage_id: StageId,
        fresh_topic_id: TopicId,
        fresh_trusted_device_id: TrustedDeviceId,
        fresh_webhook_delivery_id: WebhookDeliveryId,
        fresh_webhook_message_id: WebhookMessageId,
        fresh_webhook_subscription_id: WebhookSubscriptionId,
        fresh_integration_account_id: IntegrationAccountId,
        fresh_pending_connection_id: PendingConnectionId,
        fresh_service_subscription_id: ServiceSubscriptionId,
        fresh_account_channel_id: AccountChannelId,
        fresh_workflow_execution_id: WorkflowExecutionId,
        fresh_workflow_id: WorkflowId,
        fresh_workflow_trigger_id: WorkflowTriggerId,
    }

    id_carries_its_uuid! {
        access_request_id: AccessRequestId,
        access_review_id: AccessReviewId,
        relationship_id: RelationshipId,
        separation_rule_id: SeparationRuleId,
        action_call_id: ActionCallId,
        code_run_id: CodeRunId,
        agent_channel_id: AgentChannelId,
        agent_credential_id: AgentCredentialId,
        agent_id: AgentId,
        agent_run_id: AgentRunId,
        agent_sighting_id: AgentSightingId,
        agent_tool_id: AgentToolId,
        api_key_id: ApiKeyId,
        approval_id: ApprovalId,
        ceremony_id: CeremonyId,
        connection_id: ConnectionId,
        connector_id: ConnectorId,
        consumer_id: ConsumerId,
        egress_policy_id: EgressPolicyId,
        delegation_id: DelegationId,
        delegation_request_id: DelegationRequestId,
        directory_service_account_id: DirectoryServiceAccountId,
        data_export_id: DataExportId,
        user_import_id: UserImportId,
        support_impersonation_id: SupportImpersonationId,
        job_id: JobId,
        model_provider_id: ModelProviderId,
        oauth_client_id: OAuthClientId,
        refresh_family_id: RefreshFamilyId,
        initial_access_token_id: InitialAccessTokenId,
        pushed_request_id: PushedRequestId,
        operation_risk_override_id: OperationRiskOverrideId,
        sandbox_id: SandboxId,
        memory_id: MemoryId,
        memory_entry_id: MemoryEntryId,
        sandbox_version_id: SandboxVersionId,
        sandbox_trial_id: SandboxTrialId,
        image_registry_id: ImageRegistryId,
        evaluation_id: EvaluationId,
        operator_id: OperatorId,
        org_user_id: OrgUserId,
        organization_id: OrganizationId,
        principal_id: PrincipalId,
        resource_type_id: ResourceTypeId,
        review_assignment_id: ReviewAssignmentId,
        role_id: RoleId,
        service_id: ServiceId,
        session_id: SessionId,
        stream_route_id: StreamRouteId,
        task_template_id: TaskTemplateId,
        tenant_id: TenantId,
        tenant_clone_id: TenantCloneId,
        user_id: UserId,
        attribute_definition_id: AttributeDefinitionId,
        audit_record_id: AuditRecordId,
        audit_stream_id: AuditStreamId,
        audit_export_id: AuditExportId,
        correlation_id: CorrelationId,
        break_glass_grant_id: BreakGlassGrantId,
        certificate_id: CertificateId,
        classification_rule_id: ClassificationRuleId,
        classification_rule_set_id: ClassificationRuleSetId,
        consent_id: ConsentId,
        domain_id: DomainId,
        erasure_request_id: ErasureRequestId,
        event_schema_id: EventSchemaId,
        evidence_id: EvidenceId,
        group_id: GroupId,
        impersonation_grant_id: ImpersonationGrantId,
        invitation_id: InvitationId,
        ldap_certificate_id: LdapCertificateId,
        linked_identity_id: LinkedIdentityId,
        log_shipping_target_id: LogShippingTargetId,
        message_subscription_id: MessageSubscriptionId,
        notification_destination_id: NotificationDestinationId,
        notification_id: NotificationId,
        org_api_key_id: OrgApiKeyId,
        org_invitation_id: OrgInvitationId,
        passkey_id: PasskeyId,
        password_reset_id: PasswordResetId,
        pipeline_id: PipelineId,
        route_id: RouteId,
        saml_arrival_id: SamlArrivalId,
        saml_service_provider_id: SamlServiceProviderId,
        signal_delivery_id: SignalDeliveryId,
        signal_id: SignalId,
        signal_stream_id: SignalStreamId,
        stage_id: StageId,
        topic_id: TopicId,
        trusted_device_id: TrustedDeviceId,
        webhook_delivery_id: WebhookDeliveryId,
        webhook_message_id: WebhookMessageId,
        webhook_subscription_id: WebhookSubscriptionId,
        integration_account_id: IntegrationAccountId,
        pending_connection_id: PendingConnectionId,
        service_subscription_id: ServiceSubscriptionId,
        account_channel_id: AccountChannelId,
        workflow_execution_id: WorkflowExecutionId,
        workflow_id: WorkflowId,
        workflow_trigger_id: WorkflowTriggerId,
    }
}

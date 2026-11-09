window.DOMAIN_GRAPH = {
  "aggregates": [
    {
      "context": "authorization",
      "file": "domains/authorization/access_request.rs",
      "id": "AccessRequest"
    },
    {
      "context": "authorization",
      "file": "domains/authorization/request_policy.rs",
      "id": "AccessRequestPolicy"
    },
    {
      "context": "authorization",
      "file": "domains/authorization/access_review.rs",
      "id": "AccessReview"
    },
    {
      "context": "oauth",
      "file": "domains/oauth/grants/access_token.rs",
      "id": "AccessToken"
    },
    {
      "context": "tenant",
      "file": "domains/tenant/custom_domains/acme_challenge.rs",
      "id": "AcmeChallenge"
    },
    {
      "context": "agents",
      "file": "domains/agents/channels/channel.rs",
      "id": "AgentChannel"
    },
    {
      "context": "agents",
      "file": "domains/agents/identity/credential.rs",
      "id": "AgentCredential"
    },
    {
      "context": "agents",
      "file": "domains/agents/identity/agent.rs",
      "id": "AgentIdentity"
    },
    {
      "context": "agents",
      "file": "domains/agents/execution/run/mod.rs",
      "id": "AgentRun"
    },
    {
      "context": "agents",
      "file": "domains/agents/identity/sighting.rs",
      "id": "AgentSighting"
    },
    {
      "context": "agents",
      "file": "domains/agents/execution/tool.rs",
      "id": "AgentTool"
    },
    {
      "context": "crypto",
      "file": "domains/crypto/algorithm_migration.rs",
      "id": "AlgorithmMigration"
    },
    {
      "context": "oauth",
      "file": "domains/oauth/clients/api_key.rs",
      "id": "ApiKey"
    },
    {
      "context": "agents",
      "file": "domains/agents/oversight/approval/mod.rs",
      "id": "ApprovalRequest"
    },
    {
      "context": "crypto",
      "file": "domains/crypto/assertion_key.rs",
      "id": "AssertionKey"
    },
    {
      "context": "agents",
      "file": "domains/agents/identity/challenge.rs",
      "id": "AttestationChallenge"
    },
    {
      "context": "identity",
      "file": "domains/identity/attribute/definition/mod.rs",
      "id": "AttributeDefinition"
    },
    {
      "context": "audit",
      "file": "domains/audit/export.rs",
      "id": "AuditLogExport"
    },
    {
      "context": "tenant",
      "file": "domains/tenant/audit_streams.rs",
      "id": "AuditStream"
    },
    {
      "context": "oauth",
      "file": "domains/oauth/grants/authorization_code.rs",
      "id": "AuthorizationCode"
    },
    {
      "context": "authorization",
      "file": "domains/authorization/break_glass.rs",
      "id": "BreakGlassGrant"
    },
    {
      "context": "authorization",
      "file": "domains/authorization/break_glass.rs",
      "id": "BreakGlassPolicy"
    },
    {
      "context": "agents",
      "file": "domains/agents/execution/run/cancel.rs",
      "id": "CancelOrder"
    },
    {
      "context": "tenant",
      "file": "domains/tenant/custom_domains/certificate.rs",
      "id": "CertificateBundle"
    },
    {
      "context": "audit",
      "file": "domains/audit/verdict.rs",
      "id": "ChainVerdict"
    },
    {
      "context": "data_classification",
      "file": "domains/data_classification/classification.rs",
      "id": "ClassificationRuleSet"
    },
    {
      "context": "authorization",
      "file": "domains/authorization/clearance.rs",
      "id": "ClearanceRules"
    },
    {
      "context": "organization",
      "file": "domains/organization/cloud/account.rs",
      "id": "CloudAccount"
    },
    {
      "context": "routing",
      "file": "domains/routing/connector/tunnel.rs",
      "id": "ConnectorTunnel"
    },
    {
      "context": "identity",
      "file": "domains/identity/privacy/consent.rs",
      "id": "ConsentRecord"
    },
    {
      "context": "consumers",
      "file": "domains/consumers/consumer.rs",
      "id": "Consumer"
    },
    {
      "context": "identity",
      "file": "domains/identity/privacy/export.rs",
      "id": "DataExportRequest"
    },
    {
      "context": "agents",
      "file": "domains/agents/authority/delegation/mod.rs",
      "id": "Delegation"
    },
    {
      "context": "agents",
      "file": "domains/agents/authority/delegation_request.rs",
      "id": "DelegationRequest"
    },
    {
      "context": "oauth",
      "file": "domains/oauth/grants/device_authorization.rs",
      "id": "DeviceAuthorization"
    },
    {
      "context": "authentication",
      "file": "domains/authentication/directory_service/account.rs",
      "id": "DirectoryServiceAccount"
    },
    {
      "context": "routing",
      "file": "domains/routing/egress.rs",
      "id": "EgressPolicy"
    },
    {
      "context": "branding",
      "file": "domains/branding/email_template.rs",
      "id": "EmailTemplate"
    },
    {
      "context": "identity",
      "file": "domains/identity/privacy/erasure.rs",
      "id": "ErasureRequest"
    },
    {
      "context": "messaging",
      "file": "domains/messaging/schema.rs",
      "id": "EventSchema"
    },
    {
      "context": "federation",
      "file": "domains/federation/connection.rs",
      "id": "FederatedIdpConnection"
    },
    {
      "context": "federation",
      "file": "domains/federation/link.rs",
      "id": "FederatedLink"
    },
    {
      "context": "authorization",
      "file": "domains/authorization/group/mod.rs",
      "id": "Group"
    },
    {
      "context": "authorization",
      "file": "domains/authorization/group/membership.rs",
      "id": "GroupMembership"
    },
    {
      "context": "tenant",
      "file": "domains/tenant/custom_domains/handover_offer.rs",
      "id": "HandoverOffer"
    },
    {
      "context": "operator",
      "file": "domains/operator/impersonation.rs",
      "id": "ImpersonationGrant"
    },
    {
      "context": "federation",
      "file": "domains/federation/saml/authn_request.rs",
      "id": "InboundAuthnRequest"
    },
    {
      "context": "oauth",
      "file": "domains/oauth/clients/registration.rs",
      "id": "InitialAccessToken"
    },
    {
      "context": "workflows",
      "file": "domains/workflows/account.rs",
      "id": "IntegrationAccount"
    },
    {
      "context": "identity",
      "file": "domains/identity/invitations/invitation.rs",
      "id": "Invitation"
    },
    {
      "context": "identity",
      "file": "domains/identity/invitations/offer.rs",
      "id": "InvitationOffer"
    },
    {
      "context": "authentication",
      "file": "domains/authentication/ldap_certificate.rs",
      "id": "LdapClientCertificate"
    },
    {
      "context": "organization",
      "file": "domains/organization/members/linked_identity.rs",
      "id": "LinkedIdentity"
    },
    {
      "context": "proxy",
      "file": "domains/proxy/log_shipping/mod.rs",
      "id": "LogShippingTarget"
    },
    {
      "context": "federation",
      "file": "domains/federation/connection/mapped_holdings.rs",
      "id": "MappedHoldings"
    },
    {
      "context": "notifications",
      "file": "domains/notifications/personal.rs",
      "id": "MemberNotificationPreferences"
    },
    {
      "context": "authentication",
      "file": "domains/authentication/sessions/mfa_challenge.rs",
      "id": "MfaChallenge"
    },
    {
      "context": "authentication",
      "file": "domains/authentication/mfa/enrollment.rs",
      "id": "MfaEnrollment"
    },
    {
      "context": "agents",
      "file": "domains/agents/execution/model_provider.rs",
      "id": "ModelProvider"
    },
    {
      "context": "notifications",
      "file": "domains/notifications/notification.rs",
      "id": "Notification"
    },
    {
      "context": "notifications",
      "file": "domains/notifications/destination.rs",
      "id": "NotificationDestination"
    },
    {
      "context": "notifications",
      "file": "domains/notifications/preference.rs",
      "id": "NotificationPreference"
    },
    {
      "context": "oauth",
      "file": "domains/oauth/clients/client.rs",
      "id": "OAuthClient"
    },
    {
      "context": "oauth",
      "file": "domains/oauth/clients/consent.rs",
      "id": "OAuthConsent"
    },
    {
      "context": "oauth",
      "file": "domains/oauth/grants/refresh_token.rs",
      "id": "OAuthRefreshToken"
    },
    {
      "context": "authentication",
      "file": "domains/authentication/mfa/one_time_code.rs",
      "id": "OneTimeCode"
    },
    {
      "context": "workflows",
      "file": "domains/workflows/risk_override.rs",
      "id": "OperationRiskOverride"
    },
    {
      "context": "operator",
      "file": "domains/operator/identity.rs",
      "id": "Operator"
    },
    {
      "context": "operator",
      "file": "domains/operator/api_key.rs",
      "id": "OperatorApiKey"
    },
    {
      "context": "notifications",
      "file": "domains/notifications/personal.rs",
      "id": "OperatorNotificationPreferences"
    },
    {
      "context": "organization",
      "file": "domains/organization/access/api_key.rs",
      "id": "OrgApiKey"
    },
    {
      "context": "organization",
      "file": "domains/organization/branding.rs",
      "id": "OrgBranding"
    },
    {
      "context": "organization",
      "file": "domains/organization/members/privacy/consent.rs",
      "id": "OrgConsentRecord"
    },
    {
      "context": "organization",
      "file": "domains/organization/members/privacy/erasure.rs",
      "id": "OrgErasureRequest"
    },
    {
      "context": "organization",
      "file": "domains/organization/access/identity_provider.rs",
      "id": "OrgIdentityProvider"
    },
    {
      "context": "organization",
      "file": "domains/organization/members/invitation.rs",
      "id": "OrgInvitation"
    },
    {
      "context": "organization",
      "file": "domains/organization/access/passkey.rs",
      "id": "OrgPasskeyCeremony"
    },
    {
      "context": "organization",
      "file": "domains/organization/access/session.rs",
      "id": "OrgSession"
    },
    {
      "context": "organization",
      "file": "domains/organization/billing/subscription.rs",
      "id": "OrgSubscription"
    },
    {
      "context": "organization",
      "file": "domains/organization/members/tenant_grant.rs",
      "id": "OrgTenantGrant"
    },
    {
      "context": "organization",
      "file": "domains/organization/access/token.rs",
      "id": "OrgToken"
    },
    {
      "context": "organization",
      "file": "domains/organization/members/org_user.rs",
      "id": "OrgUser"
    },
    {
      "context": "organization",
      "file": "domains/organization/lifecycle.rs",
      "id": "Organization"
    },
    {
      "context": "authentication",
      "file": "domains/authentication/credentials/passkey_ceremony.rs",
      "id": "PasskeyCeremony"
    },
    {
      "context": "authentication",
      "file": "domains/authentication/credentials/passkey.rs",
      "id": "PasskeyCredential"
    },
    {
      "context": "authentication",
      "file": "domains/authentication/recovery/reset.rs",
      "id": "PasswordResetRequest"
    },
    {
      "context": "identity",
      "file": "domains/identity/account/email_change.rs",
      "id": "PendingEmailChange"
    },
    {
      "context": "organization",
      "file": "domains/organization/signup.rs",
      "id": "PendingSignup"
    },
    {
      "context": "proxy",
      "file": "domains/proxy/pipeline.rs",
      "id": "Pipeline"
    },
    {
      "context": "tenant",
      "file": "domains/tenant/hosts/certificate.rs",
      "id": "PlatformCertificate"
    },
    {
      "context": "authorization",
      "file": "domains/authorization/policy/set.rs",
      "id": "PolicySet"
    },
    {
      "context": "routing",
      "file": "domains/routing/connector/mod.rs",
      "id": "PrivateConnector"
    },
    {
      "context": "oauth",
      "file": "domains/oauth/grants/pushed_request.rs",
      "id": "PushedRequest"
    },
    {
      "context": "authentication",
      "file": "domains/authentication/recovery/codes.rs",
      "id": "RecoveryCode"
    },
    {
      "context": "authentication",
      "file": "domains/authentication/recovery/codes.rs",
      "id": "RecoveryCodeSet"
    },
    {
      "context": "tenant",
      "file": "domains/tenant/custom_domains/registered_domain.rs",
      "id": "RegisteredDomain"
    },
    {
      "context": "authorization",
      "file": "domains/authorization/relationship.rs",
      "id": "Relationship"
    },
    {
      "context": "authorization",
      "file": "domains/authorization/resource_type/mod.rs",
      "id": "ResourceType"
    },
    {
      "context": "agents",
      "file": "domains/agents/oversight/review.rs",
      "id": "ReviewAssignment"
    },
    {
      "context": "authorization",
      "file": "domains/authorization/role/mod.rs",
      "id": "Role"
    },
    {
      "context": "authorization",
      "file": "domains/authorization/role_assignment.rs",
      "id": "RoleAssignment"
    },
    {
      "context": "routing",
      "file": "domains/routing/route/mod.rs",
      "id": "Route"
    },
    {
      "context": "federation",
      "file": "domains/federation/service_provider.rs",
      "id": "SamlServiceProvider"
    },
    {
      "context": "scheduling",
      "file": "domains/scheduling/job.rs",
      "id": "ScheduledJob"
    },
    {
      "context": "federation",
      "file": "domains/federation/scim.rs",
      "id": "ScimEndpoint"
    },
    {
      "context": "identity",
      "file": "domains/identity/tokens/secure.rs",
      "id": "SecureToken"
    },
    {
      "context": "signals",
      "file": "domains/signals/signal.rs",
      "id": "SecuritySignal"
    },
    {
      "context": "federation",
      "file": "domains/federation/saml/logout.rs",
      "id": "SentLogoutRequest"
    },
    {
      "context": "authorization",
      "file": "domains/authorization/separation.rs",
      "id": "SeparationRule"
    },
    {
      "context": "routing",
      "file": "domains/routing/service.rs",
      "id": "Service"
    },
    {
      "context": "authentication",
      "file": "domains/authentication/sessions/session/mod.rs",
      "id": "Session"
    },
    {
      "context": "authentication",
      "file": "domains/authentication/sessions/handoff.rs",
      "id": "SessionHandoff"
    },
    {
      "context": "authentication",
      "file": "domains/authentication/sessions/sign_in_code.rs",
      "id": "SignInCode"
    },
    {
      "context": "authentication",
      "file": "domains/authentication/sessions/sign_in_progress.rs",
      "id": "SignInProgress"
    },
    {
      "context": "signals",
      "file": "domains/signals/stream.rs",
      "id": "SignalStream"
    },
    {
      "context": "crypto",
      "file": "domains/crypto/signing_key.rs",
      "id": "SigningKey"
    },
    {
      "context": "proxy",
      "file": "domains/proxy/stages/stage/mod.rs",
      "id": "StageConfig"
    },
    {
      "context": "routing",
      "file": "domains/routing/stream/mod.rs",
      "id": "StreamRoute"
    },
    {
      "context": "messaging",
      "file": "domains/messaging/subscription.rs",
      "id": "Subscription"
    },
    {
      "context": "identity",
      "file": "domains/identity/impersonation/mod.rs",
      "id": "SupportImpersonation"
    },
    {
      "context": "agents",
      "file": "domains/agents/authority/task_template.rs",
      "id": "TaskTemplate"
    },
    {
      "context": "tenant",
      "file": "domains/tenant/lifecycle.rs",
      "id": "Tenant"
    },
    {
      "context": "branding",
      "file": "domains/branding/config.rs",
      "id": "TenantBranding"
    },
    {
      "context": "tenant",
      "file": "domains/tenant/clone.rs",
      "id": "TenantClone"
    },
    {
      "context": "organization",
      "file": "domains/organization/members/linked_identity.rs",
      "id": "TenantLink"
    },
    {
      "context": "branding",
      "file": "domains/branding/mail_provider.rs",
      "id": "TenantMailProvider"
    },
    {
      "context": "tenant",
      "file": "domains/tenant/setup.rs",
      "id": "TenantSetup"
    },
    {
      "context": "tenant",
      "file": "domains/tenant/teardown.rs",
      "id": "TenantTeardown"
    },
    {
      "context": "messaging",
      "file": "domains/messaging/topic.rs",
      "id": "Topic"
    },
    {
      "context": "authentication",
      "file": "domains/authentication/device_trust.rs",
      "id": "TrustedDevice"
    },
    {
      "context": "identity",
      "file": "domains/identity/account/user/mod.rs",
      "id": "User"
    },
    {
      "context": "identity",
      "file": "domains/identity/account/import/run.rs",
      "id": "UserImport"
    },
    {
      "context": "crypto",
      "file": "domains/crypto/verifying_key.rs",
      "id": "VerifyingKey"
    },
    {
      "context": "webhooks",
      "file": "domains/webhooks/subscription.rs",
      "id": "WebhookSubscription"
    },
    {
      "context": "workflows",
      "file": "domains/workflows/workflow.rs",
      "id": "Workflow"
    },
    {
      "context": "workflows",
      "file": "domains/workflows/execution/mod.rs",
      "id": "WorkflowExecution"
    },
    {
      "context": "workflows",
      "file": "domains/workflows/trigger_secret.rs",
      "id": "WorkflowTriggerSecret"
    }
  ],
  "contexts": [
    {
      "id": "activity",
      "layer": 0
    },
    {
      "id": "audit",
      "layer": 0
    },
    {
      "id": "crypto",
      "layer": 0
    },
    {
      "id": "data_classification",
      "layer": 0
    },
    {
      "id": "identity",
      "layer": 0
    },
    {
      "id": "metrics",
      "layer": 0
    },
    {
      "id": "scheduling",
      "layer": 0
    },
    {
      "id": "signals",
      "layer": 0
    },
    {
      "id": "authentication",
      "layer": 1
    },
    {
      "id": "authorization",
      "layer": 2
    },
    {
      "id": "tenant",
      "layer": 3
    },
    {
      "id": "consumers",
      "layer": 4
    },
    {
      "id": "routing",
      "layer": 5
    },
    {
      "id": "branding",
      "layer": 6
    },
    {
      "id": "federation",
      "layer": 6
    },
    {
      "id": "messaging",
      "layer": 6
    },
    {
      "id": "oauth",
      "layer": 6
    },
    {
      "id": "operator",
      "layer": 6
    },
    {
      "id": "organization",
      "layer": 7
    },
    {
      "id": "agents",
      "layer": 8
    },
    {
      "id": "notifications",
      "layer": 8
    },
    {
      "id": "proxy",
      "layer": 9
    },
    {
      "id": "webhooks",
      "layer": 9
    },
    {
      "id": "workflows",
      "layer": 9
    }
  ],
  "holes": [
    {
      "aggregate": "BudgetKey",
      "file": "domains/agents/authority/capability/budget.rs",
      "kind": "caller-by-id",
      "line": 172,
      "method": "counted_for",
      "parameter": "acting_for"
    },
    {
      "aggregate": "Role",
      "file": "domains/authorization/role/starting.rs",
      "kind": "proof-ignored",
      "line": 74,
      "method": "starting"
    },
    {
      "aggregate": "Pipeline",
      "detail": "RoutingRight::DeletePipeline",
      "file": "domains/proxy/pipeline.rs",
      "kind": "right-does-not-fit",
      "line": 347,
      "method": "delete",
      "severity": "check"
    },
    {
      "aggregate": "Session",
      "file": "domains/authentication/sessions/session/rotation.rs",
      "kind": "refusal-untested",
      "line": 92,
      "method": "hand_over",
      "severity": "check"
    },
    {
      "aggregate": "Role",
      "file": "domains/authorization/role/starting.rs",
      "kind": "refusal-untested",
      "line": 74,
      "method": "starting",
      "severity": "check"
    },
    {
      "aggregate": "FederatedIdpConnection",
      "file": "domains/federation/connection/provisioning.rs",
      "kind": "refusal-untested",
      "line": 151,
      "method": "stop_mapping_groups",
      "severity": "check"
    },
    {
      "aggregate": "FederatedIdpConnection",
      "file": "domains/federation/connection/saml.rs",
      "kind": "refusal-untested",
      "line": 137,
      "method": "roll_over_certificate",
      "severity": "check"
    },
    {
      "aggregate": "User",
      "file": "domains/identity/account/user/directory.rs",
      "kind": "refusal-untested",
      "line": 36,
      "method": "switch_by_directory",
      "severity": "check"
    },
    {
      "aggregate": "MemberNotificationPreferences",
      "file": "domains/notifications/personal.rs",
      "kind": "refusal-untested",
      "line": 98,
      "method": "for_member",
      "severity": "check"
    },
    {
      "aggregate": "OrgIdentityProvider",
      "file": "domains/organization/access/identity_provider.rs",
      "kind": "refusal-untested",
      "line": 290,
      "method": "switch",
      "severity": "check"
    },
    {
      "aggregate": "OrgSubscription",
      "file": "domains/organization/billing/subscription.rs",
      "kind": "refusal-untested",
      "line": 310,
      "method": "choose_plan",
      "severity": "check"
    }
  ],
  "methods": [
    {
      "aggregate": "Delegation",
      "aggregates": [],
      "file": "domains/agents/authority/delegation/mod.rs",
      "kind": "create",
      "line": 106,
      "name": "grant",
      "proofs": [
        "HeldBy"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Delegation",
      "aggregates": [],
      "file": "domains/agents/authority/delegation/mod.rs",
      "kind": "create",
      "line": 224,
      "name": "grant_owned_within",
      "proofs": [
        "OwnedTokenRequest"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Delegation",
      "aggregates": [],
      "file": "domains/agents/authority/delegation/mod.rs",
      "kind": "change",
      "line": 563,
      "name": "revoke",
      "proofs": [
        "Revoker"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Delegation",
      "aggregates": [],
      "file": "domains/agents/authority/delegation/mod.rs",
      "kind": "change",
      "line": 578,
      "name": "record_drift",
      "proofs": [],
      "rights": [],
      "uncalled": "the platform's drift monitor records an action leaving the delegation's intent; nothing stored changes and it grants nothing"
    },
    {
      "aggregate": "Delegation",
      "aggregates": [],
      "file": "domains/agents/authority/delegation/renewal.rs",
      "kind": "change",
      "line": 47,
      "name": "renew",
      "proofs": [
        "HeldBy"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Delegation",
      "aggregates": [],
      "file": "domains/agents/authority/delegation/resources.rs",
      "kind": "change",
      "line": 41,
      "name": "grant_resource",
      "proofs": [
        "ResourceCeiling"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Delegation",
      "aggregates": [],
      "file": "domains/agents/authority/delegation/resources.rs",
      "kind": "change",
      "line": 88,
      "name": "revoke_resource",
      "proofs": [
        "Revoker"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "DelegationRequest",
      "aggregates": [
        "AgentIdentity"
      ],
      "file": "domains/agents/authority/delegation_request.rs",
      "kind": "create",
      "line": 148,
      "name": "ask",
      "proofs": [
        "ActingAgent"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "DelegationRequest",
      "aggregates": [],
      "file": "domains/agents/authority/delegation_request.rs",
      "kind": "change",
      "line": 289,
      "name": "approve",
      "proofs": [
        "HeldBy"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "DelegationRequest",
      "aggregates": [
        "AgentIdentity"
      ],
      "file": "domains/agents/authority/delegation_request.rs",
      "kind": "change",
      "line": 336,
      "name": "deny",
      "proofs": [
        "AgentControl"
      ],
      "rights": [
        "AgentAction::Manage"
      ],
      "uncalled": null
    },
    {
      "aggregate": "TaskTemplate",
      "aggregates": [],
      "file": "domains/agents/authority/task_template.rs",
      "kind": "create",
      "line": 307,
      "name": "propose",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "TaskTemplate",
      "aggregates": [],
      "file": "domains/agents/authority/task_template.rs",
      "kind": "change",
      "line": 478,
      "name": "approve",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "TaskTemplate",
      "aggregates": [],
      "file": "domains/agents/authority/task_template.rs",
      "kind": "change",
      "line": 515,
      "name": "retire",
      "proofs": [
        "AgentControl"
      ],
      "rights": [
        "AgentAction::Delegate"
      ],
      "uncalled": null
    },
    {
      "aggregate": "AgentChannel",
      "aggregates": [],
      "file": "domains/agents/channels/channel.rs",
      "kind": "create",
      "line": 218,
      "name": "open",
      "proofs": [
        "AgentControl"
      ],
      "rights": [
        "AgentAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "AgentChannel",
      "aggregates": [],
      "file": "domains/agents/channels/channel.rs",
      "kind": "change",
      "line": 420,
      "name": "close",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ModelProvider",
      "aggregates": [],
      "file": "domains/agents/execution/model_provider.rs",
      "kind": "create",
      "line": 133,
      "name": "create",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ModelProvider",
      "aggregates": [],
      "file": "domains/agents/execution/model_provider.rs",
      "kind": "change",
      "line": 296,
      "name": "change_clearance",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ModelProvider",
      "aggregates": [],
      "file": "domains/agents/execution/model_provider.rs",
      "kind": "change",
      "line": 338,
      "name": "rotate_key",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ModelProvider",
      "aggregates": [],
      "file": "domains/agents/execution/model_provider.rs",
      "kind": "change",
      "line": 374,
      "name": "change_model",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ModelProvider",
      "aggregates": [],
      "file": "domains/agents/execution/model_provider.rs",
      "kind": "change",
      "line": 409,
      "name": "disable",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ModelProvider",
      "aggregates": [],
      "file": "domains/agents/execution/model_provider.rs",
      "kind": "change",
      "line": 422,
      "name": "enable",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ModelProvider",
      "aggregates": [],
      "file": "domains/agents/execution/model_provider.rs",
      "kind": "change",
      "line": 441,
      "name": "delete",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ModelProvider",
      "aggregates": [],
      "file": "domains/agents/execution/model_provider.rs",
      "kind": "change",
      "line": 487,
      "name": "record_test_result",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AgentRun",
      "aggregates": [],
      "file": "domains/agents/execution/run/announce.rs",
      "kind": "change",
      "line": 50,
      "name": "announce_start",
      "proofs": [],
      "rights": [],
      "uncalled": "records a move the run or request already made, with the names the audit trail knows; it changes and grants nothing"
    },
    {
      "aggregate": "AgentRun",
      "aggregates": [],
      "file": "domains/agents/execution/run/announce.rs",
      "kind": "change",
      "line": 69,
      "name": "announce_pause",
      "proofs": [],
      "rights": [],
      "uncalled": "records a move the run or request already made, with the names the audit trail knows; it changes and grants nothing"
    },
    {
      "aggregate": "AgentRun",
      "aggregates": [],
      "file": "domains/agents/execution/run/announce.rs",
      "kind": "change",
      "line": 88,
      "name": "announce_end",
      "proofs": [],
      "rights": [],
      "uncalled": "records a move the run or request already made, with the names the audit trail knows; it changes and grants nothing"
    },
    {
      "aggregate": "AgentRun",
      "aggregates": [
        "AgentIdentity",
        "CancelOrder"
      ],
      "file": "domains/agents/execution/run/announce.rs",
      "kind": "change",
      "line": 113,
      "name": "announce_cancel_request",
      "proofs": [
        "CancelOrder"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AgentRun",
      "aggregates": [
        "AgentIdentity",
        "Delegation"
      ],
      "file": "domains/agents/execution/run/mod.rs",
      "kind": "create",
      "line": 118,
      "name": "start",
      "proofs": [
        "RunStarter"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AgentRun",
      "aggregates": [
        "AgentIdentity"
      ],
      "file": "domains/agents/execution/run/mod.rs",
      "kind": "create",
      "line": 143,
      "name": "start_without_tools",
      "proofs": [
        "RunStarter"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AgentRun",
      "aggregates": [
        "AgentIdentity"
      ],
      "file": "domains/agents/execution/run/pause.rs",
      "kind": "change",
      "line": 40,
      "name": "await_approval",
      "proofs": [],
      "rights": [],
      "uncalled": "a step of the run itself, admitted by its gate against the delegation"
    },
    {
      "aggregate": "AgentRun",
      "aggregates": [],
      "file": "domains/agents/execution/run/pause.rs",
      "kind": "change",
      "line": 80,
      "name": "approve_pending",
      "proofs": [
        "ReleasedCall"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AgentRun",
      "aggregates": [],
      "file": "domains/agents/execution/run/pause.rs",
      "kind": "change",
      "line": 119,
      "name": "deny_pending",
      "proofs": [
        "DeniedCall"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AgentRun",
      "aggregates": [],
      "file": "domains/agents/execution/run/pause.rs",
      "kind": "change",
      "line": 138,
      "name": "fail_at_approval_limit",
      "proofs": [],
      "rights": [],
      "uncalled": "the tenant's plan, not a person, has no room for another approval request; it only ends the run failed and grants nothing"
    },
    {
      "aggregate": "AgentRun",
      "aggregates": [],
      "file": "domains/agents/execution/run/pause.rs",
      "kind": "change",
      "line": 170,
      "name": "reply_to_pending",
      "proofs": [
        "DeniedCall"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AgentRun",
      "aggregates": [
        "AgentIdentity"
      ],
      "file": "domains/agents/execution/run/pause.rs",
      "kind": "change",
      "line": 208,
      "name": "revise_pending",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AgentRun",
      "aggregates": [
        "ModelProvider"
      ],
      "file": "domains/agents/execution/run/spend.rs",
      "kind": "change",
      "line": 36,
      "name": "record_model_usage",
      "proofs": [],
      "rights": [],
      "uncalled": "a step of the run itself, admitted by its gate against the delegation"
    },
    {
      "aggregate": "AgentRun",
      "aggregates": [
        "AgentIdentity"
      ],
      "file": "domains/agents/execution/run/steering.rs",
      "kind": "change",
      "line": 33,
      "name": "pause",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AgentRun",
      "aggregates": [
        "AgentIdentity"
      ],
      "file": "domains/agents/execution/run/steering.rs",
      "kind": "change",
      "line": 66,
      "name": "resume",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AgentRun",
      "aggregates": [
        "AgentIdentity"
      ],
      "file": "domains/agents/execution/run/stepping.rs",
      "kind": "change",
      "line": 97,
      "name": "record_allowed",
      "proofs": [],
      "rights": [],
      "uncalled": "a step of the run itself, admitted by its gate against the delegation"
    },
    {
      "aggregate": "AgentRun",
      "aggregates": [],
      "file": "domains/agents/execution/run/stepping.rs",
      "kind": "change",
      "line": 127,
      "name": "record_denied",
      "proofs": [],
      "rights": [],
      "uncalled": "a step of the run itself, admitted by its gate against the delegation"
    },
    {
      "aggregate": "AgentRun",
      "aggregates": [],
      "file": "domains/agents/execution/run/stepping.rs",
      "kind": "change",
      "line": 202,
      "name": "complete",
      "proofs": [],
      "rights": [],
      "uncalled": "a step of the run itself, admitted by its gate against the delegation"
    },
    {
      "aggregate": "AgentRun",
      "aggregates": [],
      "file": "domains/agents/execution/run/stepping.rs",
      "kind": "change",
      "line": 217,
      "name": "fail",
      "proofs": [],
      "rights": [],
      "uncalled": "a step of the run itself, admitted by its gate against the delegation"
    },
    {
      "aggregate": "AgentRun",
      "aggregates": [
        "CancelOrder"
      ],
      "file": "domains/agents/execution/run/stepping.rs",
      "kind": "change",
      "line": 258,
      "name": "cancel",
      "proofs": [
        "CancelOrder"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AgentRun",
      "aggregates": [],
      "file": "domains/agents/execution/run/stepping.rs",
      "kind": "change",
      "line": 274,
      "name": "halt",
      "proofs": [],
      "rights": [],
      "uncalled": "a step of the run itself, admitted by its gate against the delegation"
    },
    {
      "aggregate": "AgentTool",
      "aggregates": [
        "Route"
      ],
      "file": "domains/agents/execution/tool.rs",
      "kind": "create",
      "line": 241,
      "name": "register",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AgentTool",
      "aggregates": [],
      "file": "domains/agents/execution/tool.rs",
      "kind": "change",
      "line": 421,
      "name": "disable",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AgentTool",
      "aggregates": [],
      "file": "domains/agents/execution/tool.rs",
      "kind": "change",
      "line": 432,
      "name": "enable",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AgentTool",
      "aggregates": [
        "Route"
      ],
      "file": "domains/agents/execution/tool.rs",
      "kind": "change",
      "line": 451,
      "name": "edit",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AgentTool",
      "aggregates": [],
      "file": "domains/agents/execution/tool.rs",
      "kind": "change",
      "line": 495,
      "name": "delete",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AgentIdentity",
      "aggregates": [],
      "file": "domains/agents/identity/agent/attesting.rs",
      "kind": "change",
      "line": 101,
      "name": "trust_attestation",
      "proofs": [
        "AgentControl"
      ],
      "rights": [
        "AgentAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "AgentIdentity",
      "aggregates": [],
      "file": "domains/agents/identity/agent/attesting.rs",
      "kind": "change",
      "line": 126,
      "name": "clear_attestation_policy",
      "proofs": [
        "AgentControl"
      ],
      "rights": [
        "AgentAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "AgentIdentity",
      "aggregates": [],
      "file": "domains/agents/identity/agent/attesting.rs",
      "kind": "change",
      "line": 150,
      "name": "require_reattestation",
      "proofs": [
        "AgentControl"
      ],
      "rights": [
        "AgentAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "AgentIdentity",
      "aggregates": [],
      "file": "domains/agents/identity/agent/attesting.rs",
      "kind": "change",
      "line": 174,
      "name": "record_attestation",
      "proofs": [
        "AttestedIdentity"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AgentIdentity",
      "aggregates": [],
      "file": "domains/agents/identity/agent/attesting.rs",
      "kind": "change",
      "line": 198,
      "name": "issue_attestation_challenge",
      "proofs": [],
      "rights": [],
      "uncalled": "the agent asks for its own bootstrap challenge before it can prove anything; the challenge grants nothing until a bootstrap spends it with an attestation the agent's policy trusts"
    },
    {
      "aggregate": "AgentIdentity",
      "aggregates": [],
      "file": "domains/agents/identity/agent/ownership.rs",
      "kind": "change",
      "line": 213,
      "name": "transfer_ownership",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AgentIdentity",
      "aggregates": [],
      "file": "domains/agents/identity/agent/ownership.rs",
      "kind": "change",
      "line": 243,
      "name": "offer_ownership",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AgentIdentity",
      "aggregates": [],
      "file": "domains/agents/identity/agent/ownership.rs",
      "kind": "change",
      "line": 282,
      "name": "accept_ownership",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AgentIdentity",
      "aggregates": [],
      "file": "domains/agents/identity/agent/ownership.rs",
      "kind": "change",
      "line": 307,
      "name": "withdraw_offer",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AgentIdentity",
      "aggregates": [],
      "file": "domains/agents/identity/agent.rs",
      "kind": "create",
      "line": 117,
      "name": "create",
      "proofs": [
        "AgentControl"
      ],
      "rights": [
        "AgentAction::Create"
      ],
      "uncalled": null
    },
    {
      "aggregate": "AgentIdentity",
      "aggregates": [],
      "file": "domains/agents/identity/agent.rs",
      "kind": "change",
      "line": 283,
      "name": "update_details",
      "proofs": [
        "AgentControl"
      ],
      "rights": [
        "AgentAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "AgentIdentity",
      "aggregates": [],
      "file": "domains/agents/identity/agent.rs",
      "kind": "change",
      "line": 307,
      "name": "suspend",
      "proofs": [
        "SuspendedBy"
      ],
      "rights": [
        "AgentAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "AgentIdentity",
      "aggregates": [],
      "file": "domains/agents/identity/agent.rs",
      "kind": "change",
      "line": 334,
      "name": "resume",
      "proofs": [
        "AgentControl"
      ],
      "rights": [
        "AgentAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "AgentIdentity",
      "aggregates": [],
      "file": "domains/agents/identity/agent.rs",
      "kind": "change",
      "line": 354,
      "name": "revoke",
      "proofs": [
        "AgentControl"
      ],
      "rights": [
        "AgentAction::Delete"
      ],
      "uncalled": null
    },
    {
      "aggregate": "AgentIdentity",
      "aggregates": [],
      "file": "domains/agents/identity/agent.rs",
      "kind": "change",
      "line": 376,
      "name": "contain",
      "proofs": [
        "AgentControl"
      ],
      "rights": [
        "AgentAction::Delete"
      ],
      "uncalled": null
    },
    {
      "aggregate": "AgentIdentity",
      "aggregates": [],
      "file": "domains/agents/identity/agent.rs",
      "kind": "change",
      "line": 394,
      "name": "record_containment",
      "proofs": [
        "AgentControl"
      ],
      "rights": [
        "AgentAction::Delete"
      ],
      "uncalled": null
    },
    {
      "aggregate": "AgentIdentity",
      "aggregates": [],
      "file": "domains/agents/identity/agent.rs",
      "kind": "change",
      "line": 424,
      "name": "delete",
      "proofs": [
        "AgentControl"
      ],
      "rights": [
        "AgentAction::Delete"
      ],
      "uncalled": null
    },
    {
      "aggregate": "AttestationChallenge",
      "aggregates": [],
      "file": "domains/agents/identity/challenge.rs",
      "kind": "create",
      "line": 89,
      "name": "issue",
      "proofs": [],
      "rights": [],
      "uncalled": "issuing a nonce grants nothing; only signing it with the attested key bootstraps the agent"
    },
    {
      "aggregate": "AttestationChallenge",
      "aggregates": [],
      "file": "domains/agents/identity/challenge.rs",
      "kind": "change",
      "line": 184,
      "name": "spend",
      "proofs": [],
      "rights": [],
      "uncalled": "a single-use challenge being spent on one proof; it only takes away"
    },
    {
      "aggregate": "AgentCredential",
      "aggregates": [],
      "file": "domains/agents/identity/credential.rs",
      "kind": "create",
      "line": 185,
      "name": "mint",
      "proofs": [
        "MintAgentCredentialParams"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AgentCredential",
      "aggregates": [
        "AgentIdentity"
      ],
      "file": "domains/agents/identity/credential.rs",
      "kind": "change",
      "line": 519,
      "name": "rotate",
      "proofs": [
        "AgentControl"
      ],
      "rights": [
        "AgentAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "AgentCredential",
      "aggregates": [
        "AgentIdentity"
      ],
      "file": "domains/agents/identity/credential.rs",
      "kind": "change",
      "line": 557,
      "name": "revoke",
      "proofs": [
        "AgentControl"
      ],
      "rights": [
        "AgentAction::Delete"
      ],
      "uncalled": null
    },
    {
      "aggregate": "AgentSighting",
      "aggregates": [],
      "file": "domains/agents/identity/sighting.rs",
      "kind": "create",
      "line": 164,
      "name": "observe",
      "proofs": [],
      "rights": [],
      "uncalled": "the gateway or a scan sees an unregistered agent at work; a sighting grants nothing and is answered by a person who manages agents"
    },
    {
      "aggregate": "AgentSighting",
      "aggregates": [],
      "file": "domains/agents/identity/sighting.rs",
      "kind": "change",
      "line": 265,
      "name": "seen_again",
      "proofs": [],
      "rights": [],
      "uncalled": "the gateway or a scan sees the same unregistered agent again; it only counts and grants nothing"
    },
    {
      "aggregate": "AgentSighting",
      "aggregates": [
        "AgentIdentity"
      ],
      "file": "domains/agents/identity/sighting.rs",
      "kind": "change",
      "line": 285,
      "name": "register",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AgentSighting",
      "aggregates": [],
      "file": "domains/agents/identity/sighting.rs",
      "kind": "change",
      "line": 315,
      "name": "dismiss",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ApprovalRequest",
      "aggregates": [],
      "file": "domains/agents/oversight/approval/mod.rs",
      "kind": "create",
      "line": 92,
      "name": "request",
      "proofs": [],
      "rights": [],
      "uncalled": "opening a request grants nothing; approving it needs an Approver"
    },
    {
      "aggregate": "ApprovalRequest",
      "aggregates": [
        "Delegation"
      ],
      "file": "domains/agents/oversight/approval/mod.rs",
      "kind": "change",
      "line": 325,
      "name": "announce_request",
      "proofs": [],
      "rights": [],
      "uncalled": "records a move the run or request already made, with the names the audit trail knows; it changes and grants nothing"
    },
    {
      "aggregate": "ApprovalRequest",
      "aggregates": [],
      "file": "domains/agents/oversight/approval/mod.rs",
      "kind": "change",
      "line": 337,
      "name": "announce_decision",
      "proofs": [],
      "rights": [],
      "uncalled": "records a move the run or request already made, with the names the audit trail knows; it changes and grants nothing"
    },
    {
      "aggregate": "ApprovalRequest",
      "aggregates": [],
      "file": "domains/agents/oversight/approval/mod.rs",
      "kind": "change",
      "line": 418,
      "name": "approve",
      "proofs": [
        "Approver"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ApprovalRequest",
      "aggregates": [],
      "file": "domains/agents/oversight/approval/mod.rs",
      "kind": "change",
      "line": 514,
      "name": "deny",
      "proofs": [
        "Approver"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ApprovalRequest",
      "aggregates": [],
      "file": "domains/agents/oversight/approval/mod.rs",
      "kind": "change",
      "line": 534,
      "name": "consume",
      "proofs": [
        "ActionAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ApprovalRequest",
      "aggregates": [],
      "file": "domains/agents/oversight/approval/mod.rs",
      "kind": "change",
      "line": 558,
      "name": "release",
      "proofs": [
        "ActionAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ApprovalRequest",
      "aggregates": [],
      "file": "domains/agents/oversight/approval/mod.rs",
      "kind": "change",
      "line": 578,
      "name": "expire",
      "proofs": [],
      "rights": [],
      "uncalled": "its window ran out; the clock decides, and expiring grants nothing"
    },
    {
      "aggregate": "ApprovalRequest",
      "aggregates": [],
      "file": "domains/agents/oversight/approval/mod.rs",
      "kind": "change",
      "line": 598,
      "name": "withdraw",
      "proofs": [
        "RunCancelled"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ApprovalRequest",
      "aggregates": [],
      "file": "domains/agents/oversight/approval/mod.rs",
      "kind": "change",
      "line": 626,
      "name": "supersede",
      "proofs": [
        "RevisedCall"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ReviewAssignment",
      "aggregates": [],
      "file": "domains/agents/oversight/review.rs",
      "kind": "create",
      "line": 191,
      "name": "assign",
      "proofs": [
        "AgentControl"
      ],
      "rights": [
        "AgentAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "ReviewAssignment",
      "aggregates": [],
      "file": "domains/agents/oversight/review.rs",
      "kind": "change",
      "line": 337,
      "name": "end",
      "proofs": [
        "AgentControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ReviewAssignment",
      "aggregates": [],
      "file": "domains/agents/oversight/review.rs",
      "kind": "change",
      "line": 396,
      "name": "verdict",
      "proofs": [
        "ActingAgent"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AuditLogExport",
      "aggregates": [],
      "file": "domains/audit/export.rs",
      "kind": "create",
      "line": 68,
      "name": "request",
      "proofs": [
        "AuditLogAccess"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AuditLogExport",
      "aggregates": [],
      "file": "domains/audit/export.rs",
      "kind": "change",
      "line": 193,
      "name": "mark_written",
      "proofs": [],
      "rights": [],
      "uncalled": "the worker wrote the file a reader who may read the log asked for; only such a reader downloads it"
    },
    {
      "aggregate": "AuditLogExport",
      "aggregates": [],
      "file": "domains/audit/export.rs",
      "kind": "change",
      "line": 208,
      "name": "give_up",
      "proofs": [],
      "rights": [],
      "uncalled": "the worker did not write the file in time; the clock decides, and giving up keeps nothing"
    },
    {
      "aggregate": "AuditLogExport",
      "aggregates": [],
      "file": "domains/audit/export.rs",
      "kind": "change",
      "line": 224,
      "name": "expire",
      "proofs": [],
      "rights": [],
      "uncalled": "its download window ran out; the clock decides, and expiring only takes the file away"
    },
    {
      "aggregate": "AuditLogExport",
      "aggregates": [],
      "file": "domains/audit/export.rs",
      "kind": "change",
      "line": 244,
      "name": "hand_out",
      "proofs": [
        "AuditLogAccess"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ChainVerdict",
      "aggregates": [],
      "file": "domains/audit/verdict.rs",
      "kind": "create",
      "line": 40,
      "name": "of",
      "proofs": [],
      "rights": [],
      "uncalled": "the scheduled sweep keeps what its walk of the chain found; it changes no record and grants nothing"
    },
    {
      "aggregate": "PasskeyCredential",
      "aggregates": [],
      "file": "domains/authentication/credentials/passkey.rs",
      "kind": "create",
      "line": 254,
      "name": "register",
      "proofs": [
        "FactorSetupProof"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "PasskeyCredential",
      "aggregates": [],
      "file": "domains/authentication/credentials/passkey.rs",
      "kind": "change",
      "line": 393,
      "name": "update_sign_count",
      "proofs": [],
      "rights": [],
      "uncalled": "records a use the WebAuthn adapter verified; a counter that does not go up refuses the sign-in"
    },
    {
      "aggregate": "PasskeyCredential",
      "aggregates": [],
      "file": "domains/authentication/credentials/passkey.rs",
      "kind": "change",
      "line": 419,
      "name": "rename",
      "proofs": [
        "AccountKeeper"
      ],
      "rights": [
        "AccountAction::ChangeSignIn"
      ],
      "uncalled": null
    },
    {
      "aggregate": "PasskeyCredential",
      "aggregates": [],
      "file": "domains/authentication/credentials/passkey.rs",
      "kind": "change",
      "line": 440,
      "name": "remove",
      "proofs": [
        "AccountKeeper"
      ],
      "rights": [
        "AccountAction::ChangeSignIn"
      ],
      "uncalled": null
    },
    {
      "aggregate": "PasskeyCeremony",
      "aggregates": [],
      "file": "domains/authentication/credentials/passkey_ceremony.rs",
      "kind": "create",
      "line": 180,
      "name": "open",
      "proofs": [],
      "rights": [],
      "uncalled": "a WebAuthn challenge opened or spent; it proves nothing until its answer is checked"
    },
    {
      "aggregate": "PasskeyCeremony",
      "aggregates": [],
      "file": "domains/authentication/credentials/passkey_ceremony.rs",
      "kind": "create",
      "line": 225,
      "name": "open_discoverable",
      "proofs": [],
      "rights": [],
      "uncalled": "a WebAuthn challenge opened or spent; it proves nothing until its answer is checked"
    },
    {
      "aggregate": "PasskeyCeremony",
      "aggregates": [],
      "file": "domains/authentication/credentials/passkey_ceremony.rs",
      "kind": "change",
      "line": 359,
      "name": "consume",
      "proofs": [],
      "rights": [],
      "uncalled": "a WebAuthn challenge opened or spent; it proves nothing until its answer is checked"
    },
    {
      "aggregate": "TrustedDevice",
      "aggregates": [],
      "file": "domains/authentication/device_trust.rs",
      "kind": "create",
      "line": 285,
      "name": "trust",
      "proofs": [
        "SignedIn"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "TrustedDevice",
      "aggregates": [],
      "file": "domains/authentication/device_trust.rs",
      "kind": "change",
      "line": 439,
      "name": "record_login",
      "proofs": [],
      "rights": [],
      "uncalled": "bookkeeping after a sign-in the authentication context already checked"
    },
    {
      "aggregate": "TrustedDevice",
      "aggregates": [],
      "file": "domains/authentication/device_trust.rs",
      "kind": "change",
      "line": 453,
      "name": "rename",
      "proofs": [
        "AccountKeeper"
      ],
      "rights": [
        "AccountAction::ChangeSignIn"
      ],
      "uncalled": null
    },
    {
      "aggregate": "TrustedDevice",
      "aggregates": [],
      "file": "domains/authentication/device_trust.rs",
      "kind": "change",
      "line": 473,
      "name": "revoke",
      "proofs": [
        "AccountKeeper"
      ],
      "rights": [
        "AccountAction::ChangeSignIn"
      ],
      "uncalled": null
    },
    {
      "aggregate": "DirectoryServiceAccount",
      "aggregates": [],
      "file": "domains/authentication/directory_service/account.rs",
      "kind": "create",
      "line": 134,
      "name": "create",
      "proofs": [
        "DirectoryControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "DirectoryServiceAccount",
      "aggregates": [],
      "file": "domains/authentication/directory_service/account.rs",
      "kind": "change",
      "line": 241,
      "name": "rotate_secret",
      "proofs": [
        "DirectoryControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "DirectoryServiceAccount",
      "aggregates": [],
      "file": "domains/authentication/directory_service/account.rs",
      "kind": "change",
      "line": 270,
      "name": "change_scope",
      "proofs": [
        "DirectoryControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "DirectoryServiceAccount",
      "aggregates": [],
      "file": "domains/authentication/directory_service/account.rs",
      "kind": "change",
      "line": 297,
      "name": "disable",
      "proofs": [
        "DirectoryControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "DirectoryServiceAccount",
      "aggregates": [],
      "file": "domains/authentication/directory_service/account.rs",
      "kind": "change",
      "line": 310,
      "name": "enable",
      "proofs": [
        "DirectoryControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "DirectoryServiceAccount",
      "aggregates": [],
      "file": "domains/authentication/directory_service/account.rs",
      "kind": "change",
      "line": 329,
      "name": "delete",
      "proofs": [
        "DirectoryControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "LdapClientCertificate",
      "aggregates": [],
      "file": "domains/authentication/ldap_certificate.rs",
      "kind": "create",
      "line": 150,
      "name": "issue",
      "proofs": [
        "RecentProof"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "LdapClientCertificate",
      "aggregates": [],
      "file": "domains/authentication/ldap_certificate.rs",
      "kind": "change",
      "line": 301,
      "name": "revoke",
      "proofs": [
        "AccountKeeper"
      ],
      "rights": [
        "AccountAction::ChangeSignIn"
      ],
      "uncalled": null
    },
    {
      "aggregate": "MfaEnrollment",
      "aggregates": [],
      "file": "domains/authentication/mfa/enrollment.rs",
      "kind": "create",
      "line": 93,
      "name": "begin",
      "proofs": [
        "FactorSetupProof"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "MfaEnrollment",
      "aggregates": [],
      "file": "domains/authentication/mfa/enrollment.rs",
      "kind": "change",
      "line": 268,
      "name": "record_failed_attempt",
      "proofs": [],
      "rights": [],
      "uncalled": "counts a wrong answer towards a lock; it only takes away"
    },
    {
      "aggregate": "MfaEnrollment",
      "aggregates": [],
      "file": "domains/authentication/mfa/enrollment.rs",
      "kind": "change",
      "line": 323,
      "name": "answer",
      "proofs": [],
      "rights": [],
      "uncalled": "a one-time code being checked and spent; the code is the proof"
    },
    {
      "aggregate": "MfaEnrollment",
      "aggregates": [],
      "file": "domains/authentication/mfa/enrollment.rs",
      "kind": "change",
      "line": 375,
      "name": "verify",
      "proofs": [
        "AnsweredCode"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "MfaEnrollment",
      "aggregates": [],
      "file": "domains/authentication/mfa/enrollment.rs",
      "kind": "change",
      "line": 407,
      "name": "turn_off_with_code",
      "proofs": [
        "AnsweredCode"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "MfaEnrollment",
      "aggregates": [],
      "file": "domains/authentication/mfa/enrollment.rs",
      "kind": "change",
      "line": 431,
      "name": "reset_by_admin",
      "proofs": [
        "AccountControlCheck"
      ],
      "rights": [
        "AccountAction::ChangeSignIn"
      ],
      "uncalled": null
    },
    {
      "aggregate": "MfaEnrollment",
      "aggregates": [],
      "file": "domains/authentication/mfa/enrollment.rs",
      "kind": "change",
      "line": 457,
      "name": "abandon",
      "proofs": [
        "FactorSetupProof"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "MfaEnrollment",
      "aggregates": [],
      "file": "domains/authentication/mfa/enrollment.rs",
      "kind": "change",
      "line": 477,
      "name": "withdraw",
      "proofs": [
        "FactorWithdrawal"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OneTimeCode",
      "aggregates": [
        "MfaEnrollment"
      ],
      "file": "domains/authentication/mfa/one_time_code.rs",
      "kind": "create",
      "line": 112,
      "name": "issue",
      "proofs": [],
      "rights": [],
      "uncalled": "a code sent to the factor's own address or number; only its holder reads it, and sending grants nothing"
    },
    {
      "aggregate": "OneTimeCode",
      "aggregates": [],
      "file": "domains/authentication/mfa/one_time_code.rs",
      "kind": "change",
      "line": 282,
      "name": "redeem",
      "proofs": [],
      "rights": [],
      "uncalled": "a one-time code being checked and spent; the code is the proof"
    },
    {
      "aggregate": "RecoveryCodeSet",
      "aggregates": [],
      "file": "domains/authentication/recovery/codes.rs",
      "kind": "create",
      "line": 175,
      "name": "generate",
      "proofs": [
        "AnsweredCode"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "RecoveryCodeSet",
      "aggregates": [
        "MfaEnrollment"
      ],
      "file": "domains/authentication/recovery/codes.rs",
      "kind": "change",
      "line": 222,
      "name": "regenerate",
      "proofs": [
        "FactorSetupProof"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "RecoveryCodeSet",
      "aggregates": [],
      "file": "domains/authentication/recovery/codes.rs",
      "kind": "change",
      "line": 342,
      "name": "redeem",
      "proofs": [],
      "rights": [],
      "uncalled": "a one-time code being checked and spent; the code is the proof"
    },
    {
      "aggregate": "PasswordResetRequest",
      "aggregates": [
        "User"
      ],
      "file": "domains/authentication/recovery/reset.rs",
      "kind": "create",
      "line": 228,
      "name": "create",
      "proofs": [],
      "rights": [],
      "uncalled": "a link mailed to the account's own address; anyone may ask, only that mailbox can use it"
    },
    {
      "aggregate": "PasswordResetRequest",
      "aggregates": [
        "User"
      ],
      "file": "domains/authentication/recovery/reset.rs",
      "kind": "create",
      "line": 261,
      "name": "in_sign_in",
      "proofs": [],
      "rights": [],
      "uncalled": "begun by the password sign-in that just proved the account's current password; its token goes back to that sign-in or to the account's own mailbox, and sets nothing until it is spent"
    },
    {
      "aggregate": "PasswordResetRequest",
      "aggregates": [
        "User"
      ],
      "file": "domains/authentication/recovery/reset.rs",
      "kind": "change",
      "line": 459,
      "name": "complete",
      "proofs": [],
      "rights": [],
      "uncalled": "an emailed link being followed; holding that mailbox is the proof"
    },
    {
      "aggregate": "PasswordResetRequest",
      "aggregates": [
        "User"
      ],
      "file": "domains/authentication/recovery/reset.rs",
      "kind": "change",
      "line": 482,
      "name": "complete_in_sign_in",
      "proofs": [],
      "rights": [],
      "uncalled": "the sign-in's own change token being spent, beside the factor code or mailbox its change proof asks for; holding the token is the proof"
    },
    {
      "aggregate": "SessionHandoff",
      "aggregates": [
        "Session"
      ],
      "file": "domains/authentication/sessions/handoff.rs",
      "kind": "create",
      "line": 115,
      "name": "issue",
      "proofs": [],
      "rights": [],
      "uncalled": "a short-lived code issued for a live session its own cookie presented, bound to the browser that asked"
    },
    {
      "aggregate": "SessionHandoff",
      "aggregates": [],
      "file": "domains/authentication/sessions/handoff.rs",
      "kind": "change",
      "line": 242,
      "name": "redeem",
      "proofs": [],
      "rights": [],
      "uncalled": "a one-time code being checked and spent in the browser it was bound to; the code and that browser's value are the proof"
    },
    {
      "aggregate": "MfaChallenge",
      "aggregates": [
        "Session"
      ],
      "file": "domains/authentication/sessions/mfa_challenge.rs",
      "kind": "create",
      "line": 66,
      "name": "issue",
      "proofs": [],
      "rights": [],
      "uncalled": "a short-lived code issued for a session a sign-in just opened and checked"
    },
    {
      "aggregate": "MfaChallenge",
      "aggregates": [],
      "file": "domains/authentication/sessions/mfa_challenge.rs",
      "kind": "change",
      "line": 172,
      "name": "consume",
      "proofs": [],
      "rights": [],
      "uncalled": "a one-time code being checked and spent; the code is the proof"
    },
    {
      "aggregate": "MfaChallenge",
      "aggregates": [],
      "file": "domains/authentication/sessions/mfa_challenge.rs",
      "kind": "change",
      "line": 187,
      "name": "record_failure",
      "proofs": [],
      "rights": [],
      "uncalled": "counts a wrong answer towards a lock; it only takes away"
    },
    {
      "aggregate": "Session",
      "aggregates": [
        "User"
      ],
      "file": "domains/authentication/sessions/session/kept_through.rs",
      "kind": "change",
      "line": 39,
      "name": "keep_through_own_password_change",
      "proofs": [
        "RecentProof"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Session",
      "aggregates": [
        "User"
      ],
      "file": "domains/authentication/sessions/session/kept_through.rs",
      "kind": "change",
      "line": 68,
      "name": "keep_through_own_removal",
      "proofs": [
        "SignedIn"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Session",
      "aggregates": [
        "User"
      ],
      "file": "domains/authentication/sessions/session/kept_through.rs",
      "kind": "change",
      "line": 100,
      "name": "keep_through_own_factor_addition",
      "proofs": [
        "ProvedFactor"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Session",
      "aggregates": [],
      "file": "domains/authentication/sessions/session/mod.rs",
      "kind": "create",
      "line": 190,
      "name": "create",
      "proofs": [
        "MaySignIn"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Session",
      "aggregates": [
        "TrustedDevice"
      ],
      "file": "domains/authentication/sessions/session/mod.rs",
      "kind": "change",
      "line": 333,
      "name": "record_signed_in_from",
      "proofs": [],
      "rights": [],
      "uncalled": "names the remembered device whose secret the sign-in just presented and matched; it is held to the device being the holder's own and trusted, and grants nothing"
    },
    {
      "aggregate": "Session",
      "aggregates": [],
      "file": "domains/authentication/sessions/session/mod.rs",
      "kind": "change",
      "line": 512,
      "name": "revoke",
      "proofs": [
        "AccountKeeper"
      ],
      "rights": [
        "AccountAction::ShutOut"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Session",
      "aggregates": [],
      "file": "domains/authentication/sessions/session/mod.rs",
      "kind": "change",
      "line": 541,
      "name": "sign_out",
      "proofs": [],
      "rights": [],
      "uncalled": "ended by whoever presents its own refresh token; ending a session only takes away"
    },
    {
      "aggregate": "Session",
      "aggregates": [
        "User"
      ],
      "file": "domains/authentication/sessions/session/mod.rs",
      "kind": "change",
      "line": 569,
      "name": "end_with_account",
      "proofs": [],
      "rights": [],
      "uncalled": "follows the holder's account being locked, switched off or closed by someone checked when they moved it; the shut-out account is the proof, and ending a session only takes away"
    },
    {
      "aggregate": "Session",
      "aggregates": [],
      "file": "domains/authentication/sessions/session/mod.rs",
      "kind": "change",
      "line": 598,
      "name": "bind_to_app",
      "proofs": [],
      "rights": [],
      "uncalled": "bookkeeping after a sign-in the authentication context already checked"
    },
    {
      "aggregate": "Session",
      "aggregates": [
        "User"
      ],
      "file": "domains/authentication/sessions/session/mod.rs",
      "kind": "change",
      "line": 630,
      "name": "answer",
      "proofs": [
        "ProvedFactor"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Session",
      "aggregates": [],
      "file": "domains/authentication/sessions/session/records.rs",
      "kind": "change",
      "line": 25,
      "name": "record_token_theft",
      "proofs": [],
      "rights": [],
      "uncalled": "raises the theft record for a retired session whose swapped token came back; nothing stored changes, the platform ends every session of its holder"
    },
    {
      "aggregate": "Session",
      "aggregates": [],
      "file": "domains/authentication/sessions/session/records.rs",
      "kind": "change",
      "line": 67,
      "name": "record_sign_in",
      "proofs": [],
      "rights": [],
      "uncalled": "raises the sign-in record only, once the session it opened is kept; nothing stored changes"
    },
    {
      "aggregate": "Session",
      "aggregates": [],
      "file": "domains/authentication/sessions/session/records.rs",
      "kind": "change",
      "line": 83,
      "name": "record_app_token",
      "proofs": [],
      "rights": [],
      "uncalled": "raises the record of a token issued under a live session the app sign-in already checked; nothing stored changes"
    },
    {
      "aggregate": "Session",
      "aggregates": [],
      "file": "domains/authentication/sessions/session/records.rs",
      "kind": "change",
      "line": 104,
      "name": "record_factor_verified",
      "proofs": [],
      "rights": [],
      "uncalled": "raises the record of a factor the session already took; nothing stored changes"
    },
    {
      "aggregate": "Session",
      "aggregates": [],
      "file": "domains/authentication/sessions/session/rotation.rs",
      "kind": "create",
      "line": 48,
      "name": "rotate",
      "proofs": [
        "SessionCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Session",
      "aggregates": [],
      "file": "domains/authentication/sessions/session/rotation.rs",
      "kind": "create",
      "line": 92,
      "name": "hand_over",
      "proofs": [
        "SessionCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Session",
      "aggregates": [],
      "file": "domains/authentication/sessions/session/suspension.rs",
      "kind": "change",
      "line": 28,
      "name": "suspend",
      "proofs": [],
      "rights": [],
      "uncalled": "frozen on a risk or binding signal the platform raised; it only takes away until the holder proves a factor again"
    },
    {
      "aggregate": "Session",
      "aggregates": [],
      "file": "domains/authentication/sessions/session/suspension.rs",
      "kind": "change",
      "line": 68,
      "name": "resume",
      "proofs": [
        "ProvedFactor"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "SignInCode",
      "aggregates": [
        "Session"
      ],
      "file": "domains/authentication/sessions/sign_in_code.rs",
      "kind": "create",
      "line": 78,
      "name": "issue",
      "proofs": [],
      "rights": [],
      "uncalled": "a short-lived code issued for a session a sign-in just opened and checked"
    },
    {
      "aggregate": "SignInCode",
      "aggregates": [],
      "file": "domains/authentication/sessions/sign_in_code.rs",
      "kind": "change",
      "line": 175,
      "name": "redeem",
      "proofs": [],
      "rights": [],
      "uncalled": "a one-time code being checked and spent; the code is the proof"
    },
    {
      "aggregate": "AccessRequest",
      "aggregates": [],
      "file": "domains/authorization/access_request.rs",
      "kind": "create",
      "line": 313,
      "name": "request",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AccessRequest",
      "aggregates": [],
      "file": "domains/authorization/access_request.rs",
      "kind": "change",
      "line": 450,
      "name": "approve",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AccessRequest",
      "aggregates": [],
      "file": "domains/authorization/access_request.rs",
      "kind": "change",
      "line": 490,
      "name": "deny",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AccessRequest",
      "aggregates": [],
      "file": "domains/authorization/access_request.rs",
      "kind": "change",
      "line": 520,
      "name": "cancel",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AccessRequest",
      "aggregates": [],
      "file": "domains/authorization/access_request.rs",
      "kind": "change",
      "line": 543,
      "name": "expire",
      "proofs": [],
      "rights": [],
      "uncalled": "nobody answered it in time; the clock decides, and it grants nothing"
    },
    {
      "aggregate": "AccessReview",
      "aggregates": [],
      "file": "domains/authorization/access_review.rs",
      "kind": "create",
      "line": 237,
      "name": "start",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AccessReview",
      "aggregates": [],
      "file": "domains/authorization/access_review.rs",
      "kind": "change",
      "line": 371,
      "name": "decide",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AccessReview",
      "aggregates": [],
      "file": "domains/authorization/access_review.rs",
      "kind": "change",
      "line": 428,
      "name": "complete",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AccessReview",
      "aggregates": [],
      "file": "domains/authorization/access_review.rs",
      "kind": "change",
      "line": 462,
      "name": "complete_overdue",
      "proofs": [],
      "rights": [],
      "uncalled": "its due date has passed; the clock decides, and the reviewers' choices and the rule it was started with say who loses access"
    },
    {
      "aggregate": "AccessReview",
      "aggregates": [],
      "file": "domains/authorization/access_review.rs",
      "kind": "change",
      "line": 491,
      "name": "cancel",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "BreakGlassPolicy",
      "aggregates": [],
      "file": "domains/authorization/break_glass.rs",
      "kind": "create",
      "line": 190,
      "name": "off",
      "proofs": [],
      "rights": [],
      "uncalled": "the policy every tenant starts with; it lets nobody give themselves anything"
    },
    {
      "aggregate": "BreakGlassPolicy",
      "aggregates": [],
      "file": "domains/authorization/break_glass.rs",
      "kind": "change",
      "line": 255,
      "name": "change_self_service",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "BreakGlassGrant",
      "aggregates": [
        "BreakGlassPolicy"
      ],
      "file": "domains/authorization/break_glass.rs",
      "kind": "create",
      "line": 369,
      "name": "create",
      "proofs": [
        "NewBreakGlass"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "BreakGlassGrant",
      "aggregates": [],
      "file": "domains/authorization/break_glass.rs",
      "kind": "change",
      "line": 511,
      "name": "revoke",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ClearanceRules",
      "aggregates": [],
      "file": "domains/authorization/clearance.rs",
      "kind": "create",
      "line": 91,
      "name": "none",
      "proofs": [],
      "rights": [],
      "uncalled": "the rules every tenant starts with; no app permission clears for anything"
    },
    {
      "aggregate": "ClearanceRules",
      "aggregates": [],
      "file": "domains/authorization/clearance.rs",
      "kind": "change",
      "line": 150,
      "name": "add_rule",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ClearanceRules",
      "aggregates": [],
      "file": "domains/authorization/clearance.rs",
      "kind": "change",
      "line": 184,
      "name": "change_rule",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ClearanceRules",
      "aggregates": [],
      "file": "domains/authorization/clearance.rs",
      "kind": "change",
      "line": 213,
      "name": "remove_rule",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "GroupMembership",
      "aggregates": [
        "Group"
      ],
      "file": "domains/authorization/group/membership.rs",
      "kind": "create",
      "line": 89,
      "name": "join_until",
      "proofs": [
        "HeldByGranter"
      ],
      "rights": [
        "RoleAction::Assign",
        "SystemPermission::Roles"
      ],
      "uncalled": null
    },
    {
      "aggregate": "GroupMembership",
      "aggregates": [
        "AccessRequest",
        "Group"
      ],
      "file": "domains/authorization/group/membership.rs",
      "kind": "create",
      "line": 113,
      "name": "from_approved_request",
      "proofs": [],
      "rights": [],
      "uncalled": "follows an access request being approved, which checked the approver for the right and what the group brings"
    },
    {
      "aggregate": "GroupMembership",
      "aggregates": [
        "Group"
      ],
      "file": "domains/authorization/group/membership.rs",
      "kind": "create",
      "line": 149,
      "name": "from_directory",
      "proofs": [
        "TenantDirectory"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "GroupMembership",
      "aggregates": [
        "Group"
      ],
      "file": "domains/authorization/group/membership.rs",
      "kind": "change",
      "line": 220,
      "name": "lapse",
      "proofs": [],
      "rights": [],
      "uncalled": "its end has passed; the clock decides, and sweeping it only takes away"
    },
    {
      "aggregate": "GroupMembership",
      "aggregates": [
        "Group"
      ],
      "file": "domains/authorization/group/membership.rs",
      "kind": "change",
      "line": 266,
      "name": "end",
      "proofs": [
        "HeldByGranter"
      ],
      "rights": [
        "RoleAction::Assign",
        "SystemPermission::Roles"
      ],
      "uncalled": null
    },
    {
      "aggregate": "GroupMembership",
      "aggregates": [
        "Group"
      ],
      "file": "domains/authorization/group/membership.rs",
      "kind": "change",
      "line": 299,
      "name": "end_by_directory",
      "proofs": [
        "TenantDirectory"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "GroupMembership",
      "aggregates": [
        "Group"
      ],
      "file": "domains/authorization/group/membership.rs",
      "kind": "change",
      "line": 325,
      "name": "withdraw_by_review",
      "proofs": [],
      "rights": [],
      "uncalled": "follows an overdue review being completed; only that review's own removals name the member, and it only takes away"
    },
    {
      "aggregate": "Group",
      "aggregates": [],
      "file": "domains/authorization/group/mod.rs",
      "kind": "create",
      "line": 177,
      "name": "create",
      "proofs": [
        "HeldByGranter"
      ],
      "rights": [
        "RoleAction::Create",
        "SystemPermission::Roles"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Group",
      "aggregates": [],
      "file": "domains/authorization/group/mod.rs",
      "kind": "create",
      "line": 202,
      "name": "from_directory",
      "proofs": [
        "TenantDirectory"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Group",
      "aggregates": [],
      "file": "domains/authorization/group/mod.rs",
      "kind": "change",
      "line": 335,
      "name": "rename",
      "proofs": [
        "HeldByGranter"
      ],
      "rights": [
        "RoleAction::Update",
        "SystemPermission::Roles"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Group",
      "aggregates": [],
      "file": "domains/authorization/group/mod.rs",
      "kind": "change",
      "line": 369,
      "name": "move_under",
      "proofs": [
        "HeldByGranter"
      ],
      "rights": [
        "RoleAction::Update",
        "SystemPermission::Roles"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Group",
      "aggregates": [
        "Role"
      ],
      "file": "domains/authorization/group/mod.rs",
      "kind": "change",
      "line": 408,
      "name": "assign_role",
      "proofs": [
        "HeldByGranter"
      ],
      "rights": [
        "RoleAction::Assign",
        "SystemPermission::Roles"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Group",
      "aggregates": [
        "Role"
      ],
      "file": "domains/authorization/group/mod.rs",
      "kind": "change",
      "line": 440,
      "name": "unassign_role",
      "proofs": [
        "HeldByGranter"
      ],
      "rights": [
        "RoleAction::Assign",
        "SystemPermission::Roles"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Group",
      "aggregates": [],
      "file": "domains/authorization/group/mod.rs",
      "kind": "change",
      "line": 476,
      "name": "delete",
      "proofs": [
        "HeldByGranter"
      ],
      "rights": [
        "RoleAction::Delete",
        "SystemPermission::Roles"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Group",
      "aggregates": [],
      "file": "domains/authorization/group/mod.rs",
      "kind": "change",
      "line": 507,
      "name": "rename_by_directory",
      "proofs": [
        "TenantDirectory"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Group",
      "aggregates": [],
      "file": "domains/authorization/group/mod.rs",
      "kind": "change",
      "line": 534,
      "name": "delete_by_directory",
      "proofs": [
        "TenantDirectory"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "PolicySet",
      "aggregates": [],
      "file": "domains/authorization/policy/set.rs",
      "kind": "change",
      "line": 269,
      "name": "add_rule",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "PolicySet",
      "aggregates": [],
      "file": "domains/authorization/policy/set.rs",
      "kind": "change",
      "line": 294,
      "name": "remove_rule",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "PolicySet",
      "aggregates": [],
      "file": "domains/authorization/policy/set.rs",
      "kind": "change",
      "line": 322,
      "name": "switch_rule",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "PolicySet",
      "aggregates": [],
      "file": "domains/authorization/policy/set.rs",
      "kind": "change",
      "line": 351,
      "name": "change_rule",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "PolicySet",
      "aggregates": [],
      "file": "domains/authorization/policy/set.rs",
      "kind": "change",
      "line": 378,
      "name": "reorder_rules",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "PolicySet",
      "aggregates": [],
      "file": "domains/authorization/policy/set.rs",
      "kind": "create",
      "line": 407,
      "name": "start_draft",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [
        "PolicySetAction::Update",
        "SystemPermission::PolicySet"
      ],
      "uncalled": null
    },
    {
      "aggregate": "PolicySet",
      "aggregates": [],
      "file": "domains/authorization/policy/set.rs",
      "kind": "change",
      "line": 443,
      "name": "change_default_action",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "PolicySet",
      "aggregates": [],
      "file": "domains/authorization/policy/set.rs",
      "kind": "change",
      "line": 481,
      "name": "submit_for_review",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [
        "PolicySetAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "PolicySet",
      "aggregates": [],
      "file": "domains/authorization/policy/set.rs",
      "kind": "change",
      "line": 511,
      "name": "activate",
      "proofs": [
        "PolicyApprover"
      ],
      "rights": [
        "PolicySetAction::Activate",
        "SystemPermission::PolicySet"
      ],
      "uncalled": null
    },
    {
      "aggregate": "PolicySet",
      "aggregates": [],
      "file": "domains/authorization/policy/set.rs",
      "kind": "change",
      "line": 563,
      "name": "reject",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [
        "PolicySetAction::Activate"
      ],
      "uncalled": null
    },
    {
      "aggregate": "PolicySet",
      "aggregates": [],
      "file": "domains/authorization/policy/set.rs",
      "kind": "change",
      "line": 583,
      "name": "archive",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [
        "PolicySetAction::Activate",
        "PolicySetAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "PolicySet",
      "aggregates": [],
      "file": "domains/authorization/policy/set.rs",
      "kind": "change",
      "line": 611,
      "name": "simulate",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [
        "PolicySetAction::View",
        "SystemPermission::PolicySet"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Relationship",
      "aggregates": [
        "ResourceType"
      ],
      "file": "domains/authorization/relationship.rs",
      "kind": "create",
      "line": 190,
      "name": "write",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Relationship",
      "aggregates": [
        "ResourceType"
      ],
      "file": "domains/authorization/relationship.rs",
      "kind": "change",
      "line": 224,
      "name": "remove",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AccessRequestPolicy",
      "aggregates": [],
      "file": "domains/authorization/request_policy.rs",
      "kind": "create",
      "line": 50,
      "name": "widest",
      "proofs": [],
      "rights": [],
      "uncalled": "the limit every tenant starts with; it lets nobody ask for longer than anyone may"
    },
    {
      "aggregate": "AccessRequestPolicy",
      "aggregates": [],
      "file": "domains/authorization/request_policy.rs",
      "kind": "change",
      "line": 103,
      "name": "change_limits",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ResourceType",
      "aggregates": [],
      "file": "domains/authorization/resource_type/mod.rs",
      "kind": "create",
      "line": 190,
      "name": "create",
      "proofs": [
        "HeldByGranter"
      ],
      "rights": [
        "RoleAction::Create",
        "SystemPermission::Roles"
      ],
      "uncalled": null
    },
    {
      "aggregate": "ResourceType",
      "aggregates": [],
      "file": "domains/authorization/resource_type/mod.rs",
      "kind": "change",
      "line": 376,
      "name": "update",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ResourceType",
      "aggregates": [],
      "file": "domains/authorization/resource_type/mod.rs",
      "kind": "change",
      "line": 517,
      "name": "delete",
      "proofs": [
        "HeldByGranter"
      ],
      "rights": [
        "RoleAction::Delete",
        "SystemPermission::Roles"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Role",
      "aggregates": [],
      "file": "domains/authorization/role/mod.rs",
      "kind": "create",
      "line": 132,
      "name": "create",
      "proofs": [
        "HeldByGranter"
      ],
      "rights": [
        "RoleAction::Create",
        "SystemPermission::Roles"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Role",
      "aggregates": [],
      "file": "domains/authorization/role/mod.rs",
      "kind": "change",
      "line": 329,
      "name": "rename",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [
        "RoleAction::Update",
        "SystemPermission::Roles"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Role",
      "aggregates": [],
      "file": "domains/authorization/role/mod.rs",
      "kind": "change",
      "line": 358,
      "name": "change_default_assignment",
      "proofs": [
        "HeldByGranter"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Role",
      "aggregates": [],
      "file": "domains/authorization/role/mod.rs",
      "kind": "change",
      "line": 393,
      "name": "delete",
      "proofs": [
        "HeldByGranter"
      ],
      "rights": [
        "RoleAction::Delete",
        "SystemPermission::Roles"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Role",
      "aggregates": [],
      "file": "domains/authorization/role/permission_moves.rs",
      "kind": "change",
      "line": 52,
      "name": "change_permissions",
      "proofs": [
        "HeldByGranter"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Role",
      "aggregates": [],
      "file": "domains/authorization/role/starting.rs",
      "kind": "create",
      "line": 74,
      "name": "starting",
      "proofs": [
        "StartingRolesGrant"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "RoleAssignment",
      "aggregates": [
        "Role"
      ],
      "file": "domains/authorization/role_assignment.rs",
      "kind": "create",
      "line": 103,
      "name": "create",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "RoleAssignment",
      "aggregates": [
        "Role"
      ],
      "file": "domains/authorization/role_assignment.rs",
      "kind": "create",
      "line": 129,
      "name": "assign_until",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "RoleAssignment",
      "aggregates": [
        "AccessRequest",
        "Role"
      ],
      "file": "domains/authorization/role_assignment.rs",
      "kind": "create",
      "line": 153,
      "name": "from_approved_request",
      "proofs": [],
      "rights": [],
      "uncalled": "follows an access request being approved, which checked the approver for the right and the role"
    },
    {
      "aggregate": "RoleAssignment",
      "aggregates": [
        "Role"
      ],
      "file": "domains/authorization/role_assignment.rs",
      "kind": "create",
      "line": 173,
      "name": "by_default",
      "proofs": [],
      "rights": [],
      "uncalled": "follows an account being opened; whoever made the role a default was checked for all it grants"
    },
    {
      "aggregate": "RoleAssignment",
      "aggregates": [
        "Invitation",
        "Role",
        "User"
      ],
      "file": "domains/authorization/role_assignment.rs",
      "kind": "create",
      "line": 274,
      "name": "from_accepted_invitation",
      "proofs": [],
      "rights": [],
      "uncalled": "follows an invitation being accepted, which checked the role against what the inviter holds now"
    },
    {
      "aggregate": "RoleAssignment",
      "aggregates": [
        "Role"
      ],
      "file": "domains/authorization/role_assignment.rs",
      "kind": "change",
      "line": 353,
      "name": "revoke",
      "proofs": [
        "HeldByGranter"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "RoleAssignment",
      "aggregates": [
        "Role"
      ],
      "file": "domains/authorization/role_assignment.rs",
      "kind": "change",
      "line": 380,
      "name": "withdraw_by_review",
      "proofs": [],
      "rights": [],
      "uncalled": "follows an overdue review being completed; only that review's own removals name the holder, and it only takes away"
    },
    {
      "aggregate": "RoleAssignment",
      "aggregates": [
        "Role"
      ],
      "file": "domains/authorization/role_assignment.rs",
      "kind": "change",
      "line": 417,
      "name": "lapse",
      "proofs": [],
      "rights": [],
      "uncalled": "its end has passed; the clock decides, and sweeping it only takes away"
    },
    {
      "aggregate": "SeparationRule",
      "aggregates": [
        "Role"
      ],
      "file": "domains/authorization/separation.rs",
      "kind": "create",
      "line": 68,
      "name": "declare",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "SeparationRule",
      "aggregates": [],
      "file": "domains/authorization/separation.rs",
      "kind": "change",
      "line": 106,
      "name": "lift",
      "proofs": [
        "TenantAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "TenantBranding",
      "aggregates": [],
      "file": "domains/branding/config.rs",
      "kind": "create",
      "line": 93,
      "name": "default_branding",
      "proofs": [],
      "rights": [],
      "uncalled": "made once by the platform as it provisions the tenant; it shows only the platform's own look"
    },
    {
      "aggregate": "TenantBranding",
      "aggregates": [],
      "file": "domains/branding/config.rs",
      "kind": "change",
      "line": 184,
      "name": "change_logo",
      "proofs": [
        "BrandingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "TenantBranding",
      "aggregates": [],
      "file": "domains/branding/config.rs",
      "kind": "change",
      "line": 206,
      "name": "upload_logo",
      "proofs": [
        "BrandingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "TenantBranding",
      "aggregates": [],
      "file": "domains/branding/config.rs",
      "kind": "change",
      "line": 228,
      "name": "change_primary_color",
      "proofs": [
        "BrandingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "TenantBranding",
      "aggregates": [],
      "file": "domains/branding/config.rs",
      "kind": "change",
      "line": 247,
      "name": "change_background_color",
      "proofs": [
        "BrandingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "TenantBranding",
      "aggregates": [],
      "file": "domains/branding/config.rs",
      "kind": "change",
      "line": 266,
      "name": "change_custom_css",
      "proofs": [
        "BrandingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "TenantBranding",
      "aggregates": [],
      "file": "domains/branding/config.rs",
      "kind": "change",
      "line": 284,
      "name": "change_sender_name",
      "proofs": [
        "BrandingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "TenantBranding",
      "aggregates": [
        "RegisteredDomain"
      ],
      "file": "domains/branding/config.rs",
      "kind": "change",
      "line": 308,
      "name": "send_from",
      "proofs": [
        "BrandingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "TenantBranding",
      "aggregates": [],
      "file": "domains/branding/config.rs",
      "kind": "change",
      "line": 340,
      "name": "send_from_platform",
      "proofs": [
        "BrandingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "EmailTemplate",
      "aggregates": [],
      "file": "domains/branding/email_template.rs",
      "kind": "create",
      "line": 436,
      "name": "custom",
      "proofs": [
        "BrandingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "EmailTemplate",
      "aggregates": [],
      "file": "domains/branding/email_template.rs",
      "kind": "change",
      "line": 556,
      "name": "remove",
      "proofs": [
        "BrandingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "TenantMailProvider",
      "aggregates": [],
      "file": "domains/branding/mail_provider.rs",
      "kind": "create",
      "line": 329,
      "name": "platform_mail",
      "proofs": [],
      "rights": [],
      "uncalled": "made once by the platform as it provisions the tenant; it sends through the platform's own mail as before"
    },
    {
      "aggregate": "TenantMailProvider",
      "aggregates": [],
      "file": "domains/branding/mail_provider.rs",
      "kind": "change",
      "line": 412,
      "name": "switch_to",
      "proofs": [
        "BrandingControl",
        "RecentProof"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "TenantMailProvider",
      "aggregates": [],
      "file": "domains/branding/mail_provider.rs",
      "kind": "change",
      "line": 442,
      "name": "record_test_send",
      "proofs": [],
      "rights": [],
      "uncalled": "records how a send the worker made went; it only counts failures or clears them"
    },
    {
      "aggregate": "Consumer",
      "aggregates": [],
      "file": "domains/consumers/consumer.rs",
      "kind": "create",
      "line": 138,
      "name": "create",
      "proofs": [
        "ConsumerControl"
      ],
      "rights": [
        "ConsumersAction::Create"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Consumer",
      "aggregates": [],
      "file": "domains/consumers/consumer.rs",
      "kind": "change",
      "line": 291,
      "name": "change_clearance",
      "proofs": [
        "ConsumerControl"
      ],
      "rights": [
        "ConsumersAction::Manage"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Consumer",
      "aggregates": [],
      "file": "domains/consumers/consumer.rs",
      "kind": "change",
      "line": 327,
      "name": "disable",
      "proofs": [
        "ConsumerControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Consumer",
      "aggregates": [],
      "file": "domains/consumers/consumer.rs",
      "kind": "change",
      "line": 344,
      "name": "enable",
      "proofs": [
        "ConsumerControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Consumer",
      "aggregates": [],
      "file": "domains/consumers/consumer.rs",
      "kind": "change",
      "line": 382,
      "name": "rotate_credential",
      "proofs": [
        "ConsumerTakeover"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Consumer",
      "aggregates": [],
      "file": "domains/consumers/consumer.rs",
      "kind": "change",
      "line": 414,
      "name": "end_credential_overlap",
      "proofs": [
        "ConsumerControl"
      ],
      "rights": [
        "ConsumersAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Consumer",
      "aggregates": [],
      "file": "domains/consumers/consumer.rs",
      "kind": "change",
      "line": 442,
      "name": "change_credential_expiry",
      "proofs": [
        "ConsumerControl"
      ],
      "rights": [
        "ConsumersAction::Manage"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Consumer",
      "aggregates": [],
      "file": "domains/consumers/consumer.rs",
      "kind": "change",
      "line": 471,
      "name": "change_quota",
      "proofs": [
        "ConsumerControl"
      ],
      "rights": [
        "ConsumersAction::Manage"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Consumer",
      "aggregates": [],
      "file": "domains/consumers/consumer.rs",
      "kind": "change",
      "line": 499,
      "name": "rename",
      "proofs": [
        "ConsumerControl"
      ],
      "rights": [
        "ConsumersAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Consumer",
      "aggregates": [],
      "file": "domains/consumers/consumer.rs",
      "kind": "change",
      "line": 524,
      "name": "change_description",
      "proofs": [
        "ConsumerControl"
      ],
      "rights": [
        "ConsumersAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Consumer",
      "aggregates": [],
      "file": "domains/consumers/consumer.rs",
      "kind": "change",
      "line": 561,
      "name": "delete",
      "proofs": [
        "ConsumerControl"
      ],
      "rights": [
        "ConsumersAction::Delete"
      ],
      "uncalled": null
    },
    {
      "aggregate": "AlgorithmMigration",
      "aggregates": [
        "SigningKey"
      ],
      "file": "domains/crypto/algorithm_migration.rs",
      "kind": "create",
      "line": 159,
      "name": "plan",
      "proofs": [
        "CryptoControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AlgorithmMigration",
      "aggregates": [
        "SigningKey"
      ],
      "file": "domains/crypto/algorithm_migration.rs",
      "kind": "change",
      "line": 293,
      "name": "start",
      "proofs": [
        "CryptoControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AlgorithmMigration",
      "aggregates": [],
      "file": "domains/crypto/algorithm_migration.rs",
      "kind": "change",
      "line": 329,
      "name": "promote",
      "proofs": [
        "CryptoControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AlgorithmMigration",
      "aggregates": [],
      "file": "domains/crypto/algorithm_migration.rs",
      "kind": "change",
      "line": 350,
      "name": "complete",
      "proofs": [
        "CryptoControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AlgorithmMigration",
      "aggregates": [],
      "file": "domains/crypto/algorithm_migration.rs",
      "kind": "change",
      "line": 372,
      "name": "rollback",
      "proofs": [
        "CryptoControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AlgorithmMigration",
      "aggregates": [],
      "file": "domains/crypto/algorithm_migration.rs",
      "kind": "change",
      "line": 398,
      "name": "cancel",
      "proofs": [
        "CryptoControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AssertionKey",
      "aggregates": [],
      "file": "domains/crypto/assertion_key.rs",
      "kind": "create",
      "line": 110,
      "name": "create",
      "proofs": [],
      "rights": [],
      "uncalled": "the platform makes a tenant's assertion keys at its setup and on its rotation schedule; no person makes or changes one"
    },
    {
      "aggregate": "SigningKey",
      "aggregates": [],
      "file": "domains/crypto/signing_key.rs",
      "kind": "create",
      "line": 127,
      "name": "create",
      "proofs": [],
      "rights": [],
      "uncalled": "a new key signs nothing until a key set takes it, which needs the crypto right; the first is made at provisioning"
    },
    {
      "aggregate": "VerifyingKey",
      "aggregates": [
        "SigningKey"
      ],
      "file": "domains/crypto/verifying_key.rs",
      "kind": "create",
      "line": 69,
      "name": "of",
      "proofs": [],
      "rights": [],
      "uncalled": "the public half read off a signing key as it stands; it copies what the key holds, changes nothing and grants nothing"
    },
    {
      "aggregate": "ClassificationRuleSet",
      "aggregates": [],
      "file": "domains/data_classification/classification.rs",
      "kind": "create",
      "line": 149,
      "name": "empty",
      "proofs": [
        "ClassificationControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ClassificationRuleSet",
      "aggregates": [],
      "file": "domains/data_classification/classification.rs",
      "kind": "change",
      "line": 246,
      "name": "add_rule",
      "proofs": [
        "ClassificationControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ClassificationRuleSet",
      "aggregates": [],
      "file": "domains/data_classification/classification.rs",
      "kind": "change",
      "line": 287,
      "name": "remove_rule",
      "proofs": [
        "ClassificationControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ClassificationRuleSet",
      "aggregates": [],
      "file": "domains/data_classification/classification.rs",
      "kind": "change",
      "line": 320,
      "name": "change_rule",
      "proofs": [
        "ClassificationControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "MappedHoldings",
      "aggregates": [],
      "file": "domains/federation/connection/mapped_holdings.rs",
      "kind": "create",
      "line": 51,
      "name": "none",
      "proofs": [],
      "rights": [],
      "uncalled": "an empty record of what a mapping gave, before a person's first sign-in through it; it grants nothing"
    },
    {
      "aggregate": "FederatedIdpConnection",
      "aggregates": [
        "Role"
      ],
      "file": "domains/federation/connection/provisioning.rs",
      "kind": "change",
      "line": 42,
      "name": "provision_new_accounts",
      "proofs": [
        "FederationControl"
      ],
      "rights": [
        "FederationRight::TrustConnection"
      ],
      "uncalled": null
    },
    {
      "aggregate": "FederatedIdpConnection",
      "aggregates": [],
      "file": "domains/federation/connection/provisioning.rs",
      "kind": "change",
      "line": 71,
      "name": "stop_provisioning",
      "proofs": [
        "FederationControl"
      ],
      "rights": [
        "FederationRight::EditConnection"
      ],
      "uncalled": null
    },
    {
      "aggregate": "FederatedIdpConnection",
      "aggregates": [],
      "file": "domains/federation/connection/provisioning.rs",
      "kind": "change",
      "line": 126,
      "name": "map_provider_groups",
      "proofs": [
        "FederationControl"
      ],
      "rights": [
        "FederationRight::TrustConnection"
      ],
      "uncalled": null
    },
    {
      "aggregate": "FederatedIdpConnection",
      "aggregates": [],
      "file": "domains/federation/connection/provisioning.rs",
      "kind": "change",
      "line": 151,
      "name": "stop_mapping_groups",
      "proofs": [
        "FederationControl"
      ],
      "rights": [
        "FederationRight::EditConnection"
      ],
      "uncalled": null
    },
    {
      "aggregate": "FederatedIdpConnection",
      "aggregates": [],
      "file": "domains/federation/connection/saml.rs",
      "kind": "change",
      "line": 65,
      "name": "import_metadata",
      "proofs": [
        "FederationControl"
      ],
      "rights": [
        "FederationRight::TrustConnection"
      ],
      "uncalled": null
    },
    {
      "aggregate": "FederatedIdpConnection",
      "aggregates": [],
      "file": "domains/federation/connection/saml.rs",
      "kind": "change",
      "line": 95,
      "name": "refresh_metadata",
      "proofs": [],
      "rights": [],
      "uncalled": "the scheduled refresh reads again the address an admin who may trust connections chose; it takes only metadata naming the same provider"
    },
    {
      "aggregate": "FederatedIdpConnection",
      "aggregates": [],
      "file": "domains/federation/connection/saml.rs",
      "kind": "change",
      "line": 137,
      "name": "roll_over_certificate",
      "proofs": [
        "FederationControl"
      ],
      "rights": [
        "FederationRight::EditConnection"
      ],
      "uncalled": null
    },
    {
      "aggregate": "FederatedIdpConnection",
      "aggregates": [],
      "file": "domains/federation/connection/trust.rs",
      "kind": "change",
      "line": 28,
      "name": "change_assurance_trust",
      "proofs": [
        "FederationControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "FederatedIdpConnection",
      "aggregates": [],
      "file": "domains/federation/connection/trust.rs",
      "kind": "change",
      "line": 103,
      "name": "change_email_trust",
      "proofs": [
        "FederationControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "FederatedIdpConnection",
      "aggregates": [],
      "file": "domains/federation/connection.rs",
      "kind": "create",
      "line": 145,
      "name": "create",
      "proofs": [
        "FederationControl"
      ],
      "rights": [
        "FederationRight::CreateConnection"
      ],
      "uncalled": null
    },
    {
      "aggregate": "FederatedIdpConnection",
      "aggregates": [],
      "file": "domains/federation/connection.rs",
      "kind": "change",
      "line": 360,
      "name": "activate",
      "proofs": [
        "FederationControl"
      ],
      "rights": [
        "FederationRight::TrustConnection"
      ],
      "uncalled": null
    },
    {
      "aggregate": "FederatedIdpConnection",
      "aggregates": [],
      "file": "domains/federation/connection.rs",
      "kind": "change",
      "line": 379,
      "name": "disable",
      "proofs": [
        "FederationControl"
      ],
      "rights": [
        "FederationRight::EditConnection"
      ],
      "uncalled": null
    },
    {
      "aggregate": "FederatedIdpConnection",
      "aggregates": [],
      "file": "domains/federation/connection.rs",
      "kind": "change",
      "line": 438,
      "name": "update_config",
      "proofs": [
        "FederationControl"
      ],
      "rights": [
        "FederationRight::TrustConnection"
      ],
      "uncalled": null
    },
    {
      "aggregate": "FederatedIdpConnection",
      "aggregates": [],
      "file": "domains/federation/connection.rs",
      "kind": "change",
      "line": 496,
      "name": "change_domains",
      "proofs": [
        "FederationControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "FederatedIdpConnection",
      "aggregates": [],
      "file": "domains/federation/connection.rs",
      "kind": "change",
      "line": 550,
      "name": "replace_attribute_mapping",
      "proofs": [
        "FederationControl"
      ],
      "rights": [
        "FederationRight::EditConnection"
      ],
      "uncalled": null
    },
    {
      "aggregate": "FederatedIdpConnection",
      "aggregates": [],
      "file": "domains/federation/connection.rs",
      "kind": "change",
      "line": 575,
      "name": "rename",
      "proofs": [
        "FederationControl"
      ],
      "rights": [
        "FederationRight::EditConnection"
      ],
      "uncalled": null
    },
    {
      "aggregate": "FederatedIdpConnection",
      "aggregates": [],
      "file": "domains/federation/connection.rs",
      "kind": "change",
      "line": 602,
      "name": "delete",
      "proofs": [
        "FederationControl"
      ],
      "rights": [
        "FederationRight::DeleteConnection"
      ],
      "uncalled": null
    },
    {
      "aggregate": "FederatedLink",
      "aggregates": [
        "FederatedIdpConnection",
        "User"
      ],
      "file": "domains/federation/link.rs",
      "kind": "create",
      "line": 270,
      "name": "link",
      "proofs": [
        "LinkGrounds"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "FederatedLink",
      "aggregates": [
        "FederatedIdpConnection",
        "User"
      ],
      "file": "domains/federation/link.rs",
      "kind": "change",
      "line": 340,
      "name": "reconfirm",
      "proofs": [
        "FreshSignIn"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "FederatedLink",
      "aggregates": [
        "FederatedIdpConnection",
        "User"
      ],
      "file": "domains/federation/link.rs",
      "kind": "change",
      "line": 441,
      "name": "remove",
      "proofs": [
        "UnlinkGrounds"
      ],
      "rights": [
        "AccountAction::ChangeSignIn"
      ],
      "uncalled": null
    },
    {
      "aggregate": "ScimEndpoint",
      "aggregates": [],
      "file": "domains/federation/scim.rs",
      "kind": "create",
      "line": 118,
      "name": "create",
      "proofs": [
        "FederationControl"
      ],
      "rights": [
        "FederationRight::ConfigureScim"
      ],
      "uncalled": null
    },
    {
      "aggregate": "ScimEndpoint",
      "aggregates": [],
      "file": "domains/federation/scim.rs",
      "kind": "change",
      "line": 238,
      "name": "enable",
      "proofs": [
        "FederationControl"
      ],
      "rights": [
        "FederationRight::ConfigureScim"
      ],
      "uncalled": null
    },
    {
      "aggregate": "ScimEndpoint",
      "aggregates": [],
      "file": "domains/federation/scim.rs",
      "kind": "change",
      "line": 257,
      "name": "disable",
      "proofs": [
        "FederationControl"
      ],
      "rights": [
        "FederationRight::ConfigureScim"
      ],
      "uncalled": null
    },
    {
      "aggregate": "ScimEndpoint",
      "aggregates": [],
      "file": "domains/federation/scim.rs",
      "kind": "change",
      "line": 275,
      "name": "rotate_token",
      "proofs": [
        "FederationControl"
      ],
      "rights": [
        "FederationRight::ConfigureScim"
      ],
      "uncalled": null
    },
    {
      "aggregate": "ScimEndpoint",
      "aggregates": [],
      "file": "domains/federation/scim.rs",
      "kind": "change",
      "line": 301,
      "name": "change_settings",
      "proofs": [
        "FederationControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ScimEndpoint",
      "aggregates": [],
      "file": "domains/federation/scim.rs",
      "kind": "change",
      "line": 408,
      "name": "record_sync",
      "proofs": [],
      "rights": [],
      "uncalled": "when it last happened, shown to people; no rule reads it"
    },
    {
      "aggregate": "SamlServiceProvider",
      "aggregates": [],
      "file": "domains/federation/service_provider.rs",
      "kind": "create",
      "line": 116,
      "name": "create",
      "proofs": [
        "FederationControl"
      ],
      "rights": [
        "FederationRight::CreateConnection",
        "FederationRight::TrustConnection"
      ],
      "uncalled": null
    },
    {
      "aggregate": "SamlServiceProvider",
      "aggregates": [],
      "file": "domains/federation/service_provider.rs",
      "kind": "change",
      "line": 391,
      "name": "update",
      "proofs": [
        "FederationControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "SamlServiceProvider",
      "aggregates": [],
      "file": "domains/federation/service_provider.rs",
      "kind": "change",
      "line": 431,
      "name": "activate",
      "proofs": [
        "FederationControl"
      ],
      "rights": [
        "FederationRight::TrustConnection"
      ],
      "uncalled": null
    },
    {
      "aggregate": "SamlServiceProvider",
      "aggregates": [],
      "file": "domains/federation/service_provider.rs",
      "kind": "change",
      "line": 447,
      "name": "disable",
      "proofs": [
        "FederationControl"
      ],
      "rights": [
        "FederationRight::EditConnection"
      ],
      "uncalled": null
    },
    {
      "aggregate": "SamlServiceProvider",
      "aggregates": [],
      "file": "domains/federation/service_provider.rs",
      "kind": "change",
      "line": 462,
      "name": "delete",
      "proofs": [
        "FederationControl"
      ],
      "rights": [
        "FederationRight::DeleteConnection"
      ],
      "uncalled": null
    },
    {
      "aggregate": "PendingEmailChange",
      "aggregates": [],
      "file": "domains/identity/account/email_change.rs",
      "kind": "create",
      "line": 191,
      "name": "create",
      "proofs": [
        "RecentProof"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "PendingEmailChange",
      "aggregates": [],
      "file": "domains/identity/account/email_change.rs",
      "kind": "change",
      "line": 411,
      "name": "confirm",
      "proofs": [],
      "rights": [],
      "uncalled": "an emailed link being followed; holding that mailbox is the proof"
    },
    {
      "aggregate": "PendingEmailChange",
      "aggregates": [],
      "file": "domains/identity/account/email_change.rs",
      "kind": "change",
      "line": 444,
      "name": "cancel_from_old_address",
      "proofs": [],
      "rights": [],
      "uncalled": "an emailed link being followed; holding that mailbox is the proof"
    },
    {
      "aggregate": "PendingEmailChange",
      "aggregates": [],
      "file": "domains/identity/account/email_change.rs",
      "kind": "change",
      "line": 495,
      "name": "reissue",
      "proofs": [],
      "rights": [],
      "uncalled": "a dead link traded by its holder for a new one, while the account stands as it was"
    },
    {
      "aggregate": "UserImport",
      "aggregates": [],
      "file": "domains/identity/account/import/run.rs",
      "kind": "create",
      "line": 177,
      "name": "start",
      "proofs": [
        "AccountCreator"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "UserImport",
      "aggregates": [],
      "file": "domains/identity/account/import/run.rs",
      "kind": "change",
      "line": 296,
      "name": "take_up",
      "proofs": [],
      "rights": [],
      "uncalled": "the worker's progress through an import whose sender was checked when it was kept; it opens only the records that import holds"
    },
    {
      "aggregate": "UserImport",
      "aggregates": [],
      "file": "domains/identity/account/import/run.rs",
      "kind": "change",
      "line": 348,
      "name": "record_chunk",
      "proofs": [],
      "rights": [],
      "uncalled": "the worker's progress through an import whose sender was checked when it was kept; it opens only the records that import holds"
    },
    {
      "aggregate": "UserImport",
      "aggregates": [],
      "file": "domains/identity/account/import/run.rs",
      "kind": "change",
      "line": 374,
      "name": "give_up",
      "proofs": [],
      "rights": [],
      "uncalled": "the worker's progress through an import whose sender was checked when it was kept; it opens only the records that import holds"
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/directory.rs",
      "kind": "change",
      "line": 36,
      "name": "switch_by_directory",
      "proofs": [
        "AccountControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/directory.rs",
      "kind": "change",
      "line": 66,
      "name": "close_directory_change",
      "proofs": [],
      "rights": [],
      "uncalled": "ends a directory's change whose moves switch_by_directory already checked, raising its one status record"
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/directory.rs",
      "kind": "change",
      "line": 136,
      "name": "delete_by_directory",
      "proofs": [
        "AccountControlCheck"
      ],
      "rights": [
        "AccountAction::ShutOut"
      ],
      "uncalled": null
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/import.rs",
      "kind": "create",
      "line": 35,
      "name": "import",
      "proofs": [
        "AccountCreator"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/mod.rs",
      "kind": "create",
      "line": 119,
      "name": "register",
      "proofs": [
        "AccountCreator"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/mod.rs",
      "kind": "create",
      "line": 148,
      "name": "provision",
      "proofs": [
        "VerifiedEmail"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/mod.rs",
      "kind": "create",
      "line": 168,
      "name": "invite",
      "proofs": [
        "AccountCreator"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/mod.rs",
      "kind": "change",
      "line": 382,
      "name": "verify_email",
      "proofs": [
        "VerifiedEmail"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/mod.rs",
      "kind": "change",
      "line": 424,
      "name": "change_email",
      "proofs": [
        "AccountControlCheck"
      ],
      "rights": [
        "AccountAction::ChangeSignIn"
      ],
      "uncalled": null
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/mod.rs",
      "kind": "change",
      "line": 454,
      "name": "change_verified_email",
      "proofs": [
        "VerifiedEmail"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/mod.rs",
      "kind": "change",
      "line": 469,
      "name": "record_credential_change",
      "proofs": [],
      "rights": [],
      "uncalled": "follows a password or factor change already checked; it only ends sessions and devices"
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/mod.rs",
      "kind": "change",
      "line": 496,
      "name": "allow_password_reset",
      "proofs": [
        "AccountControlCheck"
      ],
      "rights": [
        "AccountAction::ChangeSignIn"
      ],
      "uncalled": null
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/mod.rs",
      "kind": "change",
      "line": 527,
      "name": "delete",
      "proofs": [
        "AccountControlCheck"
      ],
      "rights": [
        "AccountAction::Erase"
      ],
      "uncalled": null
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/mod.rs",
      "kind": "change",
      "line": 535,
      "name": "record_login",
      "proofs": [],
      "rights": [],
      "uncalled": "bookkeeping after a sign-in the authentication context already checked"
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/profile.rs",
      "kind": "change",
      "line": 33,
      "name": "update_details",
      "proofs": [
        "ProfileEditor"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/profile.rs",
      "kind": "change",
      "line": 64,
      "name": "update_records",
      "proofs": [
        "AccountControlCheck"
      ],
      "rights": [
        "AccountAction::EditRecords"
      ],
      "uncalled": null
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/profile.rs",
      "kind": "change",
      "line": 106,
      "name": "rename",
      "proofs": [
        "ProfileEditor"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/profile.rs",
      "kind": "change",
      "line": 132,
      "name": "change_preferences",
      "proofs": [
        "ProfileEditor"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/records.rs",
      "kind": "change",
      "line": 54,
      "name": "note_verification_mailed",
      "proofs": [],
      "rights": [],
      "uncalled": "raises the mail record only; nothing stored changes"
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/records.rs",
      "kind": "change",
      "line": 63,
      "name": "note_welcome_mailed",
      "proofs": [],
      "rights": [],
      "uncalled": "raises the mail record only; nothing stored changes"
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/status.rs",
      "kind": "change",
      "line": 39,
      "name": "activate",
      "proofs": [
        "AccountControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/status.rs",
      "kind": "change",
      "line": 63,
      "name": "lock",
      "proofs": [
        "AccountControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/status.rs",
      "kind": "change",
      "line": 85,
      "name": "unlock",
      "proofs": [
        "AccountControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "User",
      "aggregates": [],
      "file": "domains/identity/account/user/status.rs",
      "kind": "change",
      "line": 110,
      "name": "deactivate",
      "proofs": [
        "AccountControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AttributeDefinition",
      "aggregates": [],
      "file": "domains/identity/attribute/definition/mod.rs",
      "kind": "create",
      "line": 160,
      "name": "declare",
      "proofs": [
        "SchemaControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AttributeDefinition",
      "aggregates": [],
      "file": "domains/identity/attribute/definition/mod.rs",
      "kind": "change",
      "line": 395,
      "name": "update",
      "proofs": [
        "SchemaControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AttributeDefinition",
      "aggregates": [],
      "file": "domains/identity/attribute/definition/mod.rs",
      "kind": "change",
      "line": 413,
      "name": "delete",
      "proofs": [
        "SchemaControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AttributeDefinition",
      "aggregates": [],
      "file": "domains/identity/attribute/definition/mod.rs",
      "kind": "change",
      "line": 429,
      "name": "rename",
      "proofs": [
        "SchemaControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AttributeDefinition",
      "aggregates": [],
      "file": "domains/identity/attribute/definition/mod.rs",
      "kind": "change",
      "line": 445,
      "name": "describe",
      "proofs": [
        "SchemaControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AttributeDefinition",
      "aggregates": [],
      "file": "domains/identity/attribute/definition/mod.rs",
      "kind": "change",
      "line": 463,
      "name": "change_control",
      "proofs": [
        "SchemaControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AttributeDefinition",
      "aggregates": [],
      "file": "domains/identity/attribute/definition/mod.rs",
      "kind": "change",
      "line": 488,
      "name": "replace_options",
      "proofs": [
        "SchemaControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AttributeDefinition",
      "aggregates": [],
      "file": "domains/identity/attribute/definition/mod.rs",
      "kind": "change",
      "line": 522,
      "name": "change_max_length",
      "proofs": [
        "SchemaControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AttributeDefinition",
      "aggregates": [],
      "file": "domains/identity/attribute/definition/mod.rs",
      "kind": "change",
      "line": 543,
      "name": "change_bounds",
      "proofs": [
        "SchemaControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AttributeDefinition",
      "aggregates": [],
      "file": "domains/identity/attribute/definition/mod.rs",
      "kind": "change",
      "line": 574,
      "name": "change_visibility",
      "proofs": [
        "SchemaControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AttributeDefinition",
      "aggregates": [],
      "file": "domains/identity/attribute/definition/mod.rs",
      "kind": "change",
      "line": 602,
      "name": "archive",
      "proofs": [
        "SchemaControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AttributeDefinition",
      "aggregates": [],
      "file": "domains/identity/attribute/definition/mod.rs",
      "kind": "change",
      "line": 612,
      "name": "restore",
      "proofs": [
        "SchemaControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "SupportImpersonation",
      "aggregates": [
        "User"
      ],
      "file": "domains/identity/impersonation/mod.rs",
      "kind": "create",
      "line": 105,
      "name": "request",
      "proofs": [
        "AccountControlCheck",
        "SignedInPerson"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "SupportImpersonation",
      "aggregates": [],
      "file": "domains/identity/impersonation/mod.rs",
      "kind": "change",
      "line": 244,
      "name": "approve",
      "proofs": [
        "SignedInPerson"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "SupportImpersonation",
      "aggregates": [],
      "file": "domains/identity/impersonation/mod.rs",
      "kind": "change",
      "line": 262,
      "name": "decline",
      "proofs": [
        "SignedInPerson"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "SupportImpersonation",
      "aggregates": [],
      "file": "domains/identity/impersonation/mod.rs",
      "kind": "change",
      "line": 288,
      "name": "end",
      "proofs": [
        "SignedInPerson"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Invitation",
      "aggregates": [],
      "file": "domains/identity/invitations/invitation.rs",
      "kind": "create",
      "line": 112,
      "name": "create",
      "proofs": [
        "InvitedRole"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Invitation",
      "aggregates": [
        "User"
      ],
      "file": "domains/identity/invitations/invitation.rs",
      "kind": "change",
      "line": 290,
      "name": "accept",
      "proofs": [
        "InvitedRole"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Invitation",
      "aggregates": [
        "User"
      ],
      "file": "domains/identity/invitations/invitation.rs",
      "kind": "change",
      "line": 347,
      "name": "revoke",
      "proofs": [
        "AccountControlCheck"
      ],
      "rights": [
        "AccountAction::ShutOut"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Invitation",
      "aggregates": [
        "User"
      ],
      "file": "domains/identity/invitations/invitation.rs",
      "kind": "change",
      "line": 376,
      "name": "lapse",
      "proofs": [],
      "rights": [],
      "uncalled": "its link ran out; the clock decides, and lapsing grants nothing"
    },
    {
      "aggregate": "Invitation",
      "aggregates": [
        "User"
      ],
      "file": "domains/identity/invitations/invitation.rs",
      "kind": "change",
      "line": 420,
      "name": "decline",
      "proofs": [],
      "rights": [],
      "uncalled": "an emailed link being followed; holding that mailbox is the proof"
    },
    {
      "aggregate": "Invitation",
      "aggregates": [
        "User"
      ],
      "file": "domains/identity/invitations/invitation.rs",
      "kind": "change",
      "line": 452,
      "name": "rotate_token",
      "proofs": [
        "AccountCreator"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Invitation",
      "aggregates": [
        "User"
      ],
      "file": "domains/identity/invitations/invitation.rs",
      "kind": "change",
      "line": 492,
      "name": "renew_from_link",
      "proofs": [],
      "rights": [],
      "uncalled": "a dead link traded by its holder for a new one, while the account stands as it was"
    },
    {
      "aggregate": "ConsentRecord",
      "aggregates": [],
      "file": "domains/identity/privacy/consent.rs",
      "kind": "create",
      "line": 99,
      "name": "record",
      "proofs": [
        "SignedInPerson"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ConsentRecord",
      "aggregates": [],
      "file": "domains/identity/privacy/consent.rs",
      "kind": "create",
      "line": 141,
      "name": "withdraw_for",
      "proofs": [
        "AccountControlCheck"
      ],
      "rights": [
        "AccountAction::RecordForThem"
      ],
      "uncalled": null
    },
    {
      "aggregate": "ConsentRecord",
      "aggregates": [
        "User"
      ],
      "file": "domains/identity/privacy/consent.rs",
      "kind": "change",
      "line": 230,
      "name": "name_person",
      "proofs": [],
      "rights": [],
      "uncalled": "names the person on the record once its own proof allowed it; staff may read the account only after that check"
    },
    {
      "aggregate": "ErasureRequest",
      "aggregates": [
        "User"
      ],
      "file": "domains/identity/privacy/erasure.rs",
      "kind": "create",
      "line": 216,
      "name": "submit",
      "proofs": [
        "SignedInPerson"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ErasureRequest",
      "aggregates": [
        "User"
      ],
      "file": "domains/identity/privacy/erasure.rs",
      "kind": "create",
      "line": 240,
      "name": "submit_for",
      "proofs": [
        "AccountControlCheck"
      ],
      "rights": [
        "AccountAction::Erase"
      ],
      "uncalled": null
    },
    {
      "aggregate": "ErasureRequest",
      "aggregates": [],
      "file": "domains/identity/privacy/erasure.rs",
      "kind": "change",
      "line": 401,
      "name": "start_processing",
      "proofs": [],
      "rights": [],
      "uncalled": "a step of carrying out an erasure already asked for, once its grace period is over; it only removes"
    },
    {
      "aggregate": "ErasureRequest",
      "aggregates": [],
      "file": "domains/identity/privacy/erasure.rs",
      "kind": "change",
      "line": 418,
      "name": "complete",
      "proofs": [],
      "rights": [],
      "uncalled": "a step of carrying out an erasure already asked for, once its grace period is over; it only removes"
    },
    {
      "aggregate": "ErasureRequest",
      "aggregates": [
        "User"
      ],
      "file": "domains/identity/privacy/erasure.rs",
      "kind": "change",
      "line": 441,
      "name": "cancel_from_link",
      "proofs": [],
      "rights": [],
      "uncalled": "an emailed link being followed; holding that mailbox is the proof"
    },
    {
      "aggregate": "ErasureRequest",
      "aggregates": [
        "User"
      ],
      "file": "domains/identity/privacy/erasure.rs",
      "kind": "change",
      "line": 460,
      "name": "cancel_for",
      "proofs": [
        "AccountControlCheck"
      ],
      "rights": [
        "AccountAction::Erase"
      ],
      "uncalled": null
    },
    {
      "aggregate": "ErasureRequest",
      "aggregates": [],
      "file": "domains/identity/privacy/erasure.rs",
      "kind": "change",
      "line": 493,
      "name": "hold",
      "proofs": [
        "AccountControlCheck"
      ],
      "rights": [
        "AccountAction::Erase"
      ],
      "uncalled": null
    },
    {
      "aggregate": "ErasureRequest",
      "aggregates": [],
      "file": "domains/identity/privacy/erasure.rs",
      "kind": "change",
      "line": 511,
      "name": "release",
      "proofs": [
        "AccountControlCheck"
      ],
      "rights": [
        "AccountAction::Erase"
      ],
      "uncalled": null
    },
    {
      "aggregate": "ErasureRequest",
      "aggregates": [],
      "file": "domains/identity/privacy/erasure.rs",
      "kind": "change",
      "line": 531,
      "name": "fail",
      "proofs": [],
      "rights": [],
      "uncalled": "a step of carrying out an erasure already asked for, once its grace period is over; it only removes"
    },
    {
      "aggregate": "ErasureRequest",
      "aggregates": [],
      "file": "domains/identity/privacy/erasure.rs",
      "kind": "change",
      "line": 551,
      "name": "retry",
      "proofs": [],
      "rights": [],
      "uncalled": "a step of carrying out an erasure already asked for, once its grace period is over; it only removes"
    },
    {
      "aggregate": "DataExportRequest",
      "aggregates": [
        "User"
      ],
      "file": "domains/identity/privacy/export.rs",
      "kind": "create",
      "line": 220,
      "name": "request",
      "proofs": [
        "SignedInPerson"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "DataExportRequest",
      "aggregates": [
        "User"
      ],
      "file": "domains/identity/privacy/export.rs",
      "kind": "create",
      "line": 242,
      "name": "request_for",
      "proofs": [
        "AccountControlCheck"
      ],
      "rights": [
        "AccountAction::Export"
      ],
      "uncalled": null
    },
    {
      "aggregate": "DataExportRequest",
      "aggregates": [],
      "file": "domains/identity/privacy/export.rs",
      "kind": "change",
      "line": 366,
      "name": "mark_ready",
      "proofs": [],
      "rights": [],
      "uncalled": "the file asked for was gathered; the worker records it, and only the person downloads it"
    },
    {
      "aggregate": "DataExportRequest",
      "aggregates": [],
      "file": "domains/identity/privacy/export.rs",
      "kind": "change",
      "line": 394,
      "name": "download",
      "proofs": [
        "SignedInPerson"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "DataExportRequest",
      "aggregates": [],
      "file": "domains/identity/privacy/export.rs",
      "kind": "change",
      "line": 419,
      "name": "expire",
      "proofs": [],
      "rights": [],
      "uncalled": "its download window ran out; the clock decides, and expiring only takes the file away"
    },
    {
      "aggregate": "SecureToken",
      "aggregates": [],
      "file": "domains/identity/tokens/secure.rs",
      "kind": "create",
      "line": 102,
      "name": "create",
      "proofs": [],
      "rights": [],
      "uncalled": "a link mailed to the address the account holds; only its reader can spend it, and issuing grants nothing"
    },
    {
      "aggregate": "SecureToken",
      "aggregates": [
        "User"
      ],
      "file": "domains/identity/tokens/secure.rs",
      "kind": "change",
      "line": 219,
      "name": "redeem",
      "proofs": [],
      "rights": [],
      "uncalled": "an emailed link being followed; holding that mailbox is the proof"
    },
    {
      "aggregate": "EventSchema",
      "aggregates": [],
      "file": "domains/messaging/schema.rs",
      "kind": "create",
      "line": 220,
      "name": "register",
      "proofs": [
        "MessagingCreator"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "EventSchema",
      "aggregates": [],
      "file": "domains/messaging/schema.rs",
      "kind": "change",
      "line": 385,
      "name": "add_version",
      "proofs": [
        "MessagingControl"
      ],
      "rights": [
        "MessagingAction::Manage"
      ],
      "uncalled": null
    },
    {
      "aggregate": "EventSchema",
      "aggregates": [],
      "file": "domains/messaging/schema.rs",
      "kind": "change",
      "line": 429,
      "name": "delete",
      "proofs": [
        "MessagingControl"
      ],
      "rights": [
        "MessagingAction::Delete"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Subscription",
      "aggregates": [
        "Topic"
      ],
      "file": "domains/messaging/subscription.rs",
      "kind": "create",
      "line": 153,
      "name": "create",
      "proofs": [
        "Subscriber"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Subscription",
      "aggregates": [],
      "file": "domains/messaging/subscription.rs",
      "kind": "change",
      "line": 318,
      "name": "pause",
      "proofs": [
        "MessagingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Subscription",
      "aggregates": [],
      "file": "domains/messaging/subscription.rs",
      "kind": "change",
      "line": 336,
      "name": "resume",
      "proofs": [
        "MessagingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Subscription",
      "aggregates": [],
      "file": "domains/messaging/subscription.rs",
      "kind": "change",
      "line": 364,
      "name": "rotate_push_secret",
      "proofs": [
        "MessagingControl"
      ],
      "rights": [
        "MessagingAction::Manage"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Subscription",
      "aggregates": [],
      "file": "domains/messaging/subscription.rs",
      "kind": "change",
      "line": 443,
      "name": "replay_dead_letter",
      "proofs": [
        "MessagingReader"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Subscription",
      "aggregates": [],
      "file": "domains/messaging/subscription.rs",
      "kind": "change",
      "line": 466,
      "name": "delete",
      "proofs": [
        "MessagingControl"
      ],
      "rights": [
        "MessagingAction::Delete"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Topic",
      "aggregates": [],
      "file": "domains/messaging/topic.rs",
      "kind": "create",
      "line": 150,
      "name": "create",
      "proofs": [
        "MessagingCreator"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Topic",
      "aggregates": [],
      "file": "domains/messaging/topic.rs",
      "kind": "change",
      "line": 296,
      "name": "accept_publish",
      "proofs": [],
      "rights": [],
      "uncalled": "raises the publish record only; nothing stored changes, and the publish right is checked before the topic is loaded, so a refused caller never learns it exists"
    },
    {
      "aggregate": "Topic",
      "aggregates": [],
      "file": "domains/messaging/topic.rs",
      "kind": "change",
      "line": 352,
      "name": "pause",
      "proofs": [
        "MessagingControl"
      ],
      "rights": [
        "MessagingAction::Manage"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Topic",
      "aggregates": [],
      "file": "domains/messaging/topic.rs",
      "kind": "change",
      "line": 371,
      "name": "resume",
      "proofs": [
        "MessagingControl"
      ],
      "rights": [
        "MessagingAction::Manage"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Topic",
      "aggregates": [],
      "file": "domains/messaging/topic.rs",
      "kind": "change",
      "line": 390,
      "name": "archive",
      "proofs": [
        "MessagingControl"
      ],
      "rights": [
        "MessagingAction::Delete"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Topic",
      "aggregates": [],
      "file": "domains/messaging/topic.rs",
      "kind": "change",
      "line": 412,
      "name": "change_schema",
      "proofs": [
        "MessagingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Topic",
      "aggregates": [],
      "file": "domains/messaging/topic.rs",
      "kind": "change",
      "line": 445,
      "name": "change_retention",
      "proofs": [
        "MessagingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Topic",
      "aggregates": [],
      "file": "domains/messaging/topic.rs",
      "kind": "change",
      "line": 480,
      "name": "raise_data_class",
      "proofs": [
        "MessagingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Topic",
      "aggregates": [],
      "file": "domains/messaging/topic.rs",
      "kind": "change",
      "line": 518,
      "name": "delete",
      "proofs": [
        "MessagingControl"
      ],
      "rights": [
        "MessagingAction::Delete"
      ],
      "uncalled": null
    },
    {
      "aggregate": "NotificationDestination",
      "aggregates": [],
      "file": "domains/notifications/destination.rs",
      "kind": "create",
      "line": 177,
      "name": "add",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "NotificationDestination",
      "aggregates": [],
      "file": "domains/notifications/destination.rs",
      "kind": "change",
      "line": 307,
      "name": "reconfigure",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "NotificationDestination",
      "aggregates": [],
      "file": "domains/notifications/destination.rs",
      "kind": "change",
      "line": 335,
      "name": "pause",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "NotificationDestination",
      "aggregates": [],
      "file": "domains/notifications/destination.rs",
      "kind": "change",
      "line": 356,
      "name": "resume",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "NotificationDestination",
      "aggregates": [],
      "file": "domains/notifications/destination.rs",
      "kind": "change",
      "line": 377,
      "name": "remove",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Notification",
      "aggregates": [],
      "file": "domains/notifications/notification.rs",
      "kind": "create",
      "line": 181,
      "name": "create",
      "proofs": [],
      "rights": [],
      "uncalled": "made by the fan-out worker from an event that already happened; only holders of the event's view right see it"
    },
    {
      "aggregate": "Notification",
      "aggregates": [],
      "file": "domains/notifications/notification.rs",
      "kind": "change",
      "line": 309,
      "name": "mark_read",
      "proofs": [],
      "rights": [],
      "uncalled": "the recipient's own read mark in an inbox the store opens only for them; it grants and hides nothing"
    },
    {
      "aggregate": "MemberNotificationPreferences",
      "aggregates": [],
      "file": "domains/notifications/personal.rs",
      "kind": "create",
      "line": 98,
      "name": "for_member",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "MemberNotificationPreferences",
      "aggregates": [],
      "file": "domains/notifications/personal.rs",
      "kind": "change",
      "line": 156,
      "name": "change_channel",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OperatorNotificationPreferences",
      "aggregates": [],
      "file": "domains/notifications/personal.rs",
      "kind": "create",
      "line": 205,
      "name": "for_operator",
      "proofs": [
        "OperatorAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OperatorNotificationPreferences",
      "aggregates": [],
      "file": "domains/notifications/personal.rs",
      "kind": "change",
      "line": 252,
      "name": "change_channel",
      "proofs": [
        "OperatorAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "NotificationPreference",
      "aggregates": [],
      "file": "domains/notifications/preference.rs",
      "kind": "create",
      "line": 35,
      "name": "new",
      "proofs": [],
      "rights": [],
      "uncalled": "a category and channel pair the platform fills in; it decides nothing, and delivery does not read it yet"
    },
    {
      "aggregate": "ApiKey",
      "aggregates": [],
      "file": "domains/oauth/clients/api_key.rs",
      "kind": "create",
      "line": 121,
      "name": "create",
      "proofs": [
        "OAuthControl"
      ],
      "rights": [
        "OAuthRight::Create"
      ],
      "uncalled": null
    },
    {
      "aggregate": "ApiKey",
      "aggregates": [],
      "file": "domains/oauth/clients/api_key.rs",
      "kind": "change",
      "line": 293,
      "name": "record_usage",
      "proofs": [],
      "rights": [],
      "uncalled": "when it last happened, shown to people; no rule reads it"
    },
    {
      "aggregate": "ApiKey",
      "aggregates": [],
      "file": "domains/oauth/clients/api_key.rs",
      "kind": "change",
      "line": 317,
      "name": "update",
      "proofs": [
        "OAuthControl"
      ],
      "rights": [
        "OAuthRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "ApiKey",
      "aggregates": [],
      "file": "domains/oauth/clients/api_key.rs",
      "kind": "change",
      "line": 344,
      "name": "revoke",
      "proofs": [
        "OAuthControl"
      ],
      "rights": [
        "OAuthRight::Revoke"
      ],
      "uncalled": null
    },
    {
      "aggregate": "OAuthClient",
      "aggregates": [],
      "file": "domains/oauth/clients/client.rs",
      "kind": "create",
      "line": 175,
      "name": "create",
      "proofs": [
        "OAuthControl"
      ],
      "rights": [
        "OAuthRight::Create"
      ],
      "uncalled": null
    },
    {
      "aggregate": "OAuthClient",
      "aggregates": [],
      "file": "domains/oauth/clients/client.rs",
      "kind": "create",
      "line": 196,
      "name": "register",
      "proofs": [
        "RegistrationAdmission"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OAuthClient",
      "aggregates": [],
      "file": "domains/oauth/clients/client.rs",
      "kind": "change",
      "line": 448,
      "name": "revoke",
      "proofs": [
        "OAuthControl"
      ],
      "rights": [
        "OAuthRight::Revoke"
      ],
      "uncalled": null
    },
    {
      "aggregate": "OAuthClient",
      "aggregates": [],
      "file": "domains/oauth/clients/client.rs",
      "kind": "change",
      "line": 461,
      "name": "deregister",
      "proofs": [
        "SelfManagement"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OAuthClient",
      "aggregates": [],
      "file": "domains/oauth/clients/client.rs",
      "kind": "change",
      "line": 489,
      "name": "update",
      "proofs": [
        "OAuthControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OAuthClient",
      "aggregates": [],
      "file": "domains/oauth/clients/client.rs",
      "kind": "change",
      "line": 506,
      "name": "update_registration",
      "proofs": [
        "SelfManagement"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OAuthClient",
      "aggregates": [],
      "file": "domains/oauth/clients/client.rs",
      "kind": "change",
      "line": 526,
      "name": "rotate_secret",
      "proofs": [
        "OAuthControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OAuthConsent",
      "aggregates": [
        "OAuthClient"
      ],
      "file": "domains/oauth/clients/consent.rs",
      "kind": "create",
      "line": 62,
      "name": "grant",
      "proofs": [
        "SignedInPerson"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OAuthConsent",
      "aggregates": [
        "OAuthClient"
      ],
      "file": "domains/oauth/clients/consent.rs",
      "kind": "change",
      "line": 139,
      "name": "extend_scopes",
      "proofs": [
        "SignedInPerson"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OAuthConsent",
      "aggregates": [
        "OAuthClient"
      ],
      "file": "domains/oauth/clients/consent.rs",
      "kind": "change",
      "line": 167,
      "name": "revoke",
      "proofs": [
        "SignedInPerson"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "InitialAccessToken",
      "aggregates": [],
      "file": "domains/oauth/clients/registration.rs",
      "kind": "create",
      "line": 97,
      "name": "issue",
      "proofs": [
        "OAuthControl"
      ],
      "rights": [
        "OAuthRight::Create"
      ],
      "uncalled": null
    },
    {
      "aggregate": "InitialAccessToken",
      "aggregates": [],
      "file": "domains/oauth/clients/registration.rs",
      "kind": "change",
      "line": 211,
      "name": "admit",
      "proofs": [],
      "rights": [],
      "uncalled": "the registering app presents the token itself; holding it is the proof, and admitting only spends a use"
    },
    {
      "aggregate": "InitialAccessToken",
      "aggregates": [],
      "file": "domains/oauth/clients/registration.rs",
      "kind": "change",
      "line": 229,
      "name": "revoke",
      "proofs": [
        "OAuthControl"
      ],
      "rights": [
        "OAuthRight::Revoke"
      ],
      "uncalled": null
    },
    {
      "aggregate": "AccessToken",
      "aggregates": [],
      "file": "domains/oauth/grants/access_token.rs",
      "kind": "create",
      "line": 195,
      "name": "issue",
      "proofs": [],
      "rights": [],
      "uncalled": "issued after the consent or approval it carries was already checked; it grants nothing more"
    },
    {
      "aggregate": "AccessToken",
      "aggregates": [
        "OAuthClient",
        "StreamRoute"
      ],
      "file": "domains/oauth/grants/access_token.rs",
      "kind": "create",
      "line": 225,
      "name": "issue_for_tunnel",
      "proofs": [],
      "rights": [],
      "uncalled": "issued as `issue` is, after the consent was checked; the client is checked to be the token's and to take readable tokens, and the route to open an active signed-in tunnel"
    },
    {
      "aggregate": "AccessToken",
      "aggregates": [
        "OAuthClient"
      ],
      "file": "domains/oauth/grants/access_token.rs",
      "kind": "create",
      "line": 248,
      "name": "for_client",
      "proofs": [],
      "rights": [],
      "uncalled": "the client asks with its own secret at the token endpoint; the client is checked to hold the grant and the scopes"
    },
    {
      "aggregate": "AccessToken",
      "aggregates": [],
      "file": "domains/oauth/grants/access_token.rs",
      "kind": "create",
      "line": 280,
      "name": "exchanged",
      "proofs": [],
      "rights": [],
      "uncalled": "follows a TokenExchange that checked the client, the subject and actor tokens, the audience and the scopes"
    },
    {
      "aggregate": "AccessToken",
      "aggregates": [],
      "file": "domains/oauth/grants/access_token.rs",
      "kind": "change",
      "line": 500,
      "name": "revoke",
      "proofs": [],
      "rights": [],
      "uncalled": "revoking a token only takes it away; the client holding it asks, or a withdrawn consent or revoked client leads to it"
    },
    {
      "aggregate": "AccessToken",
      "aggregates": [
        "OAuthClient"
      ],
      "file": "domains/oauth/grants/access_token.rs",
      "kind": "change",
      "line": 517,
      "name": "revoke_by_holder",
      "proofs": [],
      "rights": [],
      "uncalled": "the client holding the token revokes it at the revocation endpoint after proving itself; it is checked to be its own, and revoking only takes away"
    },
    {
      "aggregate": "AuthorizationCode",
      "aggregates": [
        "OAuthClient"
      ],
      "file": "domains/oauth/grants/authorization_code.rs",
      "kind": "create",
      "line": 211,
      "name": "create",
      "proofs": [],
      "rights": [],
      "uncalled": "issued after the consent or approval it carries was already checked; it grants nothing more"
    },
    {
      "aggregate": "AuthorizationCode",
      "aggregates": [],
      "file": "domains/oauth/grants/authorization_code.rs",
      "kind": "change",
      "line": 461,
      "name": "consume",
      "proofs": [
        "CodeExchange"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "DeviceAuthorization",
      "aggregates": [
        "OAuthClient"
      ],
      "file": "domains/oauth/grants/device_authorization.rs",
      "kind": "create",
      "line": 250,
      "name": "create",
      "proofs": [],
      "rights": [],
      "uncalled": "a device asks to start a sign-in; it grants nothing until the signed-in person approves"
    },
    {
      "aggregate": "DeviceAuthorization",
      "aggregates": [],
      "file": "domains/oauth/grants/device_authorization.rs",
      "kind": "change",
      "line": 415,
      "name": "poll",
      "proofs": [],
      "rights": [],
      "uncalled": "the device polls with its own device code; it only records the time and may lengthen the wait"
    },
    {
      "aggregate": "DeviceAuthorization",
      "aggregates": [],
      "file": "domains/oauth/grants/device_authorization.rs",
      "kind": "change",
      "line": 441,
      "name": "approve",
      "proofs": [
        "SignedInPerson"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "DeviceAuthorization",
      "aggregates": [],
      "file": "domains/oauth/grants/device_authorization.rs",
      "kind": "change",
      "line": 470,
      "name": "deny",
      "proofs": [
        "SignedInPerson"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "DeviceAuthorization",
      "aggregates": [
        "OAuthClient"
      ],
      "file": "domains/oauth/grants/device_authorization.rs",
      "kind": "change",
      "line": 499,
      "name": "redeem",
      "proofs": [],
      "rights": [],
      "uncalled": "the client that started the flow collects an approval already given, and is checked against the request"
    },
    {
      "aggregate": "DeviceAuthorization",
      "aggregates": [],
      "file": "domains/oauth/grants/device_authorization.rs",
      "kind": "change",
      "line": 535,
      "name": "expire",
      "proofs": [],
      "rights": [],
      "uncalled": "its window ran out; the clock decides, and expiring grants nothing"
    },
    {
      "aggregate": "PushedRequest",
      "aggregates": [
        "OAuthClient"
      ],
      "file": "domains/oauth/grants/pushed_request.rs",
      "kind": "create",
      "line": 174,
      "name": "push",
      "proofs": [],
      "rights": [],
      "uncalled": "the client pushes its own request after proving itself at the endpoint; it is screened as the browser's would be"
    },
    {
      "aggregate": "PushedRequest",
      "aggregates": [
        "OAuthClient"
      ],
      "file": "domains/oauth/grants/pushed_request.rs",
      "kind": "change",
      "line": 310,
      "name": "redeem",
      "proofs": [],
      "rights": [],
      "uncalled": "a browser brings the request_uri back for the client that pushed it; it is used once, within sixty seconds"
    },
    {
      "aggregate": "OAuthRefreshToken",
      "aggregates": [
        "AuthorizationCode",
        "OAuthClient"
      ],
      "file": "domains/oauth/grants/refresh_token.rs",
      "kind": "create",
      "line": 189,
      "name": "from_code",
      "proofs": [],
      "rights": [],
      "uncalled": "follows a code its client just swapped, carrying that grant on; the code and client are checked"
    },
    {
      "aggregate": "OAuthRefreshToken",
      "aggregates": [
        "DeviceAuthorization",
        "OAuthClient"
      ],
      "file": "domains/oauth/grants/refresh_token.rs",
      "kind": "create",
      "line": 217,
      "name": "from_device",
      "proofs": [],
      "rights": [],
      "uncalled": "follows a device approval its client just collected, carrying that grant on; the approval and client are checked"
    },
    {
      "aggregate": "OAuthRefreshToken",
      "aggregates": [],
      "file": "domains/oauth/grants/refresh_token.rs",
      "kind": "create",
      "line": 261,
      "name": "rotated",
      "proofs": [],
      "rights": [],
      "uncalled": "replaces a token its client just used, carrying the same grant on, never past its family's end"
    },
    {
      "aggregate": "OAuthRefreshToken",
      "aggregates": [
        "OAuthClient"
      ],
      "file": "domains/oauth/grants/refresh_token.rs",
      "kind": "change",
      "line": 399,
      "name": "rotate",
      "proofs": [],
      "rights": [],
      "uncalled": "the client holding the token uses it at the token endpoint; the token is checked to be its own and unused"
    },
    {
      "aggregate": "OAuthRefreshToken",
      "aggregates": [
        "OAuthClient"
      ],
      "file": "domains/oauth/grants/refresh_token.rs",
      "kind": "change",
      "line": 450,
      "name": "lose_rotation",
      "proofs": [],
      "rights": [],
      "uncalled": "storage turned down a rotation another refresh with the same token won; it only records the reuse, and grants nothing"
    },
    {
      "aggregate": "OAuthRefreshToken",
      "aggregates": [],
      "file": "domains/oauth/grants/refresh_token.rs",
      "kind": "change",
      "line": 481,
      "name": "revoke",
      "proofs": [],
      "rights": [],
      "uncalled": "revoking a token only takes it away; the client holding it asks, or signing out or a reuse leads to it"
    },
    {
      "aggregate": "OAuthRefreshToken",
      "aggregates": [
        "OAuthClient"
      ],
      "file": "domains/oauth/grants/refresh_token.rs",
      "kind": "change",
      "line": 496,
      "name": "revoke_by_holder",
      "proofs": [],
      "rights": [],
      "uncalled": "the client holding the token revokes it at the revocation endpoint after proving itself; it is checked to be its own, and revoking only takes away"
    },
    {
      "aggregate": "OperatorApiKey",
      "aggregates": [
        "Operator"
      ],
      "file": "domains/operator/api_key.rs",
      "kind": "create",
      "line": 84,
      "name": "create",
      "proofs": [
        "OperatorAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OperatorApiKey",
      "aggregates": [],
      "file": "domains/operator/api_key.rs",
      "kind": "change",
      "line": 222,
      "name": "revoke",
      "proofs": [
        "OperatorAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Operator",
      "aggregates": [],
      "file": "domains/operator/identity.rs",
      "kind": "create",
      "line": 56,
      "name": "create",
      "proofs": [
        "OperatorAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Operator",
      "aggregates": [],
      "file": "domains/operator/identity.rs",
      "kind": "create",
      "line": 71,
      "name": "install_first",
      "proofs": [],
      "rights": [],
      "uncalled": "made once by the installer for the platform, before any operator exists"
    },
    {
      "aggregate": "Operator",
      "aggregates": [],
      "file": "domains/operator/identity.rs",
      "kind": "change",
      "line": 175,
      "name": "disable",
      "proofs": [
        "OperatorAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Operator",
      "aggregates": [],
      "file": "domains/operator/identity.rs",
      "kind": "change",
      "line": 194,
      "name": "enable",
      "proofs": [
        "OperatorAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Operator",
      "aggregates": [],
      "file": "domains/operator/identity.rs",
      "kind": "change",
      "line": 248,
      "name": "change_verified_email",
      "proofs": [
        "VerifiedEmail"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ImpersonationGrant",
      "aggregates": [
        "Tenant"
      ],
      "file": "domains/operator/impersonation.rs",
      "kind": "create",
      "line": 145,
      "name": "create",
      "proofs": [
        "OperatorAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "ImpersonationGrant",
      "aggregates": [],
      "file": "domains/operator/impersonation.rs",
      "kind": "change",
      "line": 427,
      "name": "revoke",
      "proofs": [
        "OperatorAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgApiKey",
      "aggregates": [],
      "file": "domains/organization/access/api_key.rs",
      "kind": "create",
      "line": 148,
      "name": "create",
      "proofs": [
        "OrgControl"
      ],
      "rights": [
        "OrgApiKeyAction::Create"
      ],
      "uncalled": null
    },
    {
      "aggregate": "OrgApiKey",
      "aggregates": [],
      "file": "domains/organization/access/api_key.rs",
      "kind": "change",
      "line": 345,
      "name": "revoke",
      "proofs": [
        "ActedBy",
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgApiKey",
      "aggregates": [],
      "file": "domains/organization/access/api_key.rs",
      "kind": "change",
      "line": 373,
      "name": "record_usage",
      "proofs": [],
      "rights": [],
      "uncalled": "when it last happened, shown to people; no rule reads it"
    },
    {
      "aggregate": "OrgIdentityProvider",
      "aggregates": [],
      "file": "domains/organization/access/identity_provider.rs",
      "kind": "create",
      "line": 142,
      "name": "add",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgIdentityProvider",
      "aggregates": [],
      "file": "domains/organization/access/identity_provider.rs",
      "kind": "change",
      "line": 261,
      "name": "change",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgIdentityProvider",
      "aggregates": [],
      "file": "domains/organization/access/identity_provider.rs",
      "kind": "change",
      "line": 290,
      "name": "switch",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgIdentityProvider",
      "aggregates": [],
      "file": "domains/organization/access/identity_provider.rs",
      "kind": "change",
      "line": 304,
      "name": "remove",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgPasskeyCeremony",
      "aggregates": [],
      "file": "domains/organization/access/passkey.rs",
      "kind": "create",
      "line": 57,
      "name": "open",
      "proofs": [],
      "rights": [],
      "uncalled": "a WebAuthn challenge opened or spent; it proves nothing until its answer is checked"
    },
    {
      "aggregate": "OrgPasskeyCeremony",
      "aggregates": [],
      "file": "domains/organization/access/passkey.rs",
      "kind": "create",
      "line": 81,
      "name": "open_discoverable",
      "proofs": [],
      "rights": [],
      "uncalled": "a WebAuthn challenge opened or spent; it proves nothing until its answer is checked"
    },
    {
      "aggregate": "OrgPasskeyCeremony",
      "aggregates": [],
      "file": "domains/organization/access/passkey.rs",
      "kind": "change",
      "line": 199,
      "name": "consume",
      "proofs": [],
      "rights": [],
      "uncalled": "a WebAuthn challenge opened or spent; it proves nothing until its answer is checked"
    },
    {
      "aggregate": "OrgSession",
      "aggregates": [
        "OrgUser"
      ],
      "file": "domains/organization/access/session/kept_through.rs",
      "kind": "change",
      "line": 40,
      "name": "keep_through_own_change",
      "proofs": [
        "RecentProof"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgSession",
      "aggregates": [
        "OrgUser"
      ],
      "file": "domains/organization/access/session/kept_through.rs",
      "kind": "change",
      "line": 67,
      "name": "keep_through_own_removal",
      "proofs": [
        "SignedIn"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgSession",
      "aggregates": [
        "OrgUser"
      ],
      "file": "domains/organization/access/session/kept_through.rs",
      "kind": "change",
      "line": 99,
      "name": "keep_through_own_factor_addition",
      "proofs": [
        "ProvedFactor"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgSession",
      "aggregates": [],
      "file": "domains/organization/access/session/switch.rs",
      "kind": "create",
      "line": 46,
      "name": "switch_to",
      "proofs": [
        "OrgSessionCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgSession",
      "aggregates": [],
      "file": "domains/organization/access/session.rs",
      "kind": "create",
      "line": 181,
      "name": "create",
      "proofs": [
        "OrgSignInStart"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgSession",
      "aggregates": [],
      "file": "domains/organization/access/session.rs",
      "kind": "change",
      "line": 425,
      "name": "revoke",
      "proofs": [
        "ActedBy",
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgSession",
      "aggregates": [],
      "file": "domains/organization/access/session.rs",
      "kind": "change",
      "line": 453,
      "name": "touch",
      "proofs": [],
      "rights": [],
      "uncalled": "activity on a session its check already admitted; it only keeps the session from going idle"
    },
    {
      "aggregate": "OrgSession",
      "aggregates": [
        "OrgUser"
      ],
      "file": "domains/organization/access/session.rs",
      "kind": "change",
      "line": 475,
      "name": "answer",
      "proofs": [
        "ProvedFactor"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgToken",
      "aggregates": [],
      "file": "domains/organization/access/token.rs",
      "kind": "create",
      "line": 97,
      "name": "issue",
      "proofs": [],
      "rights": [],
      "uncalled": "a link mailed to the account's own address; anyone may ask, only that mailbox can use it"
    },
    {
      "aggregate": "OrgToken",
      "aggregates": [],
      "file": "domains/organization/access/token.rs",
      "kind": "create",
      "line": 115,
      "name": "for_installer",
      "proofs": [
        "Founding"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgToken",
      "aggregates": [
        "OrgUser"
      ],
      "file": "domains/organization/access/token.rs",
      "kind": "change",
      "line": 129,
      "name": "confirm_installer",
      "proofs": [],
      "rights": [],
      "uncalled": "the setup token the install showed its installer being spent; holding it is the proof, and it is refused for anyone but the owner it was issued to"
    },
    {
      "aggregate": "OrgToken",
      "aggregates": [
        "OrgUser"
      ],
      "file": "domains/organization/access/token.rs",
      "kind": "change",
      "line": 153,
      "name": "confirm",
      "proofs": [],
      "rights": [],
      "uncalled": "an emailed link being followed; holding that mailbox is the proof"
    },
    {
      "aggregate": "OrgToken",
      "aggregates": [
        "OrgUser"
      ],
      "file": "domains/organization/access/token.rs",
      "kind": "change",
      "line": 182,
      "name": "sign_in",
      "proofs": [],
      "rights": [],
      "uncalled": "an emailed link being followed; holding that mailbox is the proof"
    },
    {
      "aggregate": "OrgToken",
      "aggregates": [
        "OrgUser"
      ],
      "file": "domains/organization/access/token.rs",
      "kind": "change",
      "line": 309,
      "name": "redeem",
      "proofs": [],
      "rights": [],
      "uncalled": "an emailed link being followed; holding that mailbox is the proof"
    },
    {
      "aggregate": "OrgSubscription",
      "aggregates": [
        "Organization"
      ],
      "file": "domains/organization/billing/subscription.rs",
      "kind": "create",
      "line": 167,
      "name": "start",
      "proofs": [
        "Founding"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgSubscription",
      "aggregates": [],
      "file": "domains/organization/billing/subscription.rs",
      "kind": "change",
      "line": 310,
      "name": "choose_plan",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgSubscription",
      "aggregates": [],
      "file": "domains/organization/billing/subscription.rs",
      "kind": "change",
      "line": 349,
      "name": "arrange",
      "proofs": [
        "OperatorAuthority"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgSubscription",
      "aggregates": [],
      "file": "domains/organization/billing/subscription.rs",
      "kind": "change",
      "line": 382,
      "name": "end_trial",
      "proofs": [],
      "rights": [],
      "uncalled": "the trial's time ran out; the clock decides, and the organization pays or owes from then"
    },
    {
      "aggregate": "OrgSubscription",
      "aggregates": [],
      "file": "domains/organization/billing/subscription.rs",
      "kind": "change",
      "line": 406,
      "name": "record_payment_method",
      "proofs": [],
      "rights": [],
      "uncalled": "records what the payment provider reported about a checkout or a charge; the provider, not a person, decides it"
    },
    {
      "aggregate": "OrgSubscription",
      "aggregates": [],
      "file": "domains/organization/billing/subscription.rs",
      "kind": "change",
      "line": 423,
      "name": "record_payment_failed",
      "proofs": [],
      "rights": [],
      "uncalled": "records what the payment provider reported about a checkout or a charge; the provider, not a person, decides it"
    },
    {
      "aggregate": "OrgSubscription",
      "aggregates": [],
      "file": "domains/organization/billing/subscription.rs",
      "kind": "change",
      "line": 446,
      "name": "record_payment_settled",
      "proofs": [],
      "rights": [],
      "uncalled": "records what the payment provider reported about a checkout or a charge; the provider, not a person, decides it"
    },
    {
      "aggregate": "OrgBranding",
      "aggregates": [],
      "file": "domains/organization/branding.rs",
      "kind": "create",
      "line": 61,
      "name": "platform_default",
      "proofs": [],
      "rights": [],
      "uncalled": "made with the platform's own look before anyone changes it; it shows nothing of the organization's"
    },
    {
      "aggregate": "OrgBranding",
      "aggregates": [],
      "file": "domains/organization/branding.rs",
      "kind": "change",
      "line": 137,
      "name": "change_logo",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgBranding",
      "aggregates": [],
      "file": "domains/organization/branding.rs",
      "kind": "change",
      "line": 154,
      "name": "change_primary_color",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgBranding",
      "aggregates": [],
      "file": "domains/organization/branding.rs",
      "kind": "change",
      "line": 175,
      "name": "change_sender_name",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgBranding",
      "aggregates": [],
      "file": "domains/organization/branding.rs",
      "kind": "change",
      "line": 192,
      "name": "reset",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "CloudAccount",
      "aggregates": [],
      "file": "domains/organization/cloud/account.rs",
      "kind": "create",
      "line": 217,
      "name": "begin",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "CloudAccount",
      "aggregates": [],
      "file": "domains/organization/cloud/account.rs",
      "kind": "change",
      "line": 303,
      "name": "attach_credential",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "CloudAccount",
      "aggregates": [],
      "file": "domains/organization/cloud/account.rs",
      "kind": "change",
      "line": 331,
      "name": "mark_verified",
      "proofs": [],
      "rights": [],
      "uncalled": "records what the platform's own check found: a DNS lookup or a cloud credential probe"
    },
    {
      "aggregate": "CloudAccount",
      "aggregates": [],
      "file": "domains/organization/cloud/account.rs",
      "kind": "change",
      "line": 371,
      "name": "mark_failed",
      "proofs": [],
      "rights": [],
      "uncalled": "records what the platform's own check found: a DNS lookup or a cloud credential probe"
    },
    {
      "aggregate": "Organization",
      "aggregates": [],
      "file": "domains/organization/lifecycle/non_payment.rs",
      "kind": "change",
      "line": 34,
      "name": "suspend_for_non_payment",
      "proofs": [],
      "rights": [],
      "uncalled": "the billing sweep finds a payment owed past the grace; the clock and the debt decide, and suspending only takes away"
    },
    {
      "aggregate": "Organization",
      "aggregates": [],
      "file": "domains/organization/lifecycle/non_payment.rs",
      "kind": "change",
      "line": 58,
      "name": "lift_non_payment_suspension",
      "proofs": [],
      "rights": [],
      "uncalled": "records what the payment provider reported about a checkout or a charge; the provider, not a person, decides it"
    },
    {
      "aggregate": "Organization",
      "aggregates": [],
      "file": "domains/organization/lifecycle/profile.rs",
      "kind": "change",
      "line": 27,
      "name": "rename",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Organization",
      "aggregates": [],
      "file": "domains/organization/lifecycle/profile.rs",
      "kind": "change",
      "line": 47,
      "name": "change_display_name",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Organization",
      "aggregates": [],
      "file": "domains/organization/lifecycle/profile.rs",
      "kind": "change",
      "line": 72,
      "name": "change_contact_email",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Organization",
      "aggregates": [
        "Tenant"
      ],
      "file": "domains/organization/lifecycle/tenants.rs",
      "kind": "change",
      "line": 24,
      "name": "add_tenant",
      "proofs": [
        "ActedBy",
        "OrgControl"
      ],
      "rights": [
        "TenantAction::Create"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Organization",
      "aggregates": [],
      "file": "domains/organization/lifecycle/tenants.rs",
      "kind": "change",
      "line": 55,
      "name": "remove_tenant",
      "proofs": [
        "ActedBy",
        "OrgControl"
      ],
      "rights": [
        "TenantAction::Delete"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Organization",
      "aggregates": [],
      "file": "domains/organization/lifecycle.rs",
      "kind": "create",
      "line": 135,
      "name": "create",
      "proofs": [],
      "rights": [],
      "uncalled": "founding is open sign-up; the founder becomes the first owner through the Founding it returns"
    },
    {
      "aggregate": "Organization",
      "aggregates": [],
      "file": "domains/organization/lifecycle.rs",
      "kind": "create",
      "line": 161,
      "name": "create_installation",
      "proofs": [],
      "rights": [],
      "uncalled": "made once by the installer for a self-hosted deployment, before anyone exists"
    },
    {
      "aggregate": "Organization",
      "aggregates": [],
      "file": "domains/organization/lifecycle.rs",
      "kind": "change",
      "line": 369,
      "name": "replace_auth_config",
      "proofs": [
        "OrgControl"
      ],
      "rights": [
        "OrganizationAction::AuthConfig"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Organization",
      "aggregates": [],
      "file": "domains/organization/lifecycle.rs",
      "kind": "change",
      "line": 415,
      "name": "change_plan",
      "proofs": [
        "PlanMove"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Organization",
      "aggregates": [],
      "file": "domains/organization/lifecycle.rs",
      "kind": "change",
      "line": 467,
      "name": "change_status",
      "proofs": [
        "ActedBy",
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgInvitation",
      "aggregates": [
        "OrgUser"
      ],
      "file": "domains/organization/members/invitation.rs",
      "kind": "create",
      "line": 102,
      "name": "create",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgInvitation",
      "aggregates": [
        "OrgUser"
      ],
      "file": "domains/organization/members/invitation.rs",
      "kind": "change",
      "line": 277,
      "name": "accept",
      "proofs": [],
      "rights": [],
      "uncalled": "an emailed link being followed; holding that mailbox is the proof"
    },
    {
      "aggregate": "OrgInvitation",
      "aggregates": [],
      "file": "domains/organization/members/invitation.rs",
      "kind": "change",
      "line": 339,
      "name": "revoke",
      "proofs": [
        "ActedBy",
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgInvitation",
      "aggregates": [
        "OrgUser"
      ],
      "file": "domains/organization/members/invitation.rs",
      "kind": "change",
      "line": 359,
      "name": "decline",
      "proofs": [],
      "rights": [],
      "uncalled": "an emailed link being followed; holding that mailbox is the proof"
    },
    {
      "aggregate": "OrgInvitation",
      "aggregates": [],
      "file": "domains/organization/members/invitation.rs",
      "kind": "change",
      "line": 378,
      "name": "lapse",
      "proofs": [],
      "rights": [],
      "uncalled": "its link ran out; the clock decides, and lapsing grants nothing"
    },
    {
      "aggregate": "OrgInvitation",
      "aggregates": [
        "OrgUser"
      ],
      "file": "domains/organization/members/invitation.rs",
      "kind": "change",
      "line": 431,
      "name": "rotate_token",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgInvitation",
      "aggregates": [
        "OrgUser"
      ],
      "file": "domains/organization/members/invitation.rs",
      "kind": "change",
      "line": 472,
      "name": "renew_from_link",
      "proofs": [],
      "rights": [],
      "uncalled": "a dead link traded by its holder for a new one, while the account stands as it was"
    },
    {
      "aggregate": "LinkedIdentity",
      "aggregates": [
        "Organization"
      ],
      "file": "domains/organization/members/linked_identity.rs",
      "kind": "create",
      "line": 269,
      "name": "create",
      "proofs": [
        "ProvenAccount"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "LinkedIdentity",
      "aggregates": [
        "Organization"
      ],
      "file": "domains/organization/members/linked_identity.rs",
      "kind": "change",
      "line": 497,
      "name": "add_link",
      "proofs": [
        "ProvenAccount"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "LinkedIdentity",
      "aggregates": [],
      "file": "domains/organization/members/linked_identity.rs",
      "kind": "change",
      "line": 547,
      "name": "remove_link",
      "proofs": [
        "LinkRemoval"
      ],
      "rights": [
        "MemberAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [],
      "file": "domains/organization/members/org_user/credentials.rs",
      "kind": "change",
      "line": 37,
      "name": "change_password",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [],
      "file": "domains/organization/members/org_user/credentials.rs",
      "kind": "change",
      "line": 66,
      "name": "change_own_password",
      "proofs": [],
      "rights": [],
      "uncalled": "the person proves themselves with their current password, checked here before anything changes"
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [],
      "file": "domains/organization/members/org_user/credentials.rs",
      "kind": "change",
      "line": 93,
      "name": "reset_password",
      "proofs": [
        "VerifiedEmail"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [],
      "file": "domains/organization/members/org_user/credentials.rs",
      "kind": "change",
      "line": 151,
      "name": "record_credential_change",
      "proofs": [],
      "rights": [],
      "uncalled": "follows a password or factor change already checked; it only ends sessions and devices"
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [],
      "file": "domains/organization/members/org_user/credentials.rs",
      "kind": "change",
      "line": 160,
      "name": "record_mfa_enrolled",
      "proofs": [],
      "rights": [],
      "uncalled": "follows a password or factor change already checked; it only ends sessions and devices"
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [],
      "file": "domains/organization/members/org_user/credentials.rs",
      "kind": "change",
      "line": 170,
      "name": "record_mfa_turned_off",
      "proofs": [],
      "rights": [],
      "uncalled": "follows a password or factor change already checked; it only ends sessions and devices"
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [],
      "file": "domains/organization/members/org_user/credentials.rs",
      "kind": "change",
      "line": 182,
      "name": "record_mfa_reset",
      "proofs": [],
      "rights": [],
      "uncalled": "follows a password or factor change already checked; it only ends sessions and devices"
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [
        "RecoveryCodeSet"
      ],
      "file": "domains/organization/members/org_user/credentials.rs",
      "kind": "change",
      "line": 195,
      "name": "record_recovery_codes_generated",
      "proofs": [],
      "rights": [],
      "uncalled": "follows a password or factor change already checked; it only ends sessions and devices"
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [
        "PasskeyCredential"
      ],
      "file": "domains/organization/members/org_user/credentials.rs",
      "kind": "change",
      "line": 205,
      "name": "record_passkey_registered",
      "proofs": [],
      "rights": [],
      "uncalled": "follows a password or factor change already checked; it only ends sessions and devices"
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [
        "PasskeyCredential"
      ],
      "file": "domains/organization/members/org_user/credentials.rs",
      "kind": "change",
      "line": 217,
      "name": "record_passkey_removed",
      "proofs": [],
      "rights": [],
      "uncalled": "follows a password or factor change already checked; it only ends sessions and devices"
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [],
      "file": "domains/organization/members/org_user/ownership.rs",
      "kind": "change",
      "line": 38,
      "name": "hand_ownership_to",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [],
      "file": "domains/organization/members/org_user/profile.rs",
      "kind": "change",
      "line": 33,
      "name": "change_display_name",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [],
      "file": "domains/organization/members/org_user/profile.rs",
      "kind": "change",
      "line": 67,
      "name": "change_email",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [],
      "file": "domains/organization/members/org_user/profile.rs",
      "kind": "change",
      "line": 84,
      "name": "change_verified_email",
      "proofs": [
        "VerifiedEmail"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [],
      "file": "domains/organization/members/org_user/profile.rs",
      "kind": "change",
      "line": 105,
      "name": "verify_email",
      "proofs": [
        "VerifiedEmail"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [],
      "file": "domains/organization/members/org_user/profile.rs",
      "kind": "change",
      "line": 135,
      "name": "confirm_as_installer",
      "proofs": [
        "InstallerProof"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [],
      "file": "domains/organization/members/org_user/profile.rs",
      "kind": "change",
      "line": 187,
      "name": "change_preferences",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [],
      "file": "domains/organization/members/org_user.rs",
      "kind": "create",
      "line": 143,
      "name": "create",
      "proofs": [
        "AddedBy"
      ],
      "rights": [
        "MemberAction::Create"
      ],
      "uncalled": null
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [],
      "file": "domains/organization/members/org_user.rs",
      "kind": "create",
      "line": 172,
      "name": "invite",
      "proofs": [
        "OrgControl"
      ],
      "rights": [
        "MemberAction::Invite"
      ],
      "uncalled": null
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [],
      "file": "domains/organization/members/org_user.rs",
      "kind": "change",
      "line": 368,
      "name": "record_sign_in",
      "proofs": [],
      "rights": [],
      "uncalled": "follows a sign-in the authentication context already checked; it only spends what the setup token or an invitation vouched for"
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [],
      "file": "domains/organization/members/org_user.rs",
      "kind": "change",
      "line": 403,
      "name": "change_status",
      "proofs": [
        "OrgControl"
      ],
      "rights": [
        "MemberAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [],
      "file": "domains/organization/members/org_user.rs",
      "kind": "change",
      "line": 465,
      "name": "reopen_for_invitation",
      "proofs": [
        "OrgControl"
      ],
      "rights": [
        "MemberAction::Invite"
      ],
      "uncalled": null
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [],
      "file": "domains/organization/members/org_user.rs",
      "kind": "change",
      "line": 497,
      "name": "remove",
      "proofs": [
        "OrgControl"
      ],
      "rights": [
        "MemberAction::Remove"
      ],
      "uncalled": null
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [],
      "file": "domains/organization/members/org_user.rs",
      "kind": "change",
      "line": 561,
      "name": "change_role",
      "proofs": [
        "OrgControl"
      ],
      "rights": [
        "MemberAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "OrgUser",
      "aggregates": [],
      "file": "domains/organization/members/org_user.rs",
      "kind": "change",
      "line": 607,
      "name": "accept_invitation",
      "proofs": [
        "AcceptedAddress"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgConsentRecord",
      "aggregates": [
        "OrgUser"
      ],
      "file": "domains/organization/members/privacy/consent.rs",
      "kind": "create",
      "line": 72,
      "name": "record",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgConsentRecord",
      "aggregates": [
        "OrgUser"
      ],
      "file": "domains/organization/members/privacy/consent.rs",
      "kind": "create",
      "line": 91,
      "name": "withdraw_for",
      "proofs": [
        "OrgAccountControl"
      ],
      "rights": [
        "AccountAction::RecordForThem"
      ],
      "uncalled": null
    },
    {
      "aggregate": "OrgErasureRequest",
      "aggregates": [
        "OrgUser"
      ],
      "file": "domains/organization/members/privacy/erasure.rs",
      "kind": "create",
      "line": 86,
      "name": "submit",
      "proofs": [
        "OrgControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "OrgErasureRequest",
      "aggregates": [
        "OrgUser"
      ],
      "file": "domains/organization/members/privacy/erasure.rs",
      "kind": "create",
      "line": 111,
      "name": "submit_for",
      "proofs": [
        "OrgAccountControl"
      ],
      "rights": [
        "AccountAction::Erase"
      ],
      "uncalled": null
    },
    {
      "aggregate": "OrgErasureRequest",
      "aggregates": [],
      "file": "domains/organization/members/privacy/erasure.rs",
      "kind": "change",
      "line": 259,
      "name": "start_processing",
      "proofs": [],
      "rights": [],
      "uncalled": "a step of carrying out an erasure already asked for, once its grace period is over; it only removes"
    },
    {
      "aggregate": "OrgErasureRequest",
      "aggregates": [],
      "file": "domains/organization/members/privacy/erasure.rs",
      "kind": "change",
      "line": 276,
      "name": "retry",
      "proofs": [],
      "rights": [],
      "uncalled": "a step of carrying out an erasure already asked for, once its grace period is over; it only removes"
    },
    {
      "aggregate": "OrgErasureRequest",
      "aggregates": [],
      "file": "domains/organization/members/privacy/erasure.rs",
      "kind": "change",
      "line": 295,
      "name": "complete",
      "proofs": [],
      "rights": [],
      "uncalled": "a step of carrying out an erasure already asked for, once its grace period is over; it only removes"
    },
    {
      "aggregate": "OrgErasureRequest",
      "aggregates": [],
      "file": "domains/organization/members/privacy/erasure.rs",
      "kind": "change",
      "line": 312,
      "name": "fail",
      "proofs": [],
      "rights": [],
      "uncalled": "a step of carrying out an erasure already asked for, once its grace period is over; it only removes"
    },
    {
      "aggregate": "OrgErasureRequest",
      "aggregates": [
        "OrgUser"
      ],
      "file": "domains/organization/members/privacy/erasure.rs",
      "kind": "change",
      "line": 335,
      "name": "cancel_from_link",
      "proofs": [],
      "rights": [],
      "uncalled": "an emailed link being followed; holding that mailbox is the proof"
    },
    {
      "aggregate": "OrgErasureRequest",
      "aggregates": [
        "OrgUser"
      ],
      "file": "domains/organization/members/privacy/erasure.rs",
      "kind": "change",
      "line": 354,
      "name": "cancel_for",
      "proofs": [
        "OrgAccountControl"
      ],
      "rights": [
        "AccountAction::Erase"
      ],
      "uncalled": null
    },
    {
      "aggregate": "OrgErasureRequest",
      "aggregates": [],
      "file": "domains/organization/members/privacy/erasure.rs",
      "kind": "change",
      "line": 385,
      "name": "hold",
      "proofs": [
        "OrgAccountControl"
      ],
      "rights": [
        "AccountAction::Erase"
      ],
      "uncalled": null
    },
    {
      "aggregate": "OrgErasureRequest",
      "aggregates": [],
      "file": "domains/organization/members/privacy/erasure.rs",
      "kind": "change",
      "line": 405,
      "name": "release",
      "proofs": [
        "OrgAccountControl"
      ],
      "rights": [
        "AccountAction::Erase"
      ],
      "uncalled": null
    },
    {
      "aggregate": "OrgTenantGrant",
      "aggregates": [],
      "file": "domains/organization/members/tenant_grant.rs",
      "kind": "create",
      "line": 81,
      "name": "issue",
      "proofs": [
        "GrantRequest"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "PendingSignup",
      "aggregates": [],
      "file": "domains/organization/signup.rs",
      "kind": "create",
      "line": 84,
      "name": "request",
      "proofs": [],
      "rights": [],
      "uncalled": "a stranger asks before anyone is signed in; it founds nothing until the link mailed to the address comes back and proves the mailbox"
    },
    {
      "aggregate": "LogShippingTarget",
      "aggregates": [],
      "file": "domains/proxy/log_shipping/mod.rs",
      "kind": "create",
      "line": 120,
      "name": "create",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Create"
      ],
      "uncalled": null
    },
    {
      "aggregate": "LogShippingTarget",
      "aggregates": [],
      "file": "domains/proxy/log_shipping/mod.rs",
      "kind": "change",
      "line": 266,
      "name": "change_settings",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "LogShippingTarget",
      "aggregates": [],
      "file": "domains/proxy/log_shipping/mod.rs",
      "kind": "change",
      "line": 289,
      "name": "rename",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "LogShippingTarget",
      "aggregates": [],
      "file": "domains/proxy/log_shipping/mod.rs",
      "kind": "change",
      "line": 306,
      "name": "pause",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "LogShippingTarget",
      "aggregates": [],
      "file": "domains/proxy/log_shipping/mod.rs",
      "kind": "change",
      "line": 323,
      "name": "resume",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "LogShippingTarget",
      "aggregates": [],
      "file": "domains/proxy/log_shipping/mod.rs",
      "kind": "change",
      "line": 339,
      "name": "delete",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Delete"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Pipeline",
      "aggregates": [],
      "file": "domains/proxy/pipeline/order.rs",
      "kind": "change",
      "line": 42,
      "name": "reorder_stages",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Pipeline",
      "aggregates": [],
      "file": "domains/proxy/pipeline/settings.rs",
      "kind": "change",
      "line": 31,
      "name": "reconfigure_stage",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Pipeline",
      "aggregates": [],
      "file": "domains/proxy/pipeline.rs",
      "kind": "create",
      "line": 91,
      "name": "with_defaults",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::CreatePipeline"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Pipeline",
      "aggregates": [],
      "file": "domains/proxy/pipeline.rs",
      "kind": "change",
      "line": 190,
      "name": "rename",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::ChangePipeline"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Pipeline",
      "aggregates": [
        "Route"
      ],
      "file": "domains/proxy/pipeline.rs",
      "kind": "change",
      "line": 287,
      "name": "activate",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::ChangePipeline"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Pipeline",
      "aggregates": [],
      "file": "domains/proxy/pipeline.rs",
      "kind": "change",
      "line": 318,
      "name": "disable",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::ChangePipeline"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Pipeline",
      "aggregates": [
        "Route"
      ],
      "file": "domains/proxy/pipeline.rs",
      "kind": "change",
      "line": 347,
      "name": "delete",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::DeletePipeline"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Pipeline",
      "aggregates": [
        "StageConfig"
      ],
      "file": "domains/proxy/pipeline.rs",
      "kind": "change",
      "line": 396,
      "name": "add_stage",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Pipeline",
      "aggregates": [],
      "file": "domains/proxy/pipeline.rs",
      "kind": "change",
      "line": 445,
      "name": "remove_stage",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Pipeline",
      "aggregates": [],
      "file": "domains/proxy/pipeline.rs",
      "kind": "change",
      "line": 479,
      "name": "enable_stage",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Pipeline",
      "aggregates": [],
      "file": "domains/proxy/pipeline.rs",
      "kind": "change",
      "line": 508,
      "name": "disable_stage",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "StageConfig",
      "aggregates": [],
      "file": "domains/proxy/stages/stage/mod.rs",
      "kind": "create",
      "line": 161,
      "name": "locked",
      "proofs": [],
      "rights": [],
      "uncalled": "a stage value that does nothing until a pipeline takes it; adding one needs the pipeline right through RoutingControl"
    },
    {
      "aggregate": "StageConfig",
      "aggregates": [],
      "file": "domains/proxy/stages/stage/mod.rs",
      "kind": "create",
      "line": 180,
      "name": "new",
      "proofs": [],
      "rights": [],
      "uncalled": "a stage value that does nothing until a pipeline takes it; adding one needs the pipeline right through RoutingControl"
    },
    {
      "aggregate": "PrivateConnector",
      "aggregates": [],
      "file": "domains/routing/connector/mod.rs",
      "kind": "create",
      "line": 132,
      "name": "create",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Create"
      ],
      "uncalled": null
    },
    {
      "aggregate": "PrivateConnector",
      "aggregates": [],
      "file": "domains/routing/connector/mod.rs",
      "kind": "change",
      "line": 281,
      "name": "enroll",
      "proofs": [],
      "rights": [],
      "uncalled": "the connector's agent proves itself with the one-time code an admin created it with; the code is spent on use and good for an hour"
    },
    {
      "aggregate": "PrivateConnector",
      "aggregates": [],
      "file": "domains/routing/connector/mod.rs",
      "kind": "change",
      "line": 322,
      "name": "renew",
      "proofs": [],
      "rights": [],
      "uncalled": "the connector's agent proves itself with a signing request made by the key it enrolled with; any other key is refused, and a renewal only extends that key's certificate by a day"
    },
    {
      "aggregate": "PrivateConnector",
      "aggregates": [],
      "file": "domains/routing/connector/mod.rs",
      "kind": "change",
      "line": 362,
      "name": "change_scope",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "PrivateConnector",
      "aggregates": [],
      "file": "domains/routing/connector/mod.rs",
      "kind": "change",
      "line": 383,
      "name": "revoke",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "PrivateConnector",
      "aggregates": [],
      "file": "domains/routing/connector/mod.rs",
      "kind": "change",
      "line": 401,
      "name": "delete",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Delete"
      ],
      "uncalled": null
    },
    {
      "aggregate": "EgressPolicy",
      "aggregates": [],
      "file": "domains/routing/egress.rs",
      "kind": "create",
      "line": 107,
      "name": "create",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Create"
      ],
      "uncalled": null
    },
    {
      "aggregate": "EgressPolicy",
      "aggregates": [],
      "file": "domains/routing/egress.rs",
      "kind": "change",
      "line": 229,
      "name": "replace_destinations",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "EgressPolicy",
      "aggregates": [],
      "file": "domains/routing/egress.rs",
      "kind": "change",
      "line": 249,
      "name": "rename",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "EgressPolicy",
      "aggregates": [],
      "file": "domains/routing/egress.rs",
      "kind": "change",
      "line": 265,
      "name": "change_max_data_class",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "EgressPolicy",
      "aggregates": [],
      "file": "domains/routing/egress.rs",
      "kind": "change",
      "line": 287,
      "name": "delete",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Delete"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Route",
      "aggregates": [],
      "file": "domains/routing/route/conditions.rs",
      "kind": "change",
      "line": 38,
      "name": "change_conditions",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Route",
      "aggregates": [],
      "file": "domains/routing/route/declarations.rs",
      "kind": "change",
      "line": 32,
      "name": "declare_data_class",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Route",
      "aggregates": [],
      "file": "domains/routing/route/declarations.rs",
      "kind": "change",
      "line": 77,
      "name": "declare_action_class",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Route",
      "aggregates": [],
      "file": "domains/routing/route/declarations.rs",
      "kind": "change",
      "line": 103,
      "name": "declare_reach",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Route",
      "aggregates": [],
      "file": "domains/routing/route/declarations.rs",
      "kind": "change",
      "line": 131,
      "name": "replace_parameter_rules",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Route",
      "aggregates": [
        "Service"
      ],
      "file": "domains/routing/route/mod.rs",
      "kind": "create",
      "line": 106,
      "name": "create",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "DeclaredAction::Undeclared",
        "RoutingRight::Create"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Route",
      "aggregates": [],
      "file": "domains/routing/route/mod.rs",
      "kind": "change",
      "line": 274,
      "name": "change_hosts",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Route",
      "aggregates": [],
      "file": "domains/routing/route/mod.rs",
      "kind": "change",
      "line": 305,
      "name": "move_to_pipeline",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Route",
      "aggregates": [],
      "file": "domains/routing/route/mod.rs",
      "kind": "change",
      "line": 371,
      "name": "activate",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Route",
      "aggregates": [],
      "file": "domains/routing/route/mod.rs",
      "kind": "change",
      "line": 390,
      "name": "disable",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Route",
      "aggregates": [],
      "file": "domains/routing/route/mod.rs",
      "kind": "change",
      "line": 432,
      "name": "delete",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Route",
      "aggregates": [
        "Service"
      ],
      "file": "domains/routing/route/mod.rs",
      "kind": "change",
      "line": 452,
      "name": "move_to_service",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Route",
      "aggregates": [
        "Service"
      ],
      "file": "domains/routing/route/mod.rs",
      "kind": "change",
      "line": 479,
      "name": "change_policy",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Route",
      "aggregates": [],
      "file": "domains/routing/route/mod.rs",
      "kind": "change",
      "line": 517,
      "name": "change_path",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Route",
      "aggregates": [],
      "file": "domains/routing/route/mod.rs",
      "kind": "change",
      "line": 540,
      "name": "change_methods",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Route",
      "aggregates": [],
      "file": "domains/routing/route/mod.rs",
      "kind": "change",
      "line": 559,
      "name": "change_priority",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Route",
      "aggregates": [],
      "file": "domains/routing/route/mod.rs",
      "kind": "change",
      "line": 578,
      "name": "rename",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Service",
      "aggregates": [],
      "file": "domains/routing/service.rs",
      "kind": "create",
      "line": 106,
      "name": "create",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Create"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Service",
      "aggregates": [
        "Route"
      ],
      "file": "domains/routing/service.rs",
      "kind": "change",
      "line": 283,
      "name": "replace_upstream",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Service",
      "aggregates": [],
      "file": "domains/routing/service.rs",
      "kind": "change",
      "line": 318,
      "name": "change_app_sign_in",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Service",
      "aggregates": [],
      "file": "domains/routing/service.rs",
      "kind": "change",
      "line": 354,
      "name": "accept_app_sign_in_of",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Service",
      "aggregates": [],
      "file": "domains/routing/service.rs",
      "kind": "change",
      "line": 398,
      "name": "change_health_check",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Service",
      "aggregates": [],
      "file": "domains/routing/service.rs",
      "kind": "change",
      "line": 417,
      "name": "rename",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Service",
      "aggregates": [],
      "file": "domains/routing/service.rs",
      "kind": "change",
      "line": 430,
      "name": "activate",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Service",
      "aggregates": [],
      "file": "domains/routing/service.rs",
      "kind": "change",
      "line": 443,
      "name": "disable",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Service",
      "aggregates": [
        "Route"
      ],
      "file": "domains/routing/service.rs",
      "kind": "change",
      "line": 472,
      "name": "delete",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Delete"
      ],
      "uncalled": null
    },
    {
      "aggregate": "StreamRoute",
      "aggregates": [],
      "file": "domains/routing/stream/mod.rs",
      "kind": "create",
      "line": 160,
      "name": "create",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Create"
      ],
      "uncalled": null
    },
    {
      "aggregate": "StreamRoute",
      "aggregates": [],
      "file": "domains/routing/stream/mod.rs",
      "kind": "change",
      "line": 292,
      "name": "change_admission",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "StreamRoute",
      "aggregates": [],
      "file": "domains/routing/stream/mod.rs",
      "kind": "change",
      "line": 418,
      "name": "rename",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "StreamRoute",
      "aggregates": [],
      "file": "domains/routing/stream/mod.rs",
      "kind": "change",
      "line": 434,
      "name": "replace_backends",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "StreamRoute",
      "aggregates": [],
      "file": "domains/routing/stream/mod.rs",
      "kind": "change",
      "line": 457,
      "name": "change_timeouts",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "StreamRoute",
      "aggregates": [],
      "file": "domains/routing/stream/mod.rs",
      "kind": "change",
      "line": 478,
      "name": "change_sni",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "StreamRoute",
      "aggregates": [],
      "file": "domains/routing/stream/mod.rs",
      "kind": "change",
      "line": 499,
      "name": "activate",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "StreamRoute",
      "aggregates": [],
      "file": "domains/routing/stream/mod.rs",
      "kind": "change",
      "line": 513,
      "name": "disable",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "StreamRoute",
      "aggregates": [],
      "file": "domains/routing/stream/mod.rs",
      "kind": "change",
      "line": 531,
      "name": "delete",
      "proofs": [
        "RoutingControl"
      ],
      "rights": [
        "RoutingRight::Delete"
      ],
      "uncalled": null
    },
    {
      "aggregate": "ScheduledJob",
      "aggregates": [],
      "file": "domains/scheduling/job.rs",
      "kind": "create",
      "line": 42,
      "name": "new",
      "proofs": [],
      "rights": [],
      "uncalled": "queue bookkeeping: the system enqueues work after a step already checked, and the worker records each run"
    },
    {
      "aggregate": "ScheduledJob",
      "aggregates": [],
      "file": "domains/scheduling/job.rs",
      "kind": "change",
      "line": 229,
      "name": "mark_running",
      "proofs": [],
      "rights": [],
      "uncalled": "queue bookkeeping: the system enqueues work after a step already checked, and the worker records each run"
    },
    {
      "aggregate": "ScheduledJob",
      "aggregates": [],
      "file": "domains/scheduling/job.rs",
      "kind": "change",
      "line": 241,
      "name": "mark_completed",
      "proofs": [],
      "rights": [],
      "uncalled": "queue bookkeeping: the system enqueues work after a step already checked, and the worker records each run"
    },
    {
      "aggregate": "ScheduledJob",
      "aggregates": [],
      "file": "domains/scheduling/job.rs",
      "kind": "change",
      "line": 255,
      "name": "mark_failed",
      "proofs": [],
      "rights": [],
      "uncalled": "queue bookkeeping: the system enqueues work after a step already checked, and the worker records each run"
    },
    {
      "aggregate": "ScheduledJob",
      "aggregates": [],
      "file": "domains/scheduling/job.rs",
      "kind": "change",
      "line": 280,
      "name": "abandon",
      "proofs": [],
      "rights": [],
      "uncalled": "queue bookkeeping: the system enqueues work after a step already checked, and the worker records each run"
    },
    {
      "aggregate": "SecuritySignal",
      "aggregates": [],
      "file": "domains/signals/signal.rs",
      "kind": "create",
      "line": 375,
      "name": "new",
      "proofs": [],
      "rights": [],
      "uncalled": "raised by the platform from an event already recorded, to tell receivers; it grants nothing"
    },
    {
      "aggregate": "SignalStream",
      "aggregates": [],
      "file": "domains/signals/stream/changes.rs",
      "kind": "change",
      "line": 42,
      "name": "update",
      "proofs": [
        "SignalsControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "SignalStream",
      "aggregates": [],
      "file": "domains/signals/stream/receiver_requests.rs",
      "kind": "change",
      "line": 47,
      "name": "add_subject",
      "proofs": [
        "SignalsControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "SignalStream",
      "aggregates": [],
      "file": "domains/signals/stream/receiver_requests.rs",
      "kind": "change",
      "line": 78,
      "name": "remove_subject",
      "proofs": [
        "SignalsControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "SignalStream",
      "aggregates": [],
      "file": "domains/signals/stream/receiver_requests.rs",
      "kind": "change",
      "line": 112,
      "name": "request_verification",
      "proofs": [
        "SignalsControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "SignalStream",
      "aggregates": [],
      "file": "domains/signals/stream.rs",
      "kind": "create",
      "line": 308,
      "name": "register",
      "proofs": [
        "SignalsControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "SignalStream",
      "aggregates": [],
      "file": "domains/signals/stream.rs",
      "kind": "change",
      "line": 493,
      "name": "confirm_endpoint",
      "proofs": [],
      "rights": [],
      "uncalled": "the endpoint proves itself by echoing the challenge a person with the update right had sent to it"
    },
    {
      "aggregate": "SignalStream",
      "aggregates": [],
      "file": "domains/signals/stream.rs",
      "kind": "change",
      "line": 516,
      "name": "pause",
      "proofs": [
        "SignalsControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "SignalStream",
      "aggregates": [],
      "file": "domains/signals/stream.rs",
      "kind": "change",
      "line": 535,
      "name": "resume",
      "proofs": [
        "SignalsControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "SignalStream",
      "aggregates": [],
      "file": "domains/signals/stream.rs",
      "kind": "change",
      "line": 552,
      "name": "disable",
      "proofs": [
        "SignalsControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "SignalStream",
      "aggregates": [],
      "file": "domains/signals/stream.rs",
      "kind": "change",
      "line": 587,
      "name": "delete",
      "proofs": [
        "SignalsControlCheck"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "SignalStream",
      "aggregates": [],
      "file": "domains/signals/stream.rs",
      "kind": "change",
      "line": 603,
      "name": "record_success",
      "proofs": [],
      "rights": [],
      "uncalled": "delivery bookkeeping after an attempt; it grants and changes no rights"
    },
    {
      "aggregate": "SignalStream",
      "aggregates": [],
      "file": "domains/signals/stream.rs",
      "kind": "change",
      "line": 615,
      "name": "record_failure",
      "proofs": [],
      "rights": [],
      "uncalled": "delivery bookkeeping after an attempt; switching off after repeated failures only takes away"
    },
    {
      "aggregate": "AuditStream",
      "aggregates": [],
      "file": "domains/tenant/audit_streams.rs",
      "kind": "create",
      "line": 151,
      "name": "create",
      "proofs": [
        "RecentProof",
        "TenantControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AuditStream",
      "aggregates": [],
      "file": "domains/tenant/audit_streams.rs",
      "kind": "change",
      "line": 263,
      "name": "reconfigure",
      "proofs": [
        "RecentProof",
        "TenantControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "AuditStream",
      "aggregates": [],
      "file": "domains/tenant/audit_streams.rs",
      "kind": "change",
      "line": 296,
      "name": "pause",
      "proofs": [
        "TenantControl"
      ],
      "rights": [
        "TenantArea::AuditStreaming"
      ],
      "uncalled": null
    },
    {
      "aggregate": "AuditStream",
      "aggregates": [],
      "file": "domains/tenant/audit_streams.rs",
      "kind": "change",
      "line": 311,
      "name": "resume",
      "proofs": [
        "TenantControl"
      ],
      "rights": [
        "TenantArea::AuditStreaming"
      ],
      "uncalled": null
    },
    {
      "aggregate": "AuditStream",
      "aggregates": [],
      "file": "domains/tenant/audit_streams.rs",
      "kind": "change",
      "line": 333,
      "name": "remove",
      "proofs": [
        "TenantControl"
      ],
      "rights": [
        "TenantArea::AuditStreaming"
      ],
      "uncalled": null
    },
    {
      "aggregate": "AuditStream",
      "aggregates": [],
      "file": "domains/tenant/audit_streams.rs",
      "kind": "change",
      "line": 349,
      "name": "record_delivered",
      "proofs": [],
      "rights": [],
      "uncalled": "records how a send the worker made went; it only counts failures or clears them"
    },
    {
      "aggregate": "AuditStream",
      "aggregates": [],
      "file": "domains/tenant/audit_streams.rs",
      "kind": "change",
      "line": 365,
      "name": "record_failed",
      "proofs": [],
      "rights": [],
      "uncalled": "records how a send the worker made went; it only counts failures or clears them"
    },
    {
      "aggregate": "TenantClone",
      "aggregates": [
        "Tenant"
      ],
      "file": "domains/tenant/clone.rs",
      "kind": "create",
      "line": 185,
      "name": "start",
      "proofs": [
        "Steward"
      ],
      "rights": [
        "LifecycleStep::Provision"
      ],
      "uncalled": null
    },
    {
      "aggregate": "TenantClone",
      "aggregates": [],
      "file": "domains/tenant/clone.rs",
      "kind": "change",
      "line": 333,
      "name": "mark_copied",
      "proofs": [],
      "rights": [],
      "uncalled": "a step the clone worker takes; the clone was started by a member who may make tenants in the organization, and it copies only between its own two tenants"
    },
    {
      "aggregate": "TenantClone",
      "aggregates": [],
      "file": "domains/tenant/clone.rs",
      "kind": "change",
      "line": 356,
      "name": "fail",
      "proofs": [],
      "rights": [],
      "uncalled": "a step the clone worker takes; the clone was started by a member who may make tenants in the organization, and it copies only between its own two tenants"
    },
    {
      "aggregate": "AcmeChallenge",
      "aggregates": [],
      "file": "domains/tenant/custom_domains/acme_challenge.rs",
      "kind": "create",
      "line": 104,
      "name": "open",
      "proofs": [],
      "rights": [],
      "uncalled": "a step of issuing a certificate for a domain the tenant proved; the platform takes it"
    },
    {
      "aggregate": "CertificateBundle",
      "aggregates": [],
      "file": "domains/tenant/custom_domains/certificate.rs",
      "kind": "create",
      "line": 92,
      "name": "new",
      "proofs": [],
      "rights": [],
      "uncalled": "a step of issuing a certificate for a domain the tenant proved; the platform takes it"
    },
    {
      "aggregate": "CertificateBundle",
      "aggregates": [
        "RegisteredDomain"
      ],
      "file": "domains/tenant/custom_domains/certificate.rs",
      "kind": "create",
      "line": 129,
      "name": "upload",
      "proofs": [
        "TenantControl"
      ],
      "rights": [
        "TenantArea::Domains"
      ],
      "uncalled": null
    },
    {
      "aggregate": "HandoverOffer",
      "aggregates": [],
      "file": "domains/tenant/custom_domains/handover_offer.rs",
      "kind": "create",
      "line": 76,
      "name": "offer",
      "proofs": [
        "TenantControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "HandoverOffer",
      "aggregates": [
        "Tenant"
      ],
      "file": "domains/tenant/custom_domains/handover_offer.rs",
      "kind": "change",
      "line": 117,
      "name": "accept",
      "proofs": [
        "TenantControl"
      ],
      "rights": [
        "TenantArea::Domains"
      ],
      "uncalled": null
    },
    {
      "aggregate": "RegisteredDomain",
      "aggregates": [],
      "file": "domains/tenant/custom_domains/registered_domain/certificates.rs",
      "kind": "change",
      "line": 28,
      "name": "request_certificate",
      "proofs": [],
      "rights": [],
      "uncalled": "raises the request record only; nothing stored changes, and the domains right is checked before the domain is loaded, so a refused caller never learns it exists"
    },
    {
      "aggregate": "RegisteredDomain",
      "aggregates": [
        "CertificateBundle"
      ],
      "file": "domains/tenant/custom_domains/registered_domain/certificates.rs",
      "kind": "change",
      "line": 58,
      "name": "mark_tls_active",
      "proofs": [],
      "rights": [],
      "uncalled": "a step of issuing a certificate for a domain the tenant proved; the platform takes it"
    },
    {
      "aggregate": "RegisteredDomain",
      "aggregates": [
        "CertificateBundle"
      ],
      "file": "domains/tenant/custom_domains/registered_domain/certificates.rs",
      "kind": "change",
      "line": 119,
      "name": "mark_tls_renewed",
      "proofs": [],
      "rights": [],
      "uncalled": "a step of issuing a certificate for a domain the tenant proved; the platform takes it"
    },
    {
      "aggregate": "RegisteredDomain",
      "aggregates": [],
      "file": "domains/tenant/custom_domains/registered_domain/certificates.rs",
      "kind": "change",
      "line": 139,
      "name": "mark_tls_expired",
      "proofs": [],
      "rights": [],
      "uncalled": "a step of issuing a certificate for a domain the tenant proved; the platform takes it"
    },
    {
      "aggregate": "RegisteredDomain",
      "aggregates": [
        "CertificateBundle"
      ],
      "file": "domains/tenant/custom_domains/registered_domain/certificates.rs",
      "kind": "change",
      "line": 155,
      "name": "serve_uploaded",
      "proofs": [
        "TenantControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "RegisteredDomain",
      "aggregates": [
        "CertificateBundle"
      ],
      "file": "domains/tenant/custom_domains/registered_domain/certificates.rs",
      "kind": "change",
      "line": 202,
      "name": "remove_uploaded",
      "proofs": [
        "TenantControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "RegisteredDomain",
      "aggregates": [
        "CertificateBundle"
      ],
      "file": "domains/tenant/custom_domains/registered_domain/certificates.rs",
      "kind": "change",
      "line": 226,
      "name": "report_expiring",
      "proofs": [],
      "rights": [],
      "uncalled": "warns that a certificate the tenant uploaded runs out soon; the clock decides, and it changes nothing stored"
    },
    {
      "aggregate": "RegisteredDomain",
      "aggregates": [],
      "file": "domains/tenant/custom_domains/registered_domain.rs",
      "kind": "create",
      "line": 234,
      "name": "register",
      "proofs": [
        "TenantControl"
      ],
      "rights": [
        "TenantArea::DomainClaims"
      ],
      "uncalled": null
    },
    {
      "aggregate": "RegisteredDomain",
      "aggregates": [],
      "file": "domains/tenant/custom_domains/registered_domain.rs",
      "kind": "change",
      "line": 473,
      "name": "remove",
      "proofs": [
        "TenantControl"
      ],
      "rights": [
        "TenantArea::DomainRemoval"
      ],
      "uncalled": null
    },
    {
      "aggregate": "RegisteredDomain",
      "aggregates": [],
      "file": "domains/tenant/custom_domains/registered_domain.rs",
      "kind": "change",
      "line": 513,
      "name": "mark_verified",
      "proofs": [],
      "rights": [],
      "uncalled": "records what the platform's own check found: a DNS lookup or a cloud credential probe"
    },
    {
      "aggregate": "RegisteredDomain",
      "aggregates": [],
      "file": "domains/tenant/custom_domains/registered_domain.rs",
      "kind": "change",
      "line": 531,
      "name": "prove_on_arrival",
      "proofs": [],
      "rights": [],
      "uncalled": "a name the operator vouches for, or a wildcard whose verified delegated parent the registration just checked; the registration's own record covers it"
    },
    {
      "aggregate": "RegisteredDomain",
      "aggregates": [],
      "file": "domains/tenant/custom_domains/registered_domain.rs",
      "kind": "change",
      "line": 550,
      "name": "mark_verification_failed",
      "proofs": [],
      "rights": [],
      "uncalled": "records what the platform's own check found: a DNS lookup or a cloud credential probe"
    },
    {
      "aggregate": "PlatformCertificate",
      "aggregates": [],
      "file": "domains/tenant/hosts/certificate.rs",
      "kind": "create",
      "line": 52,
      "name": "issued",
      "proofs": [],
      "rights": [],
      "uncalled": "a step of issuing a certificate for a domain the tenant proved; the platform takes it"
    },
    {
      "aggregate": "Tenant",
      "aggregates": [],
      "file": "domains/tenant/lifecycle/moves.rs",
      "kind": "change",
      "line": 66,
      "name": "activate",
      "proofs": [
        "Steward"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Tenant",
      "aggregates": [],
      "file": "domains/tenant/lifecycle/moves.rs",
      "kind": "change",
      "line": 87,
      "name": "suspend",
      "proofs": [
        "Steward"
      ],
      "rights": [
        "LifecycleStep::Suspend"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Tenant",
      "aggregates": [],
      "file": "domains/tenant/lifecycle/moves.rs",
      "kind": "change",
      "line": 105,
      "name": "reactivate",
      "proofs": [
        "Steward"
      ],
      "rights": [
        "LifecycleStep::Reactivate"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Tenant",
      "aggregates": [],
      "file": "domains/tenant/lifecycle/moves.rs",
      "kind": "change",
      "line": 129,
      "name": "archive",
      "proofs": [
        "Steward"
      ],
      "rights": [
        "LifecycleStep::Archive"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Tenant",
      "aggregates": [],
      "file": "domains/tenant/lifecycle/moves.rs",
      "kind": "change",
      "line": 148,
      "name": "restore",
      "proofs": [
        "Steward"
      ],
      "rights": [
        "LifecycleStep::Restore"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Tenant",
      "aggregates": [],
      "file": "domains/tenant/lifecycle/moves.rs",
      "kind": "change",
      "line": 166,
      "name": "delete",
      "proofs": [
        "Steward"
      ],
      "rights": [
        "LifecycleStep::Delete"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Tenant",
      "aggregates": [],
      "file": "domains/tenant/lifecycle/moves.rs",
      "kind": "change",
      "line": 191,
      "name": "delete_early",
      "proofs": [
        "Steward"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Tenant",
      "aggregates": [],
      "file": "domains/tenant/lifecycle/settings.rs",
      "kind": "change",
      "line": 38,
      "name": "change_readable_address",
      "proofs": [
        "TenantControl"
      ],
      "rights": [
        "TenantArea::Profile"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Tenant",
      "aggregates": [],
      "file": "domains/tenant/lifecycle/settings.rs",
      "kind": "change",
      "line": 65,
      "name": "rename",
      "proofs": [
        "TenantControl"
      ],
      "rights": [
        "TenantArea::Profile"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Tenant",
      "aggregates": [],
      "file": "domains/tenant/lifecycle/settings.rs",
      "kind": "change",
      "line": 89,
      "name": "change_contact_email",
      "proofs": [
        "TenantControl"
      ],
      "rights": [
        "TenantArea::Profile"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Tenant",
      "aggregates": [],
      "file": "domains/tenant/lifecycle/settings.rs",
      "kind": "change",
      "line": 113,
      "name": "change_timezone",
      "proofs": [
        "TenantControl"
      ],
      "rights": [
        "TenantArea::Profile"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Tenant",
      "aggregates": [],
      "file": "domains/tenant/lifecycle/settings.rs",
      "kind": "change",
      "line": 137,
      "name": "change_locale",
      "proofs": [
        "TenantControl"
      ],
      "rights": [
        "TenantArea::Profile"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Tenant",
      "aggregates": [],
      "file": "domains/tenant/lifecycle/settings.rs",
      "kind": "change",
      "line": 161,
      "name": "change_environment",
      "proofs": [
        "TenantControl"
      ],
      "rights": [
        "TenantArea::Profile"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Tenant",
      "aggregates": [],
      "file": "domains/tenant/lifecycle/settings.rs",
      "kind": "change",
      "line": 190,
      "name": "change_primary_domain",
      "proofs": [
        "TenantControl"
      ],
      "rights": [
        "TenantArea::Profile"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Tenant",
      "aggregates": [],
      "file": "domains/tenant/lifecycle/settings.rs",
      "kind": "change",
      "line": 239,
      "name": "release_domain",
      "proofs": [],
      "rights": [],
      "uncalled": "follows a domain being removed, handed over or losing its proof; nobody chooses it"
    },
    {
      "aggregate": "Tenant",
      "aggregates": [],
      "file": "domains/tenant/lifecycle/settings.rs",
      "kind": "change",
      "line": 259,
      "name": "update_auth_config",
      "proofs": [
        "RecentProof",
        "TenantControl"
      ],
      "rights": [
        "TenantArea::SignIn"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Tenant",
      "aggregates": [],
      "file": "domains/tenant/lifecycle/settings.rs",
      "kind": "change",
      "line": 284,
      "name": "update_mtls",
      "proofs": [
        "RecentProof",
        "TenantControl"
      ],
      "rights": [
        "TenantArea::Mtls"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Tenant",
      "aggregates": [],
      "file": "domains/tenant/lifecycle/settings.rs",
      "kind": "change",
      "line": 313,
      "name": "change_compliance",
      "proofs": [
        "RecentProof",
        "TenantControl"
      ],
      "rights": [
        "TenantArea::Compliance"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Tenant",
      "aggregates": [
        "TenantClone"
      ],
      "file": "domains/tenant/lifecycle/settings.rs",
      "kind": "change",
      "line": 352,
      "name": "copy_settings_from",
      "proofs": [],
      "rights": [],
      "uncalled": "a step the clone worker takes; the clone was started by a member who may make tenants in the organization, and it copies only between its own two tenants"
    },
    {
      "aggregate": "Tenant",
      "aggregates": [],
      "file": "domains/tenant/lifecycle.rs",
      "kind": "create",
      "line": 170,
      "name": "provision",
      "proofs": [
        "Steward"
      ],
      "rights": [
        "LifecycleStep::Provision"
      ],
      "uncalled": null
    },
    {
      "aggregate": "TenantSetup",
      "aggregates": [
        "Tenant"
      ],
      "file": "domains/tenant/setup.rs",
      "kind": "create",
      "line": 166,
      "name": "begin",
      "proofs": [],
      "rights": [],
      "uncalled": "the platform's own setup of a tenant made by someone checked when it was made; it begins only for a tenant still provisioning and grants nothing itself"
    },
    {
      "aggregate": "TenantSetup",
      "aggregates": [],
      "file": "domains/tenant/setup.rs",
      "kind": "change",
      "line": 270,
      "name": "finish",
      "proofs": [],
      "rights": [],
      "uncalled": "the platform's own setup of a tenant made by someone checked when it was made; it begins only for a tenant still provisioning and grants nothing itself"
    },
    {
      "aggregate": "TenantSetup",
      "aggregates": [],
      "file": "domains/tenant/setup.rs",
      "kind": "change",
      "line": 285,
      "name": "fail",
      "proofs": [],
      "rights": [],
      "uncalled": "the platform's own setup of a tenant made by someone checked when it was made; it begins only for a tenant still provisioning and grants nothing itself"
    },
    {
      "aggregate": "TenantTeardown",
      "aggregates": [
        "Tenant"
      ],
      "file": "domains/tenant/teardown.rs",
      "kind": "create",
      "line": 135,
      "name": "begin",
      "proofs": [],
      "rights": [],
      "uncalled": "the platform's own teardown of a tenant deleted by someone checked when it was deleted; it begins only for a deleted tenant and removes, never grants"
    },
    {
      "aggregate": "TenantTeardown",
      "aggregates": [],
      "file": "domains/tenant/teardown.rs",
      "kind": "change",
      "line": 225,
      "name": "finish",
      "proofs": [],
      "rights": [],
      "uncalled": "the platform's own teardown of a tenant deleted by someone checked when it was deleted; it begins only for a deleted tenant and removes, never grants"
    },
    {
      "aggregate": "TenantTeardown",
      "aggregates": [],
      "file": "domains/tenant/teardown.rs",
      "kind": "change",
      "line": 249,
      "name": "fail",
      "proofs": [],
      "rights": [],
      "uncalled": "the platform's own teardown of a tenant deleted by someone checked when it was deleted; it begins only for a deleted tenant and removes, never grants"
    },
    {
      "aggregate": "WebhookSubscription",
      "aggregates": [],
      "file": "domains/webhooks/subscription/changes.rs",
      "kind": "change",
      "line": 36,
      "name": "update",
      "proofs": [
        "WebhookControl"
      ],
      "rights": [
        "WebhooksAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "WebhookSubscription",
      "aggregates": [],
      "file": "domains/webhooks/subscription/changes.rs",
      "kind": "change",
      "line": 83,
      "name": "rotate_secret",
      "proofs": [
        "WebhookControl"
      ],
      "rights": [
        "WebhooksAction::Manage"
      ],
      "uncalled": null
    },
    {
      "aggregate": "WebhookSubscription",
      "aggregates": [],
      "file": "domains/webhooks/subscription.rs",
      "kind": "create",
      "line": 152,
      "name": "create",
      "proofs": [
        "WebhookControl"
      ],
      "rights": [
        "WebhooksAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "WebhookSubscription",
      "aggregates": [],
      "file": "domains/webhooks/subscription.rs",
      "kind": "change",
      "line": 399,
      "name": "record_success",
      "proofs": [],
      "rights": [],
      "uncalled": "delivery bookkeeping after an attempt; it grants and changes no rights"
    },
    {
      "aggregate": "WebhookSubscription",
      "aggregates": [],
      "file": "domains/webhooks/subscription.rs",
      "kind": "change",
      "line": 413,
      "name": "record_failure",
      "proofs": [],
      "rights": [],
      "uncalled": "delivery bookkeeping after an attempt; switching off after repeated failures only takes away"
    },
    {
      "aggregate": "WebhookSubscription",
      "aggregates": [],
      "file": "domains/webhooks/subscription.rs",
      "kind": "change",
      "line": 432,
      "name": "report_attempt",
      "proofs": [],
      "rights": [],
      "uncalled": "raises the delivery record only; nothing stored changes, the store counted the attempt already"
    },
    {
      "aggregate": "WebhookSubscription",
      "aggregates": [],
      "file": "domains/webhooks/subscription.rs",
      "kind": "change",
      "line": 446,
      "name": "report_switched_off",
      "proofs": [],
      "rights": [],
      "uncalled": "raises the switch-off the store's failure count caused; nothing stored changes, and switching off only takes away"
    },
    {
      "aggregate": "WebhookSubscription",
      "aggregates": [],
      "file": "domains/webhooks/subscription.rs",
      "kind": "change",
      "line": 466,
      "name": "pause",
      "proofs": [
        "WebhookControl"
      ],
      "rights": [
        "WebhooksAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "WebhookSubscription",
      "aggregates": [],
      "file": "domains/webhooks/subscription.rs",
      "kind": "change",
      "line": 488,
      "name": "resume",
      "proofs": [
        "WebhookControl"
      ],
      "rights": [
        "WebhooksAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "WebhookSubscription",
      "aggregates": [],
      "file": "domains/webhooks/subscription.rs",
      "kind": "change",
      "line": 517,
      "name": "delete",
      "proofs": [
        "WebhookControl"
      ],
      "rights": [
        "WebhooksAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "IntegrationAccount",
      "aggregates": [],
      "file": "domains/workflows/account.rs",
      "kind": "create",
      "line": 225,
      "name": "connect",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [
        "WorkflowAction::ConnectAccounts"
      ],
      "uncalled": null
    },
    {
      "aggregate": "IntegrationAccount",
      "aggregates": [],
      "file": "domains/workflows/account.rs",
      "kind": "change",
      "line": 349,
      "name": "disable",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "IntegrationAccount",
      "aggregates": [],
      "file": "domains/workflows/account.rs",
      "kind": "change",
      "line": 372,
      "name": "enable",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "IntegrationAccount",
      "aggregates": [],
      "file": "domains/workflows/account.rs",
      "kind": "change",
      "line": 390,
      "name": "replace_credential",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "IntegrationAccount",
      "aggregates": [],
      "file": "domains/workflows/account.rs",
      "kind": "change",
      "line": 409,
      "name": "share_with_tenant",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "IntegrationAccount",
      "aggregates": [],
      "file": "domains/workflows/account.rs",
      "kind": "change",
      "line": 424,
      "name": "keep_to_owner",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "IntegrationAccount",
      "aggregates": [],
      "file": "domains/workflows/account.rs",
      "kind": "change",
      "line": 438,
      "name": "limit_to",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "IntegrationAccount",
      "aggregates": [],
      "file": "domains/workflows/account.rs",
      "kind": "change",
      "line": 458,
      "name": "rename",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "WorkflowExecution",
      "aggregates": [],
      "file": "domains/workflows/execution/action_step.rs",
      "kind": "change",
      "line": 112,
      "name": "begin_action",
      "proofs": [],
      "rights": [],
      "uncalled": "a step the workflow engine takes, as the published version says"
    },
    {
      "aggregate": "WorkflowExecution",
      "aggregates": [],
      "file": "domains/workflows/execution/action_step.rs",
      "kind": "change",
      "line": 220,
      "name": "settle_action",
      "proofs": [],
      "rights": [],
      "uncalled": "a step the workflow engine takes, as the published version says"
    },
    {
      "aggregate": "WorkflowExecution",
      "aggregates": [
        "AgentIdentity"
      ],
      "file": "domains/workflows/execution/agent_step.rs",
      "kind": "change",
      "line": 78,
      "name": "start_agent_run",
      "proofs": [],
      "rights": [],
      "uncalled": "a step the workflow engine takes, as the published version says"
    },
    {
      "aggregate": "WorkflowExecution",
      "aggregates": [
        "AgentRun"
      ],
      "file": "domains/workflows/execution/agent_step.rs",
      "kind": "change",
      "line": 217,
      "name": "settle_agent_run",
      "proofs": [],
      "rights": [],
      "uncalled": "a step the workflow engine takes, as the published version says"
    },
    {
      "aggregate": "WorkflowExecution",
      "aggregates": [],
      "file": "domains/workflows/execution/approval_step.rs",
      "kind": "change",
      "line": 47,
      "name": "request_approval",
      "proofs": [],
      "rights": [],
      "uncalled": "a step the workflow engine takes, as the published version says"
    },
    {
      "aggregate": "WorkflowExecution",
      "aggregates": [],
      "file": "domains/workflows/execution/approval_step.rs",
      "kind": "change",
      "line": 143,
      "name": "approve",
      "proofs": [
        "StepApprover"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "WorkflowExecution",
      "aggregates": [],
      "file": "domains/workflows/execution/approval_step.rs",
      "kind": "change",
      "line": 273,
      "name": "deny",
      "proofs": [
        "StepApprover"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "WorkflowExecution",
      "aggregates": [],
      "file": "domains/workflows/execution/approval_step.rs",
      "kind": "change",
      "line": 302,
      "name": "lapse_approval",
      "proofs": [],
      "rights": [],
      "uncalled": "a step the workflow engine takes, as the published version says"
    },
    {
      "aggregate": "WorkflowExecution",
      "aggregates": [],
      "file": "domains/workflows/execution/deferral.rs",
      "kind": "change",
      "line": 40,
      "name": "defer_agent_run",
      "proofs": [],
      "rights": [],
      "uncalled": "a step the workflow engine takes, as the published version says"
    },
    {
      "aggregate": "WorkflowExecution",
      "aggregates": [
        "Workflow"
      ],
      "file": "domains/workflows/execution/mod.rs",
      "kind": "create",
      "line": 302,
      "name": "start_by_hand",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [
        "WorkflowAction::Run"
      ],
      "uncalled": null
    },
    {
      "aggregate": "WorkflowExecution",
      "aggregates": [
        "Workflow"
      ],
      "file": "domains/workflows/execution/mod.rs",
      "kind": "create",
      "line": 350,
      "name": "start_on_trigger",
      "proofs": [],
      "rights": [],
      "uncalled": "a step the workflow engine takes, as the published version says"
    },
    {
      "aggregate": "WorkflowExecution",
      "aggregates": [],
      "file": "domains/workflows/execution/progress.rs",
      "kind": "change",
      "line": 57,
      "name": "cancel",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "WorkflowExecution",
      "aggregates": [],
      "file": "domains/workflows/execution/progress.rs",
      "kind": "change",
      "line": 79,
      "name": "expire",
      "proofs": [],
      "rights": [],
      "uncalled": "a step the workflow engine takes, as the published version says"
    },
    {
      "aggregate": "WorkflowExecution",
      "aggregates": [],
      "file": "domains/workflows/execution/wait_step.rs",
      "kind": "change",
      "line": 23,
      "name": "begin_wait",
      "proofs": [],
      "rights": [],
      "uncalled": "a step the workflow engine takes, as the published version says"
    },
    {
      "aggregate": "WorkflowExecution",
      "aggregates": [],
      "file": "domains/workflows/execution/wait_step.rs",
      "kind": "change",
      "line": 43,
      "name": "elapse",
      "proofs": [],
      "rights": [],
      "uncalled": "a step the workflow engine takes, as the published version says"
    },
    {
      "aggregate": "WorkflowExecution",
      "aggregates": [
        "Workflow"
      ],
      "file": "domains/workflows/execution/webhook_start.rs",
      "kind": "create",
      "line": 43,
      "name": "start_on_webhook",
      "proofs": [],
      "rights": [],
      "uncalled": "a webhook call its trigger's secret admitted; it acts for the version's publisher, who issued that secret"
    },
    {
      "aggregate": "WorkflowExecution",
      "aggregates": [],
      "file": "domains/workflows/execution/work.rs",
      "kind": "change",
      "line": 288,
      "name": "refuse",
      "proofs": [],
      "rights": [],
      "uncalled": "a step the workflow engine takes, as the published version says"
    },
    {
      "aggregate": "OperationRiskOverride",
      "aggregates": [],
      "file": "domains/workflows/risk_override.rs",
      "kind": "create",
      "line": 110,
      "name": "raise",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [
        "WorkflowAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "OperationRiskOverride",
      "aggregates": [],
      "file": "domains/workflows/risk_override.rs",
      "kind": "change",
      "line": 166,
      "name": "change",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [
        "WorkflowAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "OperationRiskOverride",
      "aggregates": [],
      "file": "domains/workflows/risk_override.rs",
      "kind": "change",
      "line": 205,
      "name": "remove",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [
        "WorkflowAction::Manage"
      ],
      "uncalled": null
    },
    {
      "aggregate": "WorkflowTriggerSecret",
      "aggregates": [
        "Workflow"
      ],
      "file": "domains/workflows/trigger_secret.rs",
      "kind": "create",
      "line": 95,
      "name": "issue",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [
        "WorkflowAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "WorkflowTriggerSecret",
      "aggregates": [
        "Workflow"
      ],
      "file": "domains/workflows/trigger_secret.rs",
      "kind": "change",
      "line": 164,
      "name": "rotate",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [
        "WorkflowAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "WorkflowTriggerSecret",
      "aggregates": [
        "Workflow"
      ],
      "file": "domains/workflows/trigger_secret.rs",
      "kind": "change",
      "line": 191,
      "name": "revoke",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [
        "WorkflowAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Workflow",
      "aggregates": [],
      "file": "domains/workflows/workflow/flow.rs",
      "kind": "create",
      "line": 77,
      "name": "flow",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [
        "WorkflowAction::Create",
        "WorkflowAction::Run"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Workflow",
      "aggregates": [
        "WorkflowExecution"
      ],
      "file": "domains/workflows/workflow/flow.rs",
      "kind": "change",
      "line": 146,
      "name": "delete_flow",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [],
      "uncalled": null
    },
    {
      "aggregate": "Workflow",
      "aggregates": [],
      "file": "domains/workflows/workflow.rs",
      "kind": "create",
      "line": 81,
      "name": "create",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [
        "WorkflowAction::Create"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Workflow",
      "aggregates": [],
      "file": "domains/workflows/workflow.rs",
      "kind": "change",
      "line": 227,
      "name": "rename",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [
        "WorkflowAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Workflow",
      "aggregates": [],
      "file": "domains/workflows/workflow.rs",
      "kind": "change",
      "line": 246,
      "name": "replace_graph",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [
        "WorkflowAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Workflow",
      "aggregates": [],
      "file": "domains/workflows/workflow.rs",
      "kind": "change",
      "line": 269,
      "name": "change_run_limit",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [
        "WorkflowAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Workflow",
      "aggregates": [],
      "file": "domains/workflows/workflow.rs",
      "kind": "change",
      "line": 292,
      "name": "change_trigger",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [
        "WorkflowAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Workflow",
      "aggregates": [],
      "file": "domains/workflows/workflow.rs",
      "kind": "change",
      "line": 351,
      "name": "publish",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [
        "WorkflowAction::Update"
      ],
      "uncalled": null
    },
    {
      "aggregate": "Workflow",
      "aggregates": [],
      "file": "domains/workflows/workflow.rs",
      "kind": "change",
      "line": 432,
      "name": "archive",
      "proofs": [
        "WorkflowControl"
      ],
      "rights": [
        "WorkflowAction::Delete"
      ],
      "uncalled": null
    }
  ],
  "proofs": [
    {
      "asked_by": [
        "OrgSubscription::start",
        "OrgToken::for_installer",
        "through AddedBy"
      ],
      "carrier": false,
      "context": "organization",
      "file": "domains/organization/founding.rs",
      "id": "Founding"
    },
    {
      "asked_by": [
        "Role::starting"
      ],
      "carrier": false,
      "context": "authorization",
      "file": "domains/authorization/role/starting.rs",
      "id": "StartingRolesGrant"
    },
    {
      "asked_by": [
        "AccessRequest::approve",
        "AccessRequest::cancel",
        "AccessRequest::deny",
        "AccessRequest::request",
        "AccessRequestPolicy::change_limits",
        "AccessReview::cancel",
        "AccessReview::complete",
        "AccessReview::decide",
        "AccessReview::start",
        "AccountControl::assumed",
        "AccountControl::new",
        "ActingAuthority::of_signed_in",
        "AgentControl::new",
        "ApprovalRequest::readable_by",
        "BrandingControl::new",
        "BreakGlassGrant::may_be_revoked_by",
        "BreakGlassGrant::revoke",
        "BreakGlassPolicy::change_self_service",
        "ClearanceRules::add_rule",
        "ClearanceRules::change_rule",
        "ClearanceRules::clearance_of",
        "ClearanceRules::remove_rule",
        "ConsumerControl::new",
        "FederationControl::new",
        "MessagingControl::new",
        "OAuthControl::new",
        "PolicyApprover::assumed",
        "PolicyApprover::new",
        "PolicySet::add_rule",
        "PolicySet::archive",
        "PolicySet::change_default_action",
        "PolicySet::change_rule",
        "PolicySet::reject",
        "PolicySet::remove_rule",
        "PolicySet::reorder_rules",
        "PolicySet::simulate",
        "PolicySet::start_draft",
        "PolicySet::submit_for_review",
        "PolicySet::switch_rule",
        "Relationship::remove",
        "Relationship::write",
        "ResourceType::describe",
        "ResourceType::reclassify",
        "ResourceType::rename",
        "ResourceType::update",
        "Role::rename",
        "RoleAssignment::assign_until",
        "RoleAssignment::create",
        "RoutingControl::new",
        "RunStarter::person",
        "SeparationRule::declare",
        "SeparationRule::lift",
        "TenantAccess::account_control",
        "TenantAccess::policy_approver",
        "TenantControl::new",
        "WebhookControl::new",
        "WorkflowControl::new",
        "may_ask_for",
        "through ClassificationControlCheck",
        "through CryptoControlCheck",
        "through DirectoryControlCheck",
        "through SchemaControlCheck",
        "through SignalsControlCheck"
      ],
      "carrier": false,
      "context": "authorization",
      "file": "domains/authorization/authority.rs",
      "id": "TenantAuthority"
    },
    {
      "asked_by": [
        "Group::assign_role",
        "Group::create",
        "Group::delete",
        "Group::move_under",
        "Group::rename",
        "Group::unassign_role",
        "GroupMembership::end",
        "GroupMembership::join_until",
        "ResourceType::create",
        "ResourceType::delete",
        "ResourceType::redraw_actions",
        "Role::change_default_assignment",
        "Role::change_permissions",
        "Role::create",
        "Role::delete",
        "Role::ensure_editable_by",
        "RoleAssignment::revoke",
        "RoleReassignment::plan",
        "ceiling_from",
        "ensure_answers_requests",
        "through AccountCreator"
      ],
      "carrier": false,
      "context": "authorization",
      "file": "domains/authorization/granter.rs",
      "id": "HeldByGranter"
    },
    {
      "asked_by": [
        "through AccountControlCheck",
        "through ProfileEditor"
      ],
      "carrier": false,
      "context": "authorization",
      "file": "domains/authorization/granter.rs",
      "id": "AccountControl"
    },
    {
      "asked_by": [
        "ConsentRecord::withdraw_for",
        "DataExportRequest::request_for",
        "ErasureRequest::cancel_for",
        "ErasureRequest::hold",
        "ErasureRequest::release",
        "ErasureRequest::submit_for",
        "FactorReset::by_admin",
        "Invitation::revoke",
        "MfaEnrollment::reset_by_admin",
        "SupportImpersonation::request",
        "User::activate",
        "User::allow_password_reset",
        "User::change_email",
        "User::deactivate",
        "User::delete",
        "User::delete_by_directory",
        "User::let_back_in",
        "User::let_in",
        "User::lock",
        "User::shut_out",
        "User::switch_by_directory",
        "User::unlock",
        "User::update_records"
      ],
      "carrier": false,
      "context": "identity",
      "file": "domains/identity/account/control.rs",
      "id": "AccountControlCheck"
    },
    {
      "asked_by": [
        "PolicySet::activate",
        "ensure_second_person"
      ],
      "carrier": false,
      "context": "authorization",
      "file": "domains/authorization/policy/review.rs",
      "id": "PolicyApprover"
    },
    {
      "asked_by": [
        "AuditStream::create",
        "AuditStream::pause",
        "AuditStream::reconfigure",
        "AuditStream::remove",
        "AuditStream::resume",
        "CertificateBundle::upload",
        "DomainHandover::ensure_allowed",
        "HandoverOffer::accept",
        "HandoverOffer::offer",
        "RegisteredDomain::register",
        "RegisteredDomain::remove",
        "RegisteredDomain::remove_uploaded",
        "RegisteredDomain::serve_uploaded",
        "Tenant::change_compliance",
        "Tenant::change_contact_email",
        "Tenant::change_environment",
        "Tenant::change_locale",
        "Tenant::change_primary_domain",
        "Tenant::change_readable_address",
        "Tenant::change_timezone",
        "Tenant::ensure_changeable",
        "Tenant::rename",
        "Tenant::update_auth_config",
        "Tenant::update_mtls",
        "ZonePolicy::permits_removal",
        "ZonePolicy::permits_write"
      ],
      "carrier": false,
      "context": "tenant",
      "file": "domains/tenant/control.rs",
      "id": "TenantControl"
    },
    {
      "asked_by": [
        "FederatedIdpConnection::activate",
        "FederatedIdpConnection::change_assurance_trust",
        "FederatedIdpConnection::change_domains",
        "FederatedIdpConnection::change_email_trust",
        "FederatedIdpConnection::create",
        "FederatedIdpConnection::delete",
        "FederatedIdpConnection::disable",
        "FederatedIdpConnection::import_metadata",
        "FederatedIdpConnection::map_provider_groups",
        "FederatedIdpConnection::provision_new_accounts",
        "FederatedIdpConnection::rename",
        "FederatedIdpConnection::replace_attribute_mapping",
        "FederatedIdpConnection::roll_over_certificate",
        "FederatedIdpConnection::stop_mapping_groups",
        "FederatedIdpConnection::stop_provisioning",
        "FederatedIdpConnection::update_config",
        "MappingRule::checked",
        "SamlServiceProvider::activate",
        "SamlServiceProvider::create",
        "SamlServiceProvider::delete",
        "SamlServiceProvider::disable",
        "SamlServiceProvider::update",
        "ScimEndpoint::change_settings",
        "ScimEndpoint::create",
        "ScimEndpoint::disable",
        "ScimEndpoint::enable",
        "ScimEndpoint::rotate_token"
      ],
      "carrier": false,
      "context": "federation",
      "file": "domains/federation/control.rs",
      "id": "FederationControl"
    },
    {
      "asked_by": [
        "IntegrationAccount::connect",
        "IntegrationAccount::disable",
        "IntegrationAccount::enable",
        "IntegrationAccount::ensure_owner_or_manager",
        "IntegrationAccount::keep_to_owner",
        "IntegrationAccount::limit_to",
        "IntegrationAccount::rename",
        "IntegrationAccount::replace_credential",
        "IntegrationAccount::share_with_tenant",
        "OperationRiskOverride::change",
        "OperationRiskOverride::raise",
        "OperationRiskOverride::remove",
        "StepApprover::assumed",
        "StepApprover::of",
        "StepApprover::present",
        "Workflow::archive",
        "Workflow::change_run_limit",
        "Workflow::change_trigger",
        "Workflow::create",
        "Workflow::delete_flow",
        "Workflow::ensure_deletable_by",
        "Workflow::flow",
        "Workflow::next_draft",
        "Workflow::publish",
        "Workflow::rename",
        "Workflow::replace_graph",
        "WorkflowExecution::cancel",
        "WorkflowExecution::ensure_cancellable_by",
        "WorkflowExecution::restart",
        "WorkflowExecution::start_by_hand",
        "WorkflowExecution::viewed_by",
        "WorkflowTriggerSecret::issue",
        "WorkflowTriggerSecret::revoke",
        "WorkflowTriggerSecret::rotate"
      ],
      "carrier": false,
      "context": "workflows",
      "file": "domains/workflows/control.rs",
      "id": "WorkflowControl"
    },
    {
      "asked_by": [
        "WorkflowExecution::approve",
        "WorkflowExecution::deny",
        "WorkflowExecution::shown_to"
      ],
      "carrier": false,
      "context": "workflows",
      "file": "domains/workflows/control.rs",
      "id": "StepApprover"
    },
    {
      "asked_by": [
        "AgentChannel::close",
        "AgentChannel::ensure_closable_by",
        "AgentChannel::open",
        "AgentCredential::revoke",
        "AgentCredential::rotate",
        "AgentIdentity::accept_ownership",
        "AgentIdentity::clear_attestation_policy",
        "AgentIdentity::contain",
        "AgentIdentity::create",
        "AgentIdentity::delete",
        "AgentIdentity::offer_ownership",
        "AgentIdentity::record_containment",
        "AgentIdentity::require_reattestation",
        "AgentIdentity::resume",
        "AgentIdentity::revoke",
        "AgentIdentity::transfer_ownership",
        "AgentIdentity::trust_attestation",
        "AgentIdentity::update_details",
        "AgentIdentity::withdraw_offer",
        "AgentRun::order_cancel",
        "AgentRun::pause",
        "AgentRun::resume",
        "AgentRun::revise_pending",
        "AgentSighting::dismiss",
        "AgentSighting::register",
        "AgentTool::delete",
        "AgentTool::disable",
        "AgentTool::edit",
        "AgentTool::enable",
        "AgentTool::register",
        "Approver::assumed",
        "Approver::of",
        "Approver::present",
        "DelegationRequest::deny",
        "ExposureReset::ordered",
        "FleetSuspension::ordered",
        "HeldBy::worked_out",
        "ModelProvider::change_clearance",
        "ModelProvider::change_model",
        "ModelProvider::create",
        "ModelProvider::delete",
        "ModelProvider::disable",
        "ModelProvider::enable",
        "ModelProvider::record_test_result",
        "ModelProvider::rotate_key",
        "RelationChange::grant",
        "RelationChange::revoke",
        "ReviewAssignment::assign",
        "ReviewAssignment::end",
        "TaskTemplate::approve",
        "TaskTemplate::propose",
        "TaskTemplate::retire"
      ],
      "carrier": false,
      "context": "agents",
      "file": "domains/agents/identity/control.rs",
      "id": "AgentControl"
    },
    {
      "asked_by": [
        "ApprovalRequest::approve",
        "ApprovalRequest::deny"
      ],
      "carrier": false,
      "context": "agents",
      "file": "domains/agents/oversight/approval/parties.rs",
      "id": "Approver"
    },
    {
      "asked_by": [
        "CloudAccount::attach_credential",
        "CloudAccount::begin",
        "CloudAccount::disconnect",
        "MemberNotificationPreferences::change_channel",
        "MemberNotificationPreferences::for_member",
        "NotificationDestination::add",
        "NotificationDestination::pause",
        "NotificationDestination::reconfigure",
        "NotificationDestination::remove",
        "NotificationDestination::resume",
        "OrgAccountControl::new",
        "OrgApiKey::create",
        "OrgApiKey::revoke",
        "OrgBranding::change_logo",
        "OrgBranding::change_primary_color",
        "OrgBranding::change_sender_name",
        "OrgBranding::reset",
        "OrgConsentRecord::record",
        "OrgErasureRequest::submit",
        "OrgIdentityProvider::add",
        "OrgIdentityProvider::change",
        "OrgIdentityProvider::remove",
        "OrgIdentityProvider::switch",
        "OrgInvitation::create",
        "OrgInvitation::revoke",
        "OrgInvitation::rotate_token",
        "OrgSession::revoke",
        "OrgSubscription::choose_plan",
        "OrgTenantGrant::ensure_withdrawable",
        "OrgUser::change_display_name",
        "OrgUser::change_email",
        "OrgUser::change_password",
        "OrgUser::change_preferences",
        "OrgUser::change_role",
        "OrgUser::change_status",
        "OrgUser::hand_ownership_to",
        "OrgUser::invite",
        "OrgUser::remove",
        "OrgUser::reopen_for_invitation",
        "Organization::add_tenant",
        "Organization::change_contact_email",
        "Organization::change_display_name",
        "Organization::change_status",
        "Organization::remove_tenant",
        "Organization::rename",
        "Organization::replace_auth_config",
        "authority_in",
        "ensure_in_person",
        "ensure_may_act_on",
        "ensure_may_act_on_others",
        "ensure_may_edit_profile",
        "ensure_may_take_over",
        "ensure_platform_or_may",
        "through AddedBy",
        "through GrantRequest",
        "through LinkRemoval"
      ],
      "carrier": false,
      "context": "organization",
      "file": "domains/organization/members/control.rs",
      "id": "OrgControl"
    },
    {
      "asked_by": [
        "OrgApiKey::revoke",
        "OrgInvitation::revoke",
        "OrgSession::revoke",
        "OrgTenantGrant::ensure_withdrawable",
        "Organization::add_tenant",
        "Organization::change_status",
        "Organization::remove_tenant",
        "ensure_platform_or_may",
        "through LinkRemoval"
      ],
      "carrier": false,
      "context": "kernel",
      "file": "types/choice/acted_by.rs",
      "id": "ActedBy"
    },
    {
      "asked_by": [
        "Tenant::activate",
        "Tenant::archive",
        "Tenant::delete",
        "Tenant::delete_early",
        "Tenant::provision",
        "Tenant::reactivate",
        "Tenant::restore",
        "Tenant::suspend",
        "TenantClone::start",
        "ensure_may_take"
      ],
      "carrier": false,
      "context": "kernel",
      "file": null,
      "id": "Steward"
    },
    {
      "asked_by": [
        "DeviceChange::trust",
        "OrgSession::keep_through_own_removal",
        "OrgUser::vouched_address",
        "Session::keep_through_own_removal",
        "TrustedDevice::trust",
        "through AccountKeeper",
        "through ProfileEditor",
        "through SignedInPerson"
      ],
      "carrier": false,
      "context": "authentication",
      "file": "domains/authentication/sessions/sign_in_progress.rs",
      "id": "SignedIn"
    },
    {
      "asked_by": [
        "ConsentRecord::record",
        "DataExportRequest::download",
        "DataExportRequest::request",
        "DeviceAuthorization::approve",
        "DeviceAuthorization::deny",
        "ErasureRequest::submit",
        "OAuthConsent::extend_scopes",
        "OAuthConsent::grant",
        "OAuthConsent::revoke",
        "ProvenAccount::of",
        "SupportImpersonation::approve",
        "SupportImpersonation::decline",
        "SupportImpersonation::end",
        "SupportImpersonation::ensure_usable",
        "SupportImpersonation::request",
        "TenantAccess::authority_of",
        "acting_as",
        "ensure_holder"
      ],
      "carrier": false,
      "context": "identity",
      "file": "domains/identity/account/control.rs",
      "id": "SignedInPerson"
    },
    {
      "asked_by": [
        "FederatedLink::reconfirm",
        "through FactorSetupProof",
        "through RecentProof"
      ],
      "carrier": false,
      "context": "authentication",
      "file": "domains/authentication/sessions/fresh_sign_in.rs",
      "id": "FreshSignIn"
    },
    {
      "asked_by": [
        "AuditStream::create",
        "AuditStream::reconfigure",
        "BrandingControl::ensure_proved_recently",
        "LdapClientCertificate::issue",
        "OrgSession::keep_through_own_change",
        "PasswordChange::by_holder",
        "PendingEmailChange::create",
        "Session::keep_through_own_password_change",
        "Tenant::change_compliance",
        "Tenant::update_auth_config",
        "Tenant::update_mtls",
        "TenantControl::ensure_proved_recently",
        "TenantMailProvider::switch_to"
      ],
      "carrier": false,
      "context": "identity",
      "file": "domains/identity/account/control.rs",
      "id": "RecentProof"
    },
    {
      "asked_by": [
        "MfaEnrollment::abandon",
        "MfaEnrollment::begin",
        "PasskeyCredential::register",
        "RecoveryCodeSet::regenerate"
      ],
      "carrier": false,
      "context": "authentication",
      "file": "domains/authentication/sessions/fresh_sign_in.rs",
      "id": "FactorSetupProof"
    },
    {
      "asked_by": [
        "OrgSession::answer",
        "OrgSession::keep_through_own_factor_addition",
        "Session::answer",
        "Session::keep_through_own_factor_addition",
        "Session::resume"
      ],
      "carrier": false,
      "context": "authentication",
      "file": "domains/authentication/sessions/proved_factor.rs",
      "id": "ProvedFactor"
    },
    {
      "asked_by": [
        "AcceptedAddress::proven",
        "AccountAddress::confirm",
        "AccountAddress::verified",
        "InstallerProof::spent_for",
        "Operator::change_verified_email",
        "OrgUser::change_verified_email",
        "OrgUser::reset_password",
        "OrgUser::verify_email",
        "User::change_verified_email",
        "User::provision",
        "User::verify_email"
      ],
      "carrier": false,
      "context": "identity",
      "file": "domains/identity/account/verified_email.rs",
      "id": "VerifiedEmail"
    },
    {
      "asked_by": [
        "OrgUser::confirm_as_installer"
      ],
      "carrier": false,
      "context": "identity",
      "file": "domains/identity/tokens/installation_setup.rs",
      "id": "InstallerProof"
    },
    {
      "asked_by": [
        "OrgUser::accept_invitation",
        "User::join_by_invitation"
      ],
      "carrier": false,
      "context": "identity",
      "file": "domains/identity/invitations/route.rs",
      "id": "AcceptedAddress"
    },
    {
      "asked_by": [
        "Delegation::revoke",
        "Delegation::revoke_resource"
      ],
      "carrier": false,
      "context": "agents",
      "file": "domains/agents/authority/delegation/record.rs",
      "id": "Revoker"
    },
    {
      "asked_by": [
        "AgentIdentity::suspend"
      ],
      "carrier": false,
      "context": "agents",
      "file": "domains/agents/identity/agent.rs",
      "id": "SuspendedBy"
    },
    {
      "asked_by": [
        "AgentIdentity::ensure_trusts",
        "AgentIdentity::record_attestation"
      ],
      "carrier": false,
      "context": "agents",
      "file": "domains/agents/identity/attestation.rs",
      "id": "AttestedIdentity"
    },
    {
      "asked_by": [
        "AgentRun::approve_pending"
      ],
      "carrier": false,
      "context": "agents",
      "file": "domains/agents/execution/run/call.rs",
      "id": "ReleasedCall"
    },
    {
      "asked_by": [
        "AgentRun::deny_pending",
        "AgentRun::reply_to_pending"
      ],
      "carrier": false,
      "context": "agents",
      "file": "domains/agents/execution/run/call.rs",
      "id": "DeniedCall"
    },
    {
      "asked_by": [
        "ApprovalRequest::supersede"
      ],
      "carrier": false,
      "context": "agents",
      "file": "domains/agents/execution/run/call.rs",
      "id": "RevisedCall"
    },
    {
      "asked_by": [
        "AgentRun::announce_cancel_request",
        "AgentRun::cancel",
        "RunCancelled::of"
      ],
      "carrier": false,
      "context": "agents",
      "file": "domains/agents/execution/run/cancel.rs",
      "id": "CancelOrder"
    },
    {
      "asked_by": [
        "ApprovalRequest::withdraw"
      ],
      "carrier": false,
      "context": "agents",
      "file": "domains/agents/execution/run/cancel.rs",
      "id": "RunCancelled"
    },
    {
      "asked_by": [
        "ActionParties::behind",
        "ApprovalRequest::consume",
        "ApprovalRequest::grants_action_at",
        "ApprovalRequest::release"
      ],
      "carrier": false,
      "context": "agents",
      "file": "domains/agents/oversight/approval/authority.rs",
      "id": "ActionAuthority"
    },
    {
      "asked_by": [
        "Delegation::grant_resource",
        "ensure_within"
      ],
      "carrier": false,
      "context": "agents",
      "file": "domains/agents/authority/delegation/ceiling.rs",
      "id": "ResourceCeiling"
    },
    {
      "asked_by": [
        "CanaryIssue::issue",
        "EgressPolicy::change_max_data_class",
        "EgressPolicy::create",
        "EgressPolicy::delete",
        "EgressPolicy::rename",
        "EgressPolicy::replace_destinations",
        "LogShippingTarget::change_settings",
        "LogShippingTarget::create",
        "LogShippingTarget::delete",
        "LogShippingTarget::pause",
        "LogShippingTarget::rename",
        "LogShippingTarget::resume",
        "Pipeline::activate",
        "Pipeline::add_stage",
        "Pipeline::delete",
        "Pipeline::disable",
        "Pipeline::disable_stage",
        "Pipeline::enable_stage",
        "Pipeline::reconfigure_stage",
        "Pipeline::remove_stage",
        "Pipeline::rename",
        "Pipeline::reorder_stages",
        "Pipeline::with_defaults",
        "PrivateConnector::change_scope",
        "PrivateConnector::create",
        "PrivateConnector::delete",
        "PrivateConnector::revoke",
        "Route::activate",
        "Route::change_conditions",
        "Route::change_hosts",
        "Route::change_methods",
        "Route::change_path",
        "Route::change_policy",
        "Route::change_priority",
        "Route::create",
        "Route::declare_action_class",
        "Route::declare_data_class",
        "Route::declare_reach",
        "Route::delete",
        "Route::disable",
        "Route::ensure_deletable",
        "Route::move_to_pipeline",
        "Route::move_to_service",
        "Route::rename",
        "Route::replace_parameter_rules",
        "Service::accept_app_sign_in_of",
        "Service::activate",
        "Service::change_app_sign_in",
        "Service::change_health_check",
        "Service::create",
        "Service::delete",
        "Service::disable",
        "Service::rename",
        "Service::replace_upstream",
        "StreamRoute::activate",
        "StreamRoute::change_admission",
        "StreamRoute::change_sni",
        "StreamRoute::change_timeouts",
        "StreamRoute::create",
        "StreamRoute::delete",
        "StreamRoute::disable",
        "StreamRoute::rename",
        "StreamRoute::replace_backends",
        "WasmModuleUpload::admit"
      ],
      "carrier": false,
      "context": "routing",
      "file": "domains/routing/control.rs",
      "id": "RoutingControl"
    },
    {
      "asked_by": [
        "EventSchema::add_version",
        "EventSchema::delete",
        "Subscription::delete",
        "Subscription::pause",
        "Subscription::resume",
        "Subscription::rotate_push_secret",
        "Topic::archive",
        "Topic::change_retention",
        "Topic::change_schema",
        "Topic::delete",
        "Topic::pause",
        "Topic::raise_data_class",
        "Topic::resume",
        "through MessagingCreator",
        "through MessagingReader",
        "through Subscriber"
      ],
      "carrier": false,
      "context": "messaging",
      "file": "domains/messaging/control.rs",
      "id": "MessagingControl"
    },
    {
      "asked_by": [
        "WebhookSubscription::create",
        "WebhookSubscription::delete",
        "WebhookSubscription::pause",
        "WebhookSubscription::resume",
        "WebhookSubscription::rotate_secret",
        "WebhookSubscription::update"
      ],
      "carrier": false,
      "context": "webhooks",
      "file": "domains/webhooks/control.rs",
      "id": "WebhookControl"
    },
    {
      "asked_by": [
        "Consumer::change_clearance",
        "Consumer::change_credential_expiry",
        "Consumer::change_description",
        "Consumer::change_quota",
        "Consumer::create",
        "Consumer::delete",
        "Consumer::disable",
        "Consumer::enable",
        "Consumer::end_credential_overlap",
        "Consumer::rename",
        "ConsumerTakeover::of"
      ],
      "carrier": false,
      "context": "consumers",
      "file": "domains/consumers/control.rs",
      "id": "ConsumerControl"
    },
    {
      "asked_by": [
        "User::change_locale",
        "User::change_preferences",
        "User::change_timezone",
        "User::rename",
        "User::update_details"
      ],
      "carrier": false,
      "context": "identity",
      "file": "domains/identity/account/control.rs",
      "id": "ProfileEditor"
    },
    {
      "asked_by": [
        "DelegationRequest::ask",
        "ReviewAssignment::verdict",
        "RunStarter::agent",
        "through OwnedTokenRequest"
      ],
      "carrier": false,
      "context": "agents",
      "file": "domains/agents/identity/acting.rs",
      "id": "ActingAgent"
    },
    {
      "asked_by": [
        "Consumer::rotate_credential"
      ],
      "carrier": false,
      "context": "consumers",
      "file": "domains/consumers/takeover.rs",
      "id": "ConsumerTakeover"
    },
    {
      "asked_by": [
        "through MessagingCreator",
        "through MessagingReader",
        "through Subscriber"
      ],
      "carrier": false,
      "context": "consumers",
      "file": "domains/consumers/authority.rs",
      "id": "ConsumerAuthority"
    },
    {
      "asked_by": [
        "Delegation::grant",
        "Delegation::renew",
        "DelegationRequest::approve"
      ],
      "carrier": false,
      "context": "agents",
      "file": "domains/agents/authority/delegation/held_by.rs",
      "id": "HeldBy"
    },
    {
      "asked_by": [
        "AgentRun::start",
        "AgentRun::start_without_tools",
        "ensure_startable"
      ],
      "carrier": false,
      "context": "agents",
      "file": "domains/agents/execution/run/starter.rs",
      "id": "RunStarter"
    },
    {
      "asked_by": [
        "ChangedBy::of",
        "DeviceChange::revoke",
        "LdapClientCertificate::revoke",
        "PasskeyCredential::remove",
        "PasskeyCredential::rename",
        "Session::revoke",
        "TrustedDevice::rename",
        "TrustedDevice::revoke"
      ],
      "carrier": false,
      "context": "authentication",
      "file": "domains/authentication/keeper.rs",
      "id": "AccountKeeper"
    },
    {
      "asked_by": [
        "MfaEnrollment::withdraw",
        "PasskeyCredential::ensure_withdrawn_by"
      ],
      "carrier": false,
      "context": "authentication",
      "file": "domains/authentication/keeper.rs",
      "id": "FactorWithdrawal"
    },
    {
      "asked_by": [
        "Session::create"
      ],
      "carrier": false,
      "context": "authentication",
      "file": "domains/authentication/sessions/account_check.rs",
      "id": "MaySignIn"
    },
    {
      "asked_by": [
        "Session::hand_over",
        "Session::rotate",
        "Session::signed_in"
      ],
      "carrier": false,
      "context": "authentication",
      "file": "domains/authentication/sessions/account_check.rs",
      "id": "SessionCheck"
    },
    {
      "asked_by": [
        "OrgSession::signed_in",
        "OrgSession::switch_to"
      ],
      "carrier": false,
      "context": "organization",
      "file": "domains/organization/access/session_check.rs",
      "id": "OrgSessionCheck"
    },
    {
      "asked_by": [
        "MfaEnrollment::turn_off_with_code",
        "MfaEnrollment::verify",
        "ProvedFactor::by_code",
        "RecoveryCodeSet::generate"
      ],
      "carrier": false,
      "context": "authentication",
      "file": "domains/authentication/mfa/answered_code.rs",
      "id": "AnsweredCode"
    },
    {
      "asked_by": [
        "OrgSession::create"
      ],
      "carrier": false,
      "context": "organization",
      "file": "domains/organization/access/sign_in_start.rs",
      "id": "OrgSignInStart"
    },
    {
      "asked_by": [
        "ApiKey::create",
        "ApiKey::revoke",
        "ApiKey::update",
        "InitialAccessToken::issue",
        "InitialAccessToken::revoke",
        "OAuthClient::create",
        "OAuthClient::revoke",
        "OAuthClient::rotate_secret",
        "OAuthClient::update"
      ],
      "carrier": false,
      "context": "oauth",
      "file": "domains/oauth/control.rs",
      "id": "OAuthControl"
    },
    {
      "asked_by": [
        "OAuthClient::register"
      ],
      "carrier": false,
      "context": "oauth",
      "file": "domains/oauth/clients/registration.rs",
      "id": "RegistrationAdmission"
    },
    {
      "asked_by": [
        "OAuthClient::deregister",
        "OAuthClient::update_registration"
      ],
      "carrier": false,
      "context": "oauth",
      "file": "domains/oauth/clients/registration.rs",
      "id": "SelfManagement"
    },
    {
      "asked_by": [
        "EveryKeyRevocation::revoke",
        "ImpersonationGrant::act_as",
        "ImpersonationGrant::create",
        "ImpersonationGrant::revoke",
        "Operator::ask_email_change",
        "Operator::create",
        "Operator::disable",
        "Operator::enable",
        "OperatorApiKey::create",
        "OperatorApiKey::revoke",
        "OperatorNotificationPreferences::change_channel",
        "OperatorNotificationPreferences::for_operator",
        "OrgSubscription::arrange"
      ],
      "carrier": false,
      "context": "operator",
      "file": "domains/operator/control.rs",
      "id": "OperatorAuthority"
    },
    {
      "asked_by": [
        "FederatedLink::link"
      ],
      "carrier": false,
      "context": "federation",
      "file": "domains/federation/link.rs",
      "id": "LinkGrounds"
    },
    {
      "asked_by": [
        "FederatedLink::remove"
      ],
      "carrier": false,
      "context": "federation",
      "file": "domains/federation/link.rs",
      "id": "UnlinkGrounds"
    },
    {
      "asked_by": [
        "EmailTemplate::custom",
        "EmailTemplate::remove",
        "TenantBranding::change_background_color",
        "TenantBranding::change_custom_css",
        "TenantBranding::change_logo",
        "TenantBranding::change_primary_color",
        "TenantBranding::change_sender_name",
        "TenantBranding::send_from",
        "TenantBranding::send_from_platform",
        "TenantBranding::upload_logo",
        "TenantMailProvider::switch_to"
      ],
      "carrier": false,
      "context": "branding",
      "file": "domains/branding/control.rs",
      "id": "BrandingControl"
    },
    {
      "asked_by": [
        "AlgorithmMigration::cancel",
        "AlgorithmMigration::complete",
        "AlgorithmMigration::plan",
        "AlgorithmMigration::promote",
        "AlgorithmMigration::rollback",
        "AlgorithmMigration::start",
        "SigningKeySet::add_key",
        "SigningKeySet::revoke_key",
        "SigningKeySet::revoke_migrated_key",
        "SigningKeySet::rotate_out",
        "SigningKeySet::rotate_to"
      ],
      "carrier": false,
      "context": "crypto",
      "file": "domains/crypto/control.rs",
      "id": "CryptoControlCheck"
    },
    {
      "asked_by": [
        "ClassificationRuleSet::add_rule",
        "ClassificationRuleSet::change_rule",
        "ClassificationRuleSet::empty",
        "ClassificationRuleSet::remove_rule"
      ],
      "carrier": false,
      "context": "data_classification",
      "file": "domains/data_classification/control.rs",
      "id": "ClassificationControlCheck"
    },
    {
      "asked_by": [
        "SignalStream::add_subject",
        "SignalStream::change_authorization",
        "SignalStream::change_delivery_method",
        "SignalStream::change_endpoint",
        "SignalStream::delete",
        "SignalStream::disable",
        "SignalStream::pause",
        "SignalStream::register",
        "SignalStream::remove_subject",
        "SignalStream::replace_signal_types",
        "SignalStream::request_verification",
        "SignalStream::resume",
        "SignalStream::update"
      ],
      "carrier": false,
      "context": "signals",
      "file": "domains/signals/control.rs",
      "id": "SignalsControlCheck"
    },
    {
      "asked_by": [
        "Invitation::rotate_token",
        "User::import",
        "User::invite",
        "User::register",
        "UserImport::start"
      ],
      "carrier": false,
      "context": "identity",
      "file": "domains/identity/account/creator.rs",
      "id": "AccountCreator"
    },
    {
      "asked_by": [
        "Group::delete_by_directory",
        "Group::from_directory",
        "Group::rename_by_directory",
        "GroupMembership::end_by_directory",
        "GroupMembership::from_directory"
      ],
      "carrier": false,
      "context": "authorization",
      "file": "domains/authorization/directory.rs",
      "id": "TenantDirectory"
    },
    {
      "asked_by": [
        "AttributeDefinition::archive",
        "AttributeDefinition::change_bounds",
        "AttributeDefinition::change_control",
        "AttributeDefinition::change_max_length",
        "AttributeDefinition::change_visibility",
        "AttributeDefinition::declare",
        "AttributeDefinition::delete",
        "AttributeDefinition::describe",
        "AttributeDefinition::rename",
        "AttributeDefinition::replace_options",
        "AttributeDefinition::restore",
        "AttributeDefinition::update"
      ],
      "carrier": false,
      "context": "identity",
      "file": "domains/identity/attribute/schema_control.rs",
      "id": "SchemaControlCheck"
    },
    {
      "asked_by": [
        "Invitation::accept",
        "Invitation::create"
      ],
      "carrier": false,
      "context": "identity",
      "file": "domains/identity/invitations/invited_role.rs",
      "id": "InvitedRole"
    },
    {
      "asked_by": [
        "LinkedIdentity::add_link",
        "LinkedIdentity::create",
        "through LinkRemoval"
      ],
      "carrier": false,
      "context": "organization",
      "file": "domains/organization/members/linked_identity.rs",
      "id": "ProvenAccount"
    },
    {
      "asked_by": [
        "OrgConsentRecord::withdraw_for",
        "OrgErasureRequest::cancel_for",
        "OrgErasureRequest::hold",
        "OrgErasureRequest::release",
        "OrgErasureRequest::submit_for",
        "through AccountControlCheck"
      ],
      "carrier": false,
      "context": "organization",
      "file": "domains/organization/members/account_control.rs",
      "id": "OrgAccountControl"
    },
    {
      "asked_by": [
        "DirectoryServiceAccount::change_scope",
        "DirectoryServiceAccount::create",
        "DirectoryServiceAccount::delete",
        "DirectoryServiceAccount::disable",
        "DirectoryServiceAccount::enable",
        "DirectoryServiceAccount::rotate_secret"
      ],
      "carrier": false,
      "context": "authentication",
      "file": "domains/authentication/directory_service/control.rs",
      "id": "DirectoryControlCheck"
    },
    {
      "asked_by": [
        "Organization::change_plan"
      ],
      "carrier": false,
      "context": "organization",
      "file": "domains/organization/billing/subscription.rs",
      "id": "PlanMove"
    },
    {
      "asked_by": [
        "AuditLogExport::hand_out",
        "AuditLogExport::request"
      ],
      "carrier": false,
      "context": "audit",
      "file": "domains/audit/access.rs",
      "id": "AuditLogAccess"
    },
    {
      "asked_by": [
        "AgentCredential::mint"
      ],
      "carrier": true,
      "context": "agents",
      "file": "domains/agents/identity/credential.rs",
      "id": "MintAgentCredentialParams"
    },
    {
      "asked_by": [
        "Delegation::grant_owned_within"
      ],
      "carrier": true,
      "context": "agents",
      "file": "domains/agents/authority/delegation/record.rs",
      "id": "OwnedTokenRequest"
    },
    {
      "asked_by": [
        "AuthorizationCode::consume"
      ],
      "carrier": true,
      "context": "oauth",
      "file": "domains/oauth/grants/authorization_code.rs",
      "id": "CodeExchange"
    },
    {
      "asked_by": [
        "LinkedIdentity::remove_link"
      ],
      "carrier": true,
      "context": "organization",
      "file": "domains/organization/members/linked_identity.rs",
      "id": "LinkRemoval"
    },
    {
      "asked_by": [
        "OrgUser::create",
        "ensure_may_bring_in"
      ],
      "carrier": true,
      "context": "organization",
      "file": "domains/organization/members/org_user_authority.rs",
      "id": "AddedBy"
    },
    {
      "asked_by": [
        "OrgTenantGrant::issue"
      ],
      "carrier": true,
      "context": "organization",
      "file": "domains/organization/members/tenant_grant.rs",
      "id": "GrantRequest"
    },
    {
      "asked_by": [
        "BreakGlassGrant::create"
      ],
      "carrier": true,
      "context": "authorization",
      "file": "domains/authorization/break_glass.rs",
      "id": "NewBreakGlass"
    },
    {
      "asked_by": [
        "EventSchema::register",
        "Topic::create"
      ],
      "carrier": true,
      "context": "messaging",
      "file": "domains/messaging/control.rs",
      "id": "MessagingCreator"
    },
    {
      "asked_by": [
        "Subscription::replay_dead_letter",
        "Topic::ensure_readable_by"
      ],
      "carrier": true,
      "context": "messaging",
      "file": "domains/messaging/control.rs",
      "id": "MessagingReader"
    },
    {
      "asked_by": [
        "Subscription::create"
      ],
      "carrier": true,
      "context": "messaging",
      "file": "domains/messaging/subscription.rs",
      "id": "Subscriber"
    }
  ],
  "uses": [
    {
      "from": "agents",
      "lines": 2,
      "to": "authentication"
    },
    {
      "from": "agents",
      "lines": 31,
      "to": "authorization"
    },
    {
      "from": "agents",
      "lines": 2,
      "to": "crypto"
    },
    {
      "from": "agents",
      "lines": 20,
      "to": "data_classification"
    },
    {
      "from": "agents",
      "lines": 2,
      "to": "identity"
    },
    {
      "from": "agents",
      "lines": 4,
      "to": "messaging"
    },
    {
      "from": "agents",
      "lines": 1,
      "to": "organization"
    },
    {
      "from": "agents",
      "lines": 9,
      "to": "routing"
    },
    {
      "from": "agents",
      "lines": 1,
      "to": "tenant"
    },
    {
      "from": "authentication",
      "lines": 43,
      "to": "identity"
    },
    {
      "from": "authorization",
      "lines": 1,
      "to": "audit"
    },
    {
      "from": "authorization",
      "lines": 8,
      "to": "authentication"
    },
    {
      "from": "authorization",
      "lines": 2,
      "to": "crypto"
    },
    {
      "from": "authorization",
      "lines": 7,
      "to": "data_classification"
    },
    {
      "from": "authorization",
      "lines": 25,
      "to": "identity"
    },
    {
      "from": "authorization",
      "lines": 2,
      "to": "signals"
    },
    {
      "from": "branding",
      "lines": 2,
      "to": "authorization"
    },
    {
      "from": "branding",
      "lines": 2,
      "to": "identity"
    },
    {
      "from": "branding",
      "lines": 3,
      "to": "tenant"
    },
    {
      "from": "consumers",
      "lines": 13,
      "to": "authorization"
    },
    {
      "from": "consumers",
      "lines": 5,
      "to": "data_classification"
    },
    {
      "from": "federation",
      "lines": 12,
      "to": "authentication"
    },
    {
      "from": "federation",
      "lines": 24,
      "to": "authorization"
    },
    {
      "from": "federation",
      "lines": 14,
      "to": "identity"
    },
    {
      "from": "federation",
      "lines": 2,
      "to": "tenant"
    },
    {
      "from": "messaging",
      "lines": 6,
      "to": "authorization"
    },
    {
      "from": "messaging",
      "lines": 5,
      "to": "consumers"
    },
    {
      "from": "messaging",
      "lines": 4,
      "to": "data_classification"
    },
    {
      "from": "notifications",
      "lines": 4,
      "to": "authorization"
    },
    {
      "from": "notifications",
      "lines": 1,
      "to": "branding"
    },
    {
      "from": "notifications",
      "lines": 1,
      "to": "operator"
    },
    {
      "from": "notifications",
      "lines": 5,
      "to": "organization"
    },
    {
      "from": "oauth",
      "lines": 11,
      "to": "authentication"
    },
    {
      "from": "oauth",
      "lines": 5,
      "to": "authorization"
    },
    {
      "from": "oauth",
      "lines": 7,
      "to": "identity"
    },
    {
      "from": "oauth",
      "lines": 3,
      "to": "routing"
    },
    {
      "from": "operator",
      "lines": 1,
      "to": "audit"
    },
    {
      "from": "operator",
      "lines": 1,
      "to": "authentication"
    },
    {
      "from": "operator",
      "lines": 1,
      "to": "authorization"
    },
    {
      "from": "operator",
      "lines": 3,
      "to": "identity"
    },
    {
      "from": "operator",
      "lines": 2,
      "to": "tenant"
    },
    {
      "from": "organization",
      "lines": 1,
      "to": "audit"
    },
    {
      "from": "organization",
      "lines": 44,
      "to": "authentication"
    },
    {
      "from": "organization",
      "lines": 7,
      "to": "authorization"
    },
    {
      "from": "organization",
      "lines": 3,
      "to": "federation"
    },
    {
      "from": "organization",
      "lines": 40,
      "to": "identity"
    },
    {
      "from": "organization",
      "lines": 1,
      "to": "operator"
    },
    {
      "from": "organization",
      "lines": 13,
      "to": "tenant"
    },
    {
      "from": "proxy",
      "lines": 7,
      "to": "agents"
    },
    {
      "from": "proxy",
      "lines": 1,
      "to": "audit"
    },
    {
      "from": "proxy",
      "lines": 6,
      "to": "authentication"
    },
    {
      "from": "proxy",
      "lines": 16,
      "to": "authorization"
    },
    {
      "from": "proxy",
      "lines": 1,
      "to": "crypto"
    },
    {
      "from": "proxy",
      "lines": 3,
      "to": "data_classification"
    },
    {
      "from": "proxy",
      "lines": 15,
      "to": "routing"
    },
    {
      "from": "routing",
      "lines": 5,
      "to": "authorization"
    },
    {
      "from": "routing",
      "lines": 5,
      "to": "data_classification"
    },
    {
      "from": "tenant",
      "lines": 2,
      "to": "audit"
    },
    {
      "from": "tenant",
      "lines": 12,
      "to": "authentication"
    },
    {
      "from": "tenant",
      "lines": 4,
      "to": "authorization"
    },
    {
      "from": "tenant",
      "lines": 9,
      "to": "identity"
    },
    {
      "from": "webhooks",
      "lines": 6,
      "to": "authorization"
    },
    {
      "from": "webhooks",
      "lines": 1,
      "to": "identity"
    },
    {
      "from": "webhooks",
      "lines": 2,
      "to": "notifications"
    },
    {
      "from": "webhooks",
      "lines": 4,
      "to": "organization"
    },
    {
      "from": "workflows",
      "lines": 24,
      "to": "agents"
    },
    {
      "from": "workflows",
      "lines": 16,
      "to": "authorization"
    },
    {
      "from": "workflows",
      "lines": 12,
      "to": "data_classification"
    },
    {
      "from": "workflows",
      "lines": 1,
      "to": "notifications"
    },
    {
      "from": "workflows",
      "lines": 1,
      "to": "organization"
    }
  ]
}
;

//! The actions each area of the platform has.

/// Actions on user resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UserAction {
    /// Full control. Covers every other user action.
    Manage,
    /// View user profiles and status.
    View,
    /// Create new users.
    Create,
    /// Update user profiles, including which roles they hold.
    ///
    /// A person's roles are part of their record. So giving and taking a
    /// person's roles needs this, not [`RoleAction::Assign`]. That one covers
    /// roles on groups.
    Update,
    /// Deactivate user accounts.
    Deactivate,
    /// Permanently delete user accounts.
    Delete,
}

/// Actions on role resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RoleAction {
    /// Full control. Covers every other role action.
    Manage,
    /// View roles and assignments.
    View,
    /// Create new roles.
    Create,
    /// Update role permissions.
    Update,
    /// Delete roles.
    Delete,
    /// Give roles to groups and take them away, and manage who is in a group.
    ///
    /// Giving a role to one person is [`UserAction::Update`], because it
    /// edits that person's record. This one is about groups.
    Assign,
    /// Give out the tenant's own app permissions without holding them.
    ///
    /// Anyone else may only put into a role, or hand to a person, the app
    /// permissions they hold themselves. Without that rule, Sam may edit
    /// roles and writes himself any permission the tenant's app checks.
    /// This never lets anyone hand out ianua's own permissions they lack.
    Escalate,
}

/// Actions on authentication configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AuthConfigAction {
    /// Full control. Covers every other auth config action.
    Manage,
    /// View authentication settings.
    View,
    /// Modify authentication settings.
    Update,
}

/// Actions on federation resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FederationAction {
    /// Full control. Covers every other federation action.
    Manage,
    /// View federation connections.
    View,
    /// Create new connections.
    Create,
    /// Update existing connections.
    Update,
    /// Delete connections.
    Delete,
}

/// Separates reading individual records from exporting and downloading bulk history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AuditLogAction {
    /// View audit log entries.
    View,
    /// Export the audit log in bulk and download the file. Kept apart from
    /// viewing: a reader who looks up one entry at a time is not handed
    /// every record of the tenant in one file.
    Export,
}

/// Actions on branding resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BrandingAction {
    /// Full control. Covers every other branding action.
    Manage,
    /// View branding configuration.
    View,
    /// Update branding configuration.
    Update,
}

/// Actions on API key and OAuth client resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ApiKeyAction {
    /// Full control. Covers every other API key action.
    Manage,
    /// View API keys and OAuth clients.
    View,
    /// Create new keys and clients.
    Create,
    /// Update existing keys and clients.
    Update,
    /// Revoke existing keys and clients.
    Revoke,
}

/// Actions on compliance configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ComplianceAction {
    /// Full control. Covers every other compliance action.
    Manage,
    /// View compliance posture.
    View,
    /// Update compliance settings.
    Update,
}

/// Actions on the tenant's mTLS trust anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MtlsAction {
    /// Full control. Covers every other mTLS action.
    Manage,
    /// View the mTLS trust anchor configuration.
    View,
    /// Update the mTLS trust anchor configuration.
    Update,
}

/// Actions on SCIM provisioning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ScimAction {
    /// Full control. Covers every other SCIM action.
    Manage,
    /// View SCIM configuration.
    View,
    /// Modify SCIM configuration.
    Configure,
}

/// Actions on signing key and algorithm migration resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CryptoAction {
    /// Full control. Covers every other crypto action.
    Manage,
    /// View signing keys and migrations.
    View,
    /// Rotate or revoke keys, manage migrations.
    Update,
}

/// Actions on data classification rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ClassificationAction {
    /// Full control. Covers every other classification action.
    Manage,
    /// View classification rules.
    View,
    /// Update classification rules.
    Update,
}

/// How sensitive a data class someone may see, beyond the internal data
/// everyone acting in the tenant sees.
///
/// Restricted covers confidential. A run, a model or an approver cleared
/// only for confidential data never sees restricted data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DataAccessAction {
    /// See personal and financial data.
    Confidential,
    /// See secrets and health records, and everything confidential.
    Restricted,
}

/// Actions on the tenant's authorization policy.
///
/// Kept apart from [`RoleAction`] because the policy reaches further. Roles
/// say what a person may do once inside. The policy decides which requests
/// get in at all, so one rule can shut off every route in the tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PolicySetAction {
    /// Full control. Covers every other policy action.
    Manage,
    /// Read the policy and simulate requests against it.
    View,
    /// Edit the draft policy's rules and default action.
    Update,
    /// Move the policy through review, activation and archival.
    Activate,
}

/// Actions on route resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RoutingAction {
    /// Full control. Covers every other routing action.
    Manage,
    /// View routes.
    View,
    /// Create new routes.
    Create,
    /// Update existing routes.
    Update,
    /// Delete routes.
    Delete,
}

/// Actions on proxy pipeline resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PipelineAction {
    /// Full control. Covers every other pipeline action.
    Manage,
    /// View pipeline configuration.
    View,
    /// Modify pipeline stages and status.
    Update,
}

/// Actions on signal stream resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SignalsAction {
    /// Full control. Covers every other signals action.
    Manage,
    /// View signal streams.
    View,
    /// Register, pause, resume, disable, delete streams.
    Update,
}

/// Actions on webhook subscription resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum WebhooksAction {
    /// Full control. Covers every other webhooks action.
    Manage,
    /// View subscriptions and delivery history.
    View,
    /// Create, pause, resume, delete subscriptions.
    Update,
}

/// Permissions governing external clients and their access credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ConsumersAction {
    /// Full control. Covers every other consumer action.
    Manage,
    /// View consumers.
    View,
    /// Create new consumers.
    Create,
    /// Disable, enable, or rotate credentials.
    Update,
    /// Permanently delete a consumer.
    Delete,
}

/// Actions for tenant messaging management.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MessagingAction {
    /// Full control. Covers every other messaging action.
    Manage,
    /// View topics and subscriptions.
    View,
    /// Create topics and subscriptions.
    Create,
    /// Publish messages to topics.
    Publish,
    /// Draw messages from a subscription.
    ///
    /// Kept apart from [`Self::View`] because it moves the subscription on.
    /// Messages Ann pulls are messages the real consumer will not see.
    /// Reading messages and taking them are different rights.
    Consume,
    /// Delete topics and subscriptions.
    Delete,
}

/// Actions on agent identity and delegation resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AgentAction {
    /// Full control. Covers every other agent action.
    Manage,
    /// View agent identities and their delegations.
    View,
    /// Create new agent identities.
    Create,
    /// Suspend, resume, or rename an agent identity.
    Update,
    /// Revoke or delete an agent identity.
    Delete,
    /// Grant delegations to agents.
    Delegate,
    /// Decide a paused action or run that is awaiting human sign-off.
    ///
    /// Kept apart from [`Update`](Self::Update), which opens the request. An
    /// approval is a real check only when the one who asks is not the one who
    /// approves. One permission for both would let Sam approve his own
    /// request.
    Approve,
}

/// Actions on a tenant's custom domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DomainAction {
    /// Full control. Covers every other domain action.
    Manage,
    /// View the tenant's domains and their verification state.
    View,
    /// Add a domain to the tenant.
    Create,
    /// Verify a domain, provision its certificate, or transfer it.
    Update,
    /// Remove a domain from the tenant.
    Delete,
}

/// Actions on a tenant's metrics.
///
/// Metrics are read-only. They come from what the tenant already did, so
/// there is nothing to create or delete. `Manage` exists so this area looks
/// like the others, and a role builder can grant all of it at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MetricsAction {
    /// Full control. Covers every other metrics action.
    Manage,
    /// Read the tenant's metrics overview.
    View,
}

/// Actions on workflows, their executions and the integration accounts they
/// act through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum WorkflowAction {
    /// Full control. Covers every other workflow action.
    Manage,
    /// View workflows and their executions.
    View,
    /// Draft new workflows and versions.
    Create,
    /// Edit, publish and archive versions.
    Update,
    /// Delete workflows.
    Delete,
    /// Start executions by hand, and cancel them.
    Run,
    /// Decide an execution's approval steps.
    ///
    /// Kept apart from [`Run`](Self::Run). A sign-off is a real check only
    /// when it comes from someone other than the one who started the run.
    Approve,
    /// Connect, change and disable integration accounts.
    ConnectAccounts,
}

/// Actions on a tenant's own settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TenantSettingsAction {
    /// Full control. Covers every other settings action.
    Manage,
    /// Read the tenant's settings.
    View,
    /// Change display name, contact address, locale, timezone, primary
    /// domain, or JWT issuer.
    Update,
}

//! Readable names for the records an audit entry points at.

use std::collections::HashMap;

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    AgentCredentialId, AgentId, ApprovalId, ConnectionId, ConsumerId, DelegationId, EventLabel,
    GroupId, ModelProviderId, NotificationId, OAuthClientId, OperatorId, OrgUserId, OrganizationId,
    PrincipalRef, RoleId, UserId,
};

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port resolving an entity's label for an audit payload.
///
/// Labels are captured at **write time** so an audit entry stays truthful after
/// the entity is renamed or deleted. `Ok(None)` means the entity is gone; the
/// caller falls back to rendering the id.
///
/// One resolver with a method per kind rather than a port per kind, so a use
/// case injects it once. Every method takes the tenant whose records it
/// reads; organization and platform records are named by
/// [`ControlPlaneLabelResolver`] instead.
///
/// A resolver call is a fallback: prefer a label the use case already loaded
/// (`role.name()`) over a point-read.
#[async_trait]
pub trait AuditLabelResolver: Send + Sync + TenantScoped {
    /// The label for a tenant user: display name and email.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<EventLabel>, DomainError>;

    /// The label for an authorization role: its name.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn role(
        &self,
        tenant_id: &ScopedTenant,
        role_id: &RoleId,
    ) -> Result<Option<EventLabel>, DomainError>;

    /// The label for a group: its name.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn group(
        &self,
        tenant_id: &ScopedTenant,
        group_id: &GroupId,
    ) -> Result<Option<EventLabel>, DomainError>;

    /// The label for an agent: its name.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn agent(
        &self,
        tenant_id: &ScopedTenant,
        agent_id: &AgentId,
    ) -> Result<Option<EventLabel>, DomainError>;

    /// The label for a delegation, or `None` when it has no human field.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn delegation(
        &self,
        tenant_id: &ScopedTenant,
        delegation_id: &DelegationId,
    ) -> Result<Option<EventLabel>, DomainError>;

    /// The label for an agent credential, or `None` when it has no human
    /// field.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn credential(
        &self,
        tenant_id: &ScopedTenant,
        credential_id: &AgentCredentialId,
    ) -> Result<Option<EventLabel>, DomainError>;

    /// The label for an approval request: the action it gates.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn approval(
        &self,
        tenant_id: &ScopedTenant,
        approval_id: &ApprovalId,
    ) -> Result<Option<EventLabel>, DomainError>;

    /// The label for a model provider: its name.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn model_provider(
        &self,
        tenant_id: &ScopedTenant,
        provider_id: &ModelProviderId,
    ) -> Result<Option<EventLabel>, DomainError>;

    /// The label for an OAuth client: its name.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn oauth_client(
        &self,
        tenant_id: &ScopedTenant,
        client_id: &OAuthClientId,
    ) -> Result<Option<EventLabel>, DomainError>;

    /// The label for a federation connection: its provider name.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn connection(
        &self,
        tenant_id: &ScopedTenant,
        connection_id: &ConnectionId,
    ) -> Result<Option<EventLabel>, DomainError>;

    /// The label for a tenant user's notification: its title.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn notification(
        &self,
        tenant_id: &ScopedTenant,
        notification_id: &NotificationId,
    ) -> Result<Option<EventLabel>, DomainError>;

    /// The label for a consumer: its name.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn consumer(
        &self,
        tenant_id: &ScopedTenant,
        consumer_id: &ConsumerId,
    ) -> Result<Option<EventLabel>, DomainError>;

    /// The label for a tenant: its display name.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn tenant(&self, tenant_id: &ScopedTenant) -> Result<Option<EventLabel>, DomainError>;

    /// The labels of `principals`, read together rather than one lookup
    /// each, for a page that names many. A principal that is gone is left
    /// out, and so is every organization member: their labels come from
    /// [`ControlPlaneLabelResolver::org_users`].
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn principals(
        &self,
        tenant_id: &ScopedTenant,
        principals: &[PrincipalRef],
    ) -> Result<HashMap<PrincipalRef, EventLabel>, DomainError>;

    /// The label for any principal, by its kind.
    ///
    /// An organization member resolves to `None`: their label comes from
    /// [`ControlPlaneLabelResolver::org_user`], keyed by organization, which a
    /// tenant does not supply. Callers fall back to the id, as they do for a
    /// deleted row.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn principal(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
    ) -> Result<Option<EventLabel>, DomainError> {
        match principal {
            PrincipalRef::User(id) => self.user(tenant_id, id).await,
            PrincipalRef::Agent(id) => self.agent(tenant_id, id).await,
            PrincipalRef::Consumer(id) => self.consumer(tenant_id, id).await,
            PrincipalRef::OrgUser(_) => Ok(None),
        }
    }
}

/// Dyn-safe port resolving the label of an organization or platform record
/// for an audit payload.
///
/// Captured at write time and falling back to the id, as
/// [`AuditLabelResolver`] is. Not [`TenantScoped`]: organization members,
/// their notifications, operators and operators' notifications belong to no
/// tenant, so each method takes the organization or operator that owns the
/// record instead.
#[async_trait]
pub trait ControlPlaneLabelResolver: Send + Sync {
    /// The label for a platform operator's notification: its title.
    ///
    /// Separate from [`AuditLabelResolver::notification`] because platform,
    /// organization and tenant notifications live in three tables with
    /// different owning keys.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn platform_notification(
        &self,
        operator_id: &OperatorId,
        notification_id: &NotificationId,
    ) -> Result<Option<EventLabel>, DomainError>;

    /// The label for an organization member's notification: its title.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn org_notification(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
        notification_id: &NotificationId,
    ) -> Result<Option<EventLabel>, DomainError>;

    /// The label for an organization member: display name and email.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn org_user(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
    ) -> Result<Option<EventLabel>, DomainError>;

    /// The labels of the members `org_user_ids` of `organization_id`, read
    /// together. A member who is gone is left out.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn org_users(
        &self,
        organization_id: &OrganizationId,
        org_user_ids: &[OrgUserId],
    ) -> Result<HashMap<OrgUserId, EventLabel>, DomainError>;

    /// The label for a platform operator: display name and email.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn operator(&self, operator_id: &OperatorId) -> Result<Option<EventLabel>, DomainError>;
}

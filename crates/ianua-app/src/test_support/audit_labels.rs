//! A fake that names the records an audit entry points at.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{EventLabel, PrincipalRef};

use crate::test_support::Fake;

/// Resolves every audit label to a fixed, kind-tagged string.
///
/// Use case tests assert *which* label a payload carried, not how it was
/// looked up, so a deterministic per-kind answer is enough. Returns `Some`
/// for every kind; construct with [`FakeAuditLabelResolver::missing`] to
/// exercise the entity-is-gone path where the caller falls back to the id.
pub struct FakeAuditLabelResolver {
    resolves: bool,
}

impl crate::ports::TenantScoped for FakeAuditLabelResolver {}

impl FakeAuditLabelResolver {
    /// A resolver that answers every kind with a fixed label.
    #[must_use]
    pub fn new() -> Self {
        Self { resolves: true }
    }

    /// A resolver that reports every entity as gone, so callers fall back to
    /// rendering the id.
    #[must_use]
    pub fn missing() -> Self {
        Self { resolves: false }
    }

    fn label(&self, kind: &str) -> Option<EventLabel> {
        if !self.resolves {
            return None;
        }
        Some(EventLabel::of(&format!("test {kind}")))
    }
}

impl Default for FakeAuditLabelResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl crate::ports::shared::AuditLabelResolver for FakeAuditLabelResolver {
    async fn user(
        &self,
        _: &crate::tenancy::ScopedTenant,
        _: &ianua_domain::types::UserId,
    ) -> Result<Option<EventLabel>, DomainError> {
        Ok(self.label("user"))
    }

    async fn role(
        &self,
        _: &crate::tenancy::ScopedTenant,
        _: &ianua_domain::types::RoleId,
    ) -> Result<Option<EventLabel>, DomainError> {
        Ok(self.label("role"))
    }

    async fn group(
        &self,
        _: &crate::tenancy::ScopedTenant,
        _: &ianua_domain::types::GroupId,
    ) -> Result<Option<EventLabel>, DomainError> {
        Ok(self.label("group"))
    }

    async fn agent(
        &self,
        _: &crate::tenancy::ScopedTenant,
        _: &ianua_domain::types::AgentId,
    ) -> Result<Option<EventLabel>, DomainError> {
        Ok(self.label("agent"))
    }

    async fn delegation(
        &self,
        _: &crate::tenancy::ScopedTenant,
        _: &ianua_domain::types::DelegationId,
    ) -> Result<Option<EventLabel>, DomainError> {
        Ok(self.label("delegation"))
    }

    async fn credential(
        &self,
        _: &crate::tenancy::ScopedTenant,
        _: &ianua_domain::types::AgentCredentialId,
    ) -> Result<Option<EventLabel>, DomainError> {
        Ok(self.label("credential"))
    }

    async fn approval(
        &self,
        _: &crate::tenancy::ScopedTenant,
        _: &ianua_domain::types::ApprovalId,
    ) -> Result<Option<EventLabel>, DomainError> {
        Ok(self.label("approval"))
    }

    async fn model_provider(
        &self,
        _: &crate::tenancy::ScopedTenant,
        _: &ianua_domain::types::ModelProviderId,
    ) -> Result<Option<EventLabel>, DomainError> {
        Ok(self.label("provider"))
    }

    async fn oauth_client(
        &self,
        _: &crate::tenancy::ScopedTenant,
        _: &ianua_domain::types::OAuthClientId,
    ) -> Result<Option<EventLabel>, DomainError> {
        Ok(self.label("client"))
    }

    async fn connection(
        &self,
        _: &crate::tenancy::ScopedTenant,
        _: &ianua_domain::types::ConnectionId,
    ) -> Result<Option<EventLabel>, DomainError> {
        Ok(self.label("connection"))
    }

    async fn notification(
        &self,
        _: &crate::tenancy::ScopedTenant,
        _: &ianua_domain::types::NotificationId,
    ) -> Result<Option<EventLabel>, DomainError> {
        Ok(self.label("notification"))
    }

    async fn consumer(
        &self,
        _: &crate::tenancy::ScopedTenant,
        _: &ianua_domain::types::ConsumerId,
    ) -> Result<Option<EventLabel>, DomainError> {
        Ok(self.label("consumer"))
    }

    async fn tenant(
        &self,
        _: &crate::tenancy::ScopedTenant,
    ) -> Result<Option<EventLabel>, DomainError> {
        Ok(self.label("tenant"))
    }

    async fn principals(
        &self,
        _: &crate::tenancy::ScopedTenant,
        principals: &[PrincipalRef],
    ) -> Result<HashMap<PrincipalRef, EventLabel>, DomainError> {
        Ok(principals
            .iter()
            .filter_map(|principal| {
                let kind = match principal {
                    PrincipalRef::User(_) => "user",
                    PrincipalRef::Agent(_) => "agent",
                    PrincipalRef::Consumer(_) => "consumer",
                    PrincipalRef::OrgUser(_) => return None,
                };
                self.label(kind).map(|label| (*principal, label))
            })
            .collect())
    }
}

#[async_trait]
impl crate::ports::shared::ControlPlaneLabelResolver for FakeAuditLabelResolver {
    async fn platform_notification(
        &self,
        _: &ianua_domain::types::OperatorId,
        _: &ianua_domain::types::NotificationId,
    ) -> Result<Option<EventLabel>, DomainError> {
        Ok(self.label("platform notification"))
    }

    async fn org_notification(
        &self,
        _: &ianua_domain::types::OrganizationId,
        _: &ianua_domain::types::OrgUserId,
        _: &ianua_domain::types::NotificationId,
    ) -> Result<Option<EventLabel>, DomainError> {
        Ok(self.label("org notification"))
    }

    async fn org_user(
        &self,
        _: &ianua_domain::types::OrganizationId,
        _: &ianua_domain::types::OrgUserId,
    ) -> Result<Option<EventLabel>, DomainError> {
        Ok(self.label("org user"))
    }

    async fn org_users(
        &self,
        _: &ianua_domain::types::OrganizationId,
        org_user_ids: &[ianua_domain::types::OrgUserId],
    ) -> Result<HashMap<ianua_domain::types::OrgUserId, EventLabel>, DomainError> {
        Ok(org_user_ids
            .iter()
            .filter_map(|id| self.label("org user").map(|label| (*id, label)))
            .collect())
    }

    async fn operator(
        &self,
        _: &ianua_domain::types::OperatorId,
    ) -> Result<Option<EventLabel>, DomainError> {
        Ok(self.label("operator"))
    }
}

impl Fake for Arc<dyn crate::ports::shared::AuditLabelResolver> {
    fn fake() -> Self {
        Arc::new(FakeAuditLabelResolver::new())
    }
}

impl Fake for Arc<dyn crate::ports::shared::ControlPlaneLabelResolver> {
    fn fake() -> Self {
        Arc::new(FakeAuditLabelResolver::new())
    }
}

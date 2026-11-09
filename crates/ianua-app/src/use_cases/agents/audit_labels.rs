//! The labels agent events capture to name an agent or model provider in
//! the audit trail, each falling back to the id when there is nothing
//! better. A label is never worth failing the operation over.

use ianua_domain::types::{AgentId, EventLabel, ModelProviderId};

use crate::ports::shared::AuditLabelResolver;
use crate::tenancy::ScopedTenant;

/// The agent's audit label, or its id when the agent is gone or the lookup
/// fails.
pub(super) async fn agent_label(
    resolver: &dyn AuditLabelResolver,
    tenant: &ScopedTenant,
    agent_id: &AgentId,
) -> EventLabel {
    resolver
        .agent(tenant, agent_id)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| EventLabel::of(&agent_id.to_string()))
}

/// The model provider's audit label, or its id when the provider is gone or
/// the lookup fails.
pub(super) async fn provider_label(
    resolver: &dyn AuditLabelResolver,
    tenant: &ScopedTenant,
    provider_id: &ModelProviderId,
) -> EventLabel {
    resolver
        .model_provider(tenant, provider_id)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| EventLabel::of(&provider_id.to_string()))
}

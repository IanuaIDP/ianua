//! Plan limit enforcement service.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::organization::billing::plan::PlanLimits;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::OrganizationId;

use crate::ports::limits::{LimitEnforcer, OrgResourceCounter, ResourceCounter, ResourceKind};
use crate::tenancy::ScopedTenant;

/// Enforces plan limits by comparing current usage against pre-resolved
/// plan limits from the `CallerContext`.
pub struct PlanLimitEnforcer {
    tenant_counts: Arc<dyn ResourceCounter>,
    org_counts: Arc<dyn OrgResourceCounter>,
}

impl PlanLimitEnforcer {
    /// An enforcer counting a tenant's resources through `tenant_counts`
    /// and an organization's through `org_counts`.
    #[must_use]
    pub fn new(
        tenant_counts: Arc<dyn ResourceCounter>,
        org_counts: Arc<dyn OrgResourceCounter>,
    ) -> Self {
        Self {
            tenant_counts,
            org_counts,
        }
    }
}

#[async_trait]
impl LimitEnforcer for PlanLimitEnforcer {
    async fn check_tenant_limit(
        &self,
        limits: &PlanLimits,
        tenant_id: &ScopedTenant,
        kind: ResourceKind,
    ) -> Result<(), DomainError> {
        self.check_tenant_room(limits, tenant_id, kind, 1).await
    }

    async fn check_tenant_room(
        &self,
        limits: &PlanLimits,
        tenant_id: &ScopedTenant,
        kind: ResourceKind,
        wanted: u64,
    ) -> Result<(), DomainError> {
        let current = self.tenant_counts.count_for_tenant(tenant_id, kind).await?;
        ensure_room(limits, kind, current, wanted)
    }

    async fn tenant_room(
        &self,
        limits: &PlanLimits,
        tenant_id: &ScopedTenant,
        kind: ResourceKind,
    ) -> Result<u64, DomainError> {
        let current = self.tenant_counts.count_for_tenant(tenant_id, kind).await?;
        Ok(max_for(limits, kind).saturating_sub(current))
    }

    async fn check_org_limit(
        &self,
        limits: &PlanLimits,
        organization_id: &OrganizationId,
        kind: ResourceKind,
    ) -> Result<(), DomainError> {
        let current = self.org_counts.count_for_org(organization_id, kind).await?;
        ensure_room(limits, kind, current, 1)
    }
}

/// Refuses `wanted` more of `kind` when `current` plus them would pass the
/// plan's ceiling.
fn ensure_room(
    limits: &PlanLimits,
    kind: ResourceKind,
    current: u64,
    wanted: u64,
) -> Result<(), DomainError> {
    let max = max_for(limits, kind);
    if current.saturating_add(wanted) > max {
        return Err(DomainError::forbidden(message!(
            "limits-plan-limit-reached",
            format!("plan limit reached: {kind:?} ({current}/{max})")
        )));
    }
    Ok(())
}

/// The plan's ceiling for `kind`.
// One arm per kind, with no catch-all: a new kind must be given its
// ceiling here before it builds. Splitting it would bring a catch-all back.
#[allow(clippy::too_many_lines)]
fn max_for(limits: &PlanLimits, kind: ResourceKind) -> u64 {
    match kind {
        ResourceKind::Users => limits.max_users,
        ResourceKind::Tenants => u64::from(limits.max_tenants_per_org),
        ResourceKind::Routes => u64::from(limits.max_routes),
        ResourceKind::DnsRecordSets => u64::from(limits.max_dns_record_sets),
        ResourceKind::Domains => u64::from(limits.max_domains),
        ResourceKind::ApiKeys => u64::from(limits.max_api_keys),
        ResourceKind::OAuthClients => u64::from(limits.max_oauth_clients),
        ResourceKind::Roles => u64::from(limits.max_roles),
        ResourceKind::Groups => u64::from(limits.max_groups),
        ResourceKind::Webhooks => u64::from(limits.max_webhooks),
        ResourceKind::FederationConnections => u64::from(limits.max_federation_connections),
        ResourceKind::SamlServiceProviders => u64::from(limits.max_saml_service_providers),
        ResourceKind::DirectoryServiceAccounts => u64::from(limits.max_directory_service_accounts),
        ResourceKind::MessageSubscriptions => u64::from(limits.max_message_subscriptions),
        ResourceKind::Connectors => u64::from(limits.max_connectors),
        ResourceKind::LogTargets => u64::from(limits.max_log_targets),
        ResourceKind::AuditStreams => u64::from(limits.max_audit_streams),
        ResourceKind::NotificationDestinations => u64::from(limits.max_notification_destinations),
        ResourceKind::Consumers => u64::from(limits.max_consumers),
        ResourceKind::Services => u64::from(limits.max_services),
        ResourceKind::StreamRoutes => u64::from(limits.max_stream_routes),
        ResourceKind::EgressPolicies => u64::from(limits.max_egress_policies),
        ResourceKind::ResourceTypes => u64::from(limits.max_resource_types),
        ResourceKind::UserAttributes => u64::from(limits.max_user_attributes),
        ResourceKind::Agents => u64::from(limits.max_agents),
        ResourceKind::AgentTools => u64::from(limits.max_agent_tools),
        ResourceKind::ModelProviders => u64::from(limits.max_model_providers),
        ResourceKind::Workflows => u64::from(limits.max_workflows),
        ResourceKind::Sandboxes => u64::from(limits.max_sandboxes),
        ResourceKind::RunningTrials => u64::from(limits.max_running_trials),
        ResourceKind::RunningEvaluations => u64::from(limits.max_running_evaluations),
        ResourceKind::OwnImages => u64::from(limits.max_own_images),
        ResourceKind::Memories => u64::from(limits.max_memories),
        ResourceKind::ActiveAgentRuns => u64::from(limits.max_active_agent_runs),
        ResourceKind::PendingApprovals => u64::from(limits.max_pending_approvals),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::ports::TenantScoped;
    use crate::test_support::block_on;

    /// Answers every count with the same number.
    struct FixedCounter {
        count: u64,
    }

    impl TenantScoped for FixedCounter {}

    #[async_trait]
    impl ResourceCounter for FixedCounter {
        async fn count_for_tenant(
            &self,
            _: &ScopedTenant,
            _: ResourceKind,
        ) -> Result<u64, DomainError> {
            Ok(self.count)
        }
    }

    #[async_trait]
    impl OrgResourceCounter for FixedCounter {
        async fn count_for_org(
            &self,
            _: &OrganizationId,
            _: ResourceKind,
        ) -> Result<u64, DomainError> {
            Ok(self.count)
        }
    }

    fn enforcer_counting(count: u64) -> PlanLimitEnforcer {
        let counter = Arc::new(FixedCounter { count });
        PlanLimitEnforcer::new(counter.clone(), counter)
    }

    fn a_tenant() -> ScopedTenant {
        ScopedTenant::for_test(TenantId::new())
    }

    /// Ann's tenant has 50 of the Free plan's 100 users, so she may add one.
    #[test]
    fn allows_when_under_limit() {
        let enforcer = enforcer_counting(50);
        let limits = OrganizationPlan::Free.default_limits();

        let result =
            block_on(enforcer.check_tenant_limit(&limits, &a_tenant(), ResourceKind::Users));

        assert!(result.is_ok());
    }

    /// Acme holds 98 of the Free plan's 100 users. Two more fit; a tenant
    /// already past its ceiling has room for none, never a negative count.
    #[test]
    fn room_is_the_ceiling_less_what_the_tenant_holds() {
        let limits = OrganizationPlan::Free.default_limits();
        let max = limits.max_users;

        let near = block_on(enforcer_counting(max - 2).tenant_room(
            &limits,
            &a_tenant(),
            ResourceKind::Users,
        ));
        let past = block_on(enforcer_counting(max + 5).tenant_room(
            &limits,
            &a_tenant(),
            ResourceKind::Users,
        ));

        assert_eq!(near.unwrap(), 2);
        assert_eq!(past.unwrap(), 0);
    }

    /// A request for two runs is forbidden when the tenant has room for only one.
    #[test]
    fn refuses_a_batch_that_would_overflow_the_limit() {
        let limits = OrganizationPlan::Free.default_limits();
        let max = u64::from(limits.max_active_agent_runs);
        let enforcer = enforcer_counting(max - 1);

        let result = block_on(enforcer.check_tenant_room(
            &limits,
            &a_tenant(),
            ResourceKind::ActiveAgentRuns,
            2,
        ));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Ann starts two runs with room left for exactly two, and both fit.
    #[test]
    fn admits_a_batch_that_exactly_fills_the_limit() {
        let limits = OrganizationPlan::Free.default_limits();
        let max = u64::from(limits.max_active_agent_runs);
        let enforcer = enforcer_counting(max - 2);

        let result = block_on(enforcer.check_tenant_room(
            &limits,
            &a_tenant(),
            ResourceKind::ActiveAgentRuns,
            2,
        ));

        assert!(result.is_ok());
    }

    /// A tenant at its user limit is refused permission to add another user.
    #[test]
    fn rejects_when_at_limit() {
        let enforcer = enforcer_counting(100);
        let limits = OrganizationPlan::Free.default_limits();

        let result =
            block_on(enforcer.check_tenant_limit(&limits, &a_tenant(), ResourceKind::Users));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A tenant already above its user limit is refused another user too.
    #[test]
    fn rejects_when_over_limit() {
        let enforcer = enforcer_counting(150);
        let limits = OrganizationPlan::Free.default_limits();

        let result =
            block_on(enforcer.check_tenant_limit(&limits, &a_tenant(), ResourceKind::Users));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Ann's tenant on Starter holds 5,000 users and may still add one.
    #[test]
    fn higher_plan_allows_more() {
        let enforcer = enforcer_counting(5000);
        let limits = OrganizationPlan::Starter.default_limits();

        let result =
            block_on(enforcer.check_tenant_limit(&limits, &a_tenant(), ResourceKind::Users));

        assert!(result.is_ok());
    }

    /// An empty Free tenant has room for the first of every kind of resource.
    #[test]
    fn checks_each_resource_kind_under_limit() {
        let enforcer = enforcer_counting(0);
        let limits = OrganizationPlan::Free.default_limits();

        for kind in [
            ResourceKind::Users,
            ResourceKind::Routes,
            ResourceKind::ApiKeys,
            ResourceKind::OAuthClients,
            ResourceKind::Roles,
            ResourceKind::Groups,
            ResourceKind::Webhooks,
            ResourceKind::FederationConnections,
            ResourceKind::Services,
            ResourceKind::Workflows,
            ResourceKind::Sandboxes,
            ResourceKind::Memories,
        ] {
            let result = block_on(enforcer.check_tenant_limit(&limits, &a_tenant(), kind));

            assert!(result.is_ok(), "{kind:?} should be under limit at count=0");
        }
    }

    /// An organization with its one permitted tenant cannot open a second.
    #[test]
    fn org_limit_for_tenants() {
        let enforcer = enforcer_counting(1);
        let limits = OrganizationPlan::Free.default_limits();

        let result = block_on(enforcer.check_org_limit(
            &limits,
            &OrganizationId::new(),
            ResourceKind::Tenants,
        ));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }
}

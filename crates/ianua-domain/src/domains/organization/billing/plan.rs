use std::fmt;

use crate::domains::organization::billing::usage::PlanUsage;
#[cfg(test)]
use crate::domains::tenant::provisioning::infrastructure::{
    CloudProvider, DeploymentRegion, NetworkPlacement, Placement,
};
use crate::domains::tenant::provisioning::infrastructure::{IsolationLevel, TenantResidency};
use crate::message;
use crate::shared::errors::DomainError;

/// Every isolation level, for the plans that offer them all.
const EVERY_ISOLATION: [IsolationLevel; 4] = [
    IsolationLevel::Shared,
    IsolationLevel::DedicatedSchema,
    IsolationLevel::DedicatedInstance,
    IsolationLevel::DedicatedCluster,
];

/// Subscription tier identifier.
///
/// Decides which [`PlanLimits`] apply to the organization. Every sold tier's
/// limits are fixed in code. Custom gets the Business limits until limits of
/// its own are negotiated, see
/// [`NegotiatedLimits`](crate::domains::organization::billing::negotiated::NegotiatedLimits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OrganizationPlan {
    /// For trying things out. 100 users, at no cost.
    Free,
    /// For small teams and startups. 10,000 users, $100 a month.
    Starter,
    /// For production workloads. 100,000 users, $400 a month.
    Business,
    /// Negotiated limits and dedicated infrastructure.
    Custom,
    /// The one organization of an installation its owner runs themselves.
    ///
    /// Not a tier anyone buys or moves to. The hardware is the owner's, so
    /// there is nothing for a count to protect, and it is given only when an
    /// installation creates its organization.
    SelfHosted,
}

impl OrganizationPlan {
    /// The preset limits for this plan tier.
    ///
    /// `Custom` gets the Business limits here. An organization whose limits
    /// were negotiated reads them from
    /// [`Organization::limits`](crate::domains::organization::lifecycle::Organization::limits)
    /// instead.
    #[must_use]
    pub fn default_limits(&self) -> PlanLimits {
        match self {
            Self::Free => PlanLimits::free(),
            Self::Starter => PlanLimits::starter(),
            Self::Business => PlanLimits::business(),
            Self::Custom => PlanLimits::business(),
            Self::SelfHosted => PlanLimits::self_hosted(),
        }
    }

    /// Whether an organization may move from this plan to `to`.
    ///
    /// Self-hosted is fixed in both directions. Moving onto it would lift
    /// every limit on a deployment someone else pays for, and moving off it
    /// would cap an installation at a tier nobody there ever bought.
    #[must_use]
    pub fn can_change_to(&self, to: Self) -> bool {
        !matches!((self, to), (Self::SelfHosted, _) | (_, Self::SelfHosted))
    }

    /// How an organization comes to be on this plan: Free costs nothing,
    /// Starter and Business are bought by the organization itself, and
    /// Custom and self-hosted are arranged by the platform, never chosen.
    #[must_use]
    pub fn sale(&self) -> PlanSale {
        match self {
            Self::Free => PlanSale::NoCost,
            Self::Starter | Self::Business => PlanSale::SelfServed,
            Self::Custom | Self::SelfHosted => PlanSale::Arranged,
        }
    }

    /// How many trial days this plan includes, or `None` for no trial.
    #[must_use]
    pub fn trial_days(&self) -> Option<u32> {
        match self {
            Self::Free => None,
            Self::Starter => Some(14),
            Self::Business => Some(14),
            Self::Custom => None,
            Self::SelfHosted => None,
        }
    }
}

/// How an organization comes to be on a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanSale {
    /// It costs nothing, so anyone with the billing right moves onto it.
    NoCost,
    /// The organization buys it itself, with a trial or a payment method.
    SelfServed,
    /// The platform arranges it, as sales or the installer agreed.
    Arranged,
}

impl fmt::Display for OrganizationPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Free => f.write_str("free"),
            Self::Starter => f.write_str("starter"),
            Self::Business => f.write_str("business"),
            Self::Custom => f.write_str("custom"),
            Self::SelfHosted => f.write_str("self_hosted"),
        }
    }
}

/// Concrete limits enforced for an organization.
///
/// Every operation that creates a countable resource checks these limits
/// first. They come from [`OrganizationPlan::default_limits`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PlanLimits {
    /// Maximum registered users across all tenants.
    pub max_users: u64,
    /// Maximum tenants the organization can create.
    pub max_tenants_per_org: u32,
    /// Maximum proxy routes.
    pub max_routes: u32,
    /// Maximum record sets across every zone a tenant has delegated to us.
    ///
    /// Counted per set, not per value, which matches how DNS resolves and how
    /// the API is shaped. A second address on a name is still one record to a
    /// resolver.
    pub max_dns_record_sets: u32,
    /// Maximum domains a tenant may register.
    ///
    /// Limited because a hostname is claimed for the whole platform.
    /// Registering one stops every other tenant from registering it, proven
    /// or not. Without a limit one tenant could take names by the thousand,
    /// at no cost to them.
    pub max_domains: u32,
    /// Maximum proxied requests per month.
    pub max_proxy_requests_per_month: u64,
    /// Maximum API keys.
    pub max_api_keys: u32,
    /// Maximum OAuth clients.
    pub max_oauth_clients: u32,
    /// Maximum roles.
    pub max_roles: u32,
    /// Maximum groups.
    pub max_groups: u32,
    /// Maximum webhook subscriptions.
    pub max_webhooks: u32,
    /// Maximum federation connections, over SAML or OIDC.
    pub max_federation_connections: u32,
    /// Maximum consumers per tenant. Consumers are the non-human callers let
    /// through.
    pub max_consumers: u32,
    /// Maximum services per tenant. Services are the backends routes forward to.
    pub max_services: u32,
    /// Maximum stream routes per tenant. These are the ports listened on
    /// below HTTP.
    ///
    /// Tighter than the other limits because it is the only one that uses
    /// something shared by the whole deployment. A listening port is claimed
    /// on every proxy instance, and no second tenant can have it.
    pub max_stream_routes: u32,
    /// Maximum egress policies per tenant. Each lets a service reach out
    /// through the egress gateway.
    pub max_egress_policies: u32,
    /// Maximum resource types per tenant. These are the entries in the
    /// permission catalogue that describe what the tenant's own application
    /// protects.
    pub max_resource_types: u32,
    /// Maximum custom user attributes per tenant. These are the fields a
    /// tenant adds to its own users.
    ///
    /// Limited because a directory may be asked to carry, filter or sort by
    /// each attribute. Each one adds work to the listing every administrator
    /// runs.
    pub max_user_attributes: u32,
    /// Maximum agent identities per tenant.
    pub max_agents: u32,
    /// Maximum registered agent tools per tenant.
    pub max_agent_tools: u32,
    /// Maximum connected model providers per tenant.
    pub max_model_providers: u32,
    /// Maximum workflows per tenant.
    pub max_workflows: u32,
    /// Maximum sandboxes per tenant, counting each sandbox once whatever its
    /// versions. Each version's package bundle is kept in storage.
    pub max_sandboxes: u32,
    /// Maximum trials of sandbox versions running at once per tenant. Each
    /// takes a sandbox on a worker while it runs.
    pub max_running_trials: u32,
    /// Maximum evaluations of workflows running at once per tenant. Each
    /// keeps a few test runs under way until its cases end.
    pub max_running_evaluations: u32,
    /// Maximum sandboxes of the company's own image per tenant, counting
    /// each once whatever its versions. Each pins an image the platform
    /// scans and pulls into its sandboxes.
    pub max_own_images: u32,
    /// Maximum memories per tenant, those waiting to be deleted among them.
    pub max_memories: u32,
    /// Maximum texts kept across all of a tenant's memories. A memory at
    /// the limit takes no more; nothing kept is ever removed for it.
    pub max_memory_entries: u32,
    /// Maximum SAML apps the tenant signs people in to as their identity provider per tenant.
    pub max_saml_service_providers: u32,
    /// Maximum accounts applications bind to the tenant's LDAP directory as per tenant.
    pub max_directory_service_accounts: u32,
    /// Maximum message subscriptions on the tenant's topics per tenant.
    pub max_message_subscriptions: u32,
    /// Maximum private network connectors per tenant.
    pub max_connectors: u32,
    /// Maximum places the gateway ships request records to per tenant.
    pub max_log_targets: u32,
    /// Maximum places the audit trail streams to per tenant.
    pub max_audit_streams: u32,
    /// Maximum channels the organization posts its notifications to.
    pub max_notification_destinations: u32,
    /// Maximum runs in flight at once, running or awaiting approval.
    ///
    /// Limits how much model spend runs at once. Per-request rate limiting
    /// does not, because a run keeps calling the provider after the request
    /// returns.
    pub max_active_agent_runs: u32,
    /// Maximum approval requests awaiting a decision at once.
    pub max_pending_approvals: u32,
    /// Audit log retention in days.
    pub audit_retention_days: u32,
    /// API rate limit, in requests per minute.
    pub api_rate_limit_per_minute: u32,
    /// Allowed data isolation levels.
    pub allowed_isolation: Vec<IsolationLevel>,
}

impl PlanLimits {
    /// Free tier, for trying things out and prototypes.
    // One line per limit, a table and not logic: splitting it would scatter
    // one tier over several functions.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn free() -> Self {
        Self {
            max_users: 100,
            max_tenants_per_org: 1,
            max_routes: 3,
            max_dns_record_sets: 10,
            max_domains: 3,
            max_proxy_requests_per_month: 500_000,
            max_api_keys: 5,
            max_oauth_clients: 2,
            max_roles: 5,
            max_groups: 5,
            max_webhooks: 3,
            max_federation_connections: 1,
            max_consumers: 3,
            max_services: 3,
            max_stream_routes: 1,
            max_egress_policies: 1,
            max_resource_types: 5,
            max_user_attributes: 10,
            max_agents: 5,
            max_agent_tools: 10,
            max_model_providers: 2,
            max_workflows: 3,
            max_sandboxes: 3,
            max_running_trials: 2,
            max_running_evaluations: 1,
            max_own_images: 1,
            max_memories: 2,
            max_memory_entries: 20_000,
            max_saml_service_providers: 1,
            max_directory_service_accounts: 1,
            max_message_subscriptions: 5,
            max_connectors: 1,
            max_log_targets: 1,
            max_audit_streams: 1,
            max_notification_destinations: 2,
            max_active_agent_runs: 5,
            max_pending_approvals: 20,
            audit_retention_days: 30,
            api_rate_limit_per_minute: 200,
            allowed_isolation: vec![IsolationLevel::Shared, IsolationLevel::DedicatedSchema],
        }
    }

    /// Starter tier, for small teams and startups.
    // One line per limit, a table and not logic: splitting it would scatter
    // one tier over several functions.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn starter() -> Self {
        Self {
            max_users: 10_000,
            max_tenants_per_org: 3,
            max_routes: 25,
            max_dns_record_sets: 100,
            max_domains: 25,
            max_proxy_requests_per_month: 25_000_000,
            max_api_keys: 25,
            max_oauth_clients: 10,
            max_roles: 25,
            max_groups: 25,
            max_webhooks: 10,
            max_federation_connections: 3,
            max_consumers: 10,
            max_services: 10,
            max_stream_routes: 5,
            max_egress_policies: 5,
            max_resource_types: 25,
            max_user_attributes: 50,
            max_agents: 25,
            max_agent_tools: 50,
            max_model_providers: 5,
            max_workflows: 15,
            max_sandboxes: 15,
            max_running_trials: 5,
            max_running_evaluations: 3,
            max_own_images: 3,
            max_memories: 10,
            max_memory_entries: 200_000,
            max_saml_service_providers: 5,
            max_directory_service_accounts: 3,
            max_message_subscriptions: 25,
            max_connectors: 2,
            max_log_targets: 2,
            max_audit_streams: 2,
            max_notification_destinations: 5,
            max_active_agent_runs: 25,
            max_pending_approvals: 100,
            audit_retention_days: 90,
            api_rate_limit_per_minute: 2_000,
            allowed_isolation: vec![IsolationLevel::Shared, IsolationLevel::DedicatedSchema],
        }
    }

    /// Business tier, for production workloads.
    // One line per limit, a table and not logic: splitting it would scatter
    // one tier over several functions.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn business() -> Self {
        Self {
            max_users: 100_000,
            max_tenants_per_org: 25,
            max_routes: 250,
            max_dns_record_sets: 1_000,
            max_domains: 250,
            max_proxy_requests_per_month: 500_000_000,
            max_api_keys: 250,
            max_oauth_clients: 100,
            max_roles: 250,
            max_groups: 250,
            max_webhooks: 50,
            max_federation_connections: 10,
            max_consumers: 100,
            max_services: 100,
            max_stream_routes: 25,
            max_egress_policies: 25,
            max_resource_types: 200,
            max_user_attributes: 300,
            max_agents: 250,
            max_agent_tools: 500,
            max_model_providers: 25,
            max_workflows: 150,
            max_sandboxes: 150,
            max_running_trials: 25,
            max_running_evaluations: 10,
            max_own_images: 25,
            max_memories: 100,
            max_memory_entries: 5_000_000,
            max_saml_service_providers: 50,
            max_directory_service_accounts: 20,
            max_message_subscriptions: 250,
            max_connectors: 10,
            max_log_targets: 5,
            max_audit_streams: 5,
            max_notification_destinations: 25,
            max_active_agent_runs: 250,
            max_pending_approvals: 1_000,
            audit_retention_days: 365,
            api_rate_limit_per_minute: 10_000,
            allowed_isolation: EVERY_ISOLATION.to_vec(),
        }
    }

    /// Self-hosted, for an installation's own organization.
    ///
    /// Every count is unlimited. Counts exist to share a deployment fairly
    /// between customers, and here there is only one. Two values stay finite.
    /// The API rate limit protects the server from a runaway client, which an
    /// owner needs too. Audit retention is subtracted from now by a purge,
    /// and an unlimited number of days would go out of range.
    // One line per limit, a table and not logic: splitting it would scatter
    // one tier over several functions.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn self_hosted() -> Self {
        Self {
            max_users: u64::MAX,
            max_tenants_per_org: u32::MAX,
            max_routes: u32::MAX,
            max_dns_record_sets: u32::MAX,
            max_domains: u32::MAX,
            max_proxy_requests_per_month: u64::MAX,
            max_api_keys: u32::MAX,
            max_oauth_clients: u32::MAX,
            max_roles: u32::MAX,
            max_groups: u32::MAX,
            max_webhooks: u32::MAX,
            max_federation_connections: u32::MAX,
            max_consumers: u32::MAX,
            max_services: u32::MAX,
            max_stream_routes: u32::MAX,
            max_egress_policies: u32::MAX,
            max_resource_types: u32::MAX,
            max_user_attributes: u32::MAX,
            max_agents: u32::MAX,
            max_agent_tools: u32::MAX,
            max_model_providers: u32::MAX,
            max_workflows: u32::MAX,
            max_sandboxes: u32::MAX,
            max_running_trials: u32::MAX,
            max_running_evaluations: u32::MAX,
            max_own_images: u32::MAX,
            max_memories: u32::MAX,
            max_memory_entries: u32::MAX,
            max_saml_service_providers: u32::MAX,
            max_directory_service_accounts: u32::MAX,
            max_message_subscriptions: u32::MAX,
            max_connectors: u32::MAX,
            max_log_targets: u32::MAX,
            max_audit_streams: u32::MAX,
            max_notification_destinations: u32::MAX,
            max_active_agent_runs: u32::MAX,
            max_pending_approvals: u32::MAX,
            audit_retention_days: 365,
            api_rate_limit_per_minute: 10_000,
            allowed_isolation: EVERY_ISOLATION.to_vec(),
        }
    }

    /// Whether the given isolation level is allowed.
    #[must_use]
    pub fn allows_isolation(&self, level: IsolationLevel) -> bool {
        self.allowed_isolation.contains(&level)
    }

    /// Refuses a residency this plan does not cover.
    ///
    /// This is the only place a plan is compared with what a tenant asked
    /// for. Callers do not each decide what their tier is worth.
    ///
    /// Hosting on the customer's own infrastructure is the highest level. A
    /// plan gets it by allowing a dedicated cluster, not by a second flag
    /// that could disagree with the first.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] naming the isolation level the plan does
    ///   not include.
    /// - [`DomainError::Forbidden`] when the residency needs customer-owned
    ///   infrastructure and the plan does not allow a dedicated cluster.
    pub fn permits_residency(&self, residency: &TenantResidency) -> Result<(), DomainError> {
        if !self.allows_isolation(residency.isolation()) {
            return Err(DomainError::forbidden(message!(
                "organization-this-plan-does-not-include-isolation",
                format!(
                    "this plan does not include {:?} isolation",
                    residency.isolation()
                )
            )));
        }

        if residency.needs_customer_input()
            && !self.allows_isolation(IsolationLevel::DedicatedCluster)
        {
            return Err(DomainError::forbidden(message!(
                "organization-this-plan-does-not-include-hosting",
                "this plan does not include hosting on your own infrastructure"
            )));
        }

        Ok(())
    }

    /// Refuses limits the organization already uses more than.
    ///
    /// A downgrade is checked here before it happens. Acme runs forty
    /// routes on Business. Without this, it moves to Starter, keeps all
    /// forty, and pays less for what Starter never allowed.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] naming the first count `usage` goes past,
    ///   or an isolation level in use that these limits do not include.
    pub fn ensure_fits(&self, usage: &PlanUsage) -> Result<(), DomainError> {
        if let Some((what, allowed)) = usage.first_overage_under(self) {
            return Err(DomainError::conflict(message!(
                "organization-the-organization-uses-more-than-these",
                format!(
                    "the organization uses more {what} than these limits allow, which is {allowed}"
                )
            )));
        }
        let outside = usage
            .isolation_in_use
            .iter()
            .find(|level| !self.allows_isolation(**level));
        let Some(level) = outside else {
            return Ok(());
        };
        Err(DomainError::conflict(message!(
            "organization-a-tenant-uses-isolation-which-these",
            format!("a tenant uses {level:?} isolation, which these limits do not include")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The free tier allows 100 users, one tenant, three routes and 30 days
    /// of audit history.
    #[test]
    fn free_limits_are_restrictive() {
        let limits = PlanLimits::free();
        assert_eq!(limits.max_users, 100);
        assert_eq!(limits.max_tenants_per_org, 1);
        assert_eq!(limits.max_routes, 3);
        assert_eq!(limits.audit_retention_days, 30);
    }

    /// Moving from Free to Starter raises users, routes, monthly proxy
    /// requests and audit history. An upgrade never gives less.
    #[test]
    fn starter_scales_up_from_free() {
        let free = PlanLimits::free();
        let starter = PlanLimits::starter();
        assert!(starter.max_users > free.max_users);
        assert!(starter.max_routes > free.max_routes);
        assert!(starter.max_proxy_requests_per_month > free.max_proxy_requests_per_month);
        assert!(starter.audit_retention_days > free.audit_retention_days);
    }

    /// Moving from Starter to Business raises users, routes and monthly proxy
    /// requests.
    #[test]
    fn business_scales_up_from_starter() {
        let starter = PlanLimits::starter();
        let business = PlanLimits::business();
        assert!(business.max_users > starter.max_users);
        assert!(business.max_routes > starter.max_routes);
        assert!(business.max_proxy_requests_per_month > starter.max_proxy_requests_per_month);
    }

    /// The free tier allows a shared database or a dedicated schema. It does
    /// not allow a dedicated instance or cluster.
    #[test]
    fn free_allows_shared_and_schema_isolation() {
        let limits = PlanLimits::free();
        assert!(limits.allows_isolation(IsolationLevel::Shared));
        assert!(limits.allows_isolation(IsolationLevel::DedicatedSchema));
        assert!(!limits.allows_isolation(IsolationLevel::DedicatedInstance));
        assert!(!limits.allows_isolation(IsolationLevel::DedicatedCluster));
    }

    /// The Business tier allows every isolation level, up to a dedicated
    /// cluster.
    #[test]
    fn business_allows_all_isolation_levels() {
        let limits = PlanLimits::business();
        assert!(limits.allows_isolation(IsolationLevel::Shared));
        assert!(limits.allows_isolation(IsolationLevel::DedicatedSchema));
        assert!(limits.allows_isolation(IsolationLevel::DedicatedInstance));
        assert!(limits.allows_isolation(IsolationLevel::DedicatedCluster));
    }

    fn platform(isolation: IsolationLevel) -> TenantResidency {
        TenantResidency::new(
            Placement::Platform {
                region: DeploymentRegion::EuCentral1,
            },
            isolation,
        )
        .unwrap()
    }

    /// A free tenant asks to be hosted on the platform with shared or schema
    /// isolation. Both are allowed.
    #[test]
    fn free_permits_the_residency_it_advertises() {
        let limits = PlanLimits::free();

        assert!(
            limits
                .permits_residency(&platform(IsolationLevel::Shared))
                .is_ok()
        );
        assert!(
            limits
                .permits_residency(&platform(IsolationLevel::DedicatedSchema))
                .is_ok()
        );
    }

    /// Free refuses a dedicated database instance because that isolation
    /// level is outside its limits.
    #[test]
    fn free_refuses_an_isolation_level_it_does_not_include() {
        let limits = PlanLimits::free();

        let result = limits.permits_residency(&platform(IsolationLevel::DedicatedInstance));

        assert!(
            matches!(result, Err(DomainError::Forbidden(_))),
            "{result:?}"
        );
    }

    /// Free refuses a dedicated instance on a customer-owned database.
    #[test]
    fn free_refuses_customer_owned_infrastructure() {
        let limits = PlanLimits::free();
        let residency = TenantResidency::new(
            Placement::CustomerDatabase,
            IsolationLevel::DedicatedInstance,
        )
        .unwrap();

        let result = limits.permits_residency(&residency);

        assert!(
            matches!(result, Err(DomainError::Forbidden(_))),
            "{result:?}"
        );
    }

    /// A Business tenant asks for a dedicated cluster in its own AWS account.
    /// It is allowed.
    #[test]
    fn business_permits_customer_owned_infrastructure() {
        let limits = PlanLimits::business();
        let residency = TenantResidency::new(
            Placement::CustomerCloud {
                provider: CloudProvider::Aws,
                region: DeploymentRegion::EuWest1,
                network: NetworkPlacement::Provision,
            },
            IsolationLevel::DedicatedCluster,
        )
        .unwrap();

        assert!(limits.permits_residency(&residency).is_ok());
    }

    /// A Custom organization gets the Business user and route limits, since
    /// nothing stores negotiated limits.
    #[test]
    fn custom_defaults_to_business() {
        let custom = OrganizationPlan::Custom.default_limits();
        let business = PlanLimits::business();
        assert_eq!(custom.max_users, business.max_users);
        assert_eq!(custom.max_routes, business.max_routes);
    }

    /// Starter and Business each come with a 14-day trial. Free and Custom
    /// have none.
    #[test]
    fn trial_days_only_on_paid_tiers() {
        assert!(OrganizationPlan::Free.trial_days().is_none());
        assert_eq!(OrganizationPlan::Starter.trial_days(), Some(14));
        assert_eq!(OrganizationPlan::Business.trial_days(), Some(14));
        assert!(OrganizationPlan::Custom.trial_days().is_none());
    }

    /// Each plan prints as its lower-case name, with `self_hosted` for the
    /// self-hosted plan, which is how it appears in messages.
    #[test]
    fn plan_display_is_lowercase() {
        assert_eq!(OrganizationPlan::Free.to_string(), "free");
        assert_eq!(OrganizationPlan::Starter.to_string(), "starter");
        assert_eq!(OrganizationPlan::Business.to_string(), "business");
        assert_eq!(OrganizationPlan::Custom.to_string(), "custom");
        assert_eq!(OrganizationPlan::SelfHosted.to_string(), "self_hosted");
    }

    /// An installation's own organization allows more users, tenants, routes
    /// and agents than the largest tier sold.
    #[test]
    fn self_hosted_outgrows_every_sold_tier() {
        let self_hosted = OrganizationPlan::SelfHosted.default_limits();
        let business = PlanLimits::business();

        assert!(self_hosted.max_users > business.max_users);
        assert!(self_hosted.max_tenants_per_org > business.max_tenants_per_org);
        assert!(self_hosted.max_routes > business.max_routes);
        assert!(self_hosted.max_agents > business.max_agents);
    }

    /// The self-hosted plan has no trial, since nobody buys it.
    #[test]
    fn self_hosted_offers_no_trial() {
        assert!(OrganizationPlan::SelfHosted.trial_days().is_none());
    }

    /// An organization upgrades from Free to Business, or downgrades from
    /// Business to Starter. Both are allowed.
    #[test]
    fn sold_tiers_move_freely_between_each_other() {
        assert!(OrganizationPlan::Free.can_change_to(OrganizationPlan::Business));
        assert!(OrganizationPlan::Business.can_change_to(OrganizationPlan::Starter));
    }

    /// Neither Free nor Custom permits a move onto the self-hosted plan.
    #[test]
    fn no_organization_can_move_onto_self_hosted() {
        assert!(!OrganizationPlan::Free.can_change_to(OrganizationPlan::SelfHosted));
        assert!(!OrganizationPlan::Custom.can_change_to(OrganizationPlan::SelfHosted));
    }

    /// An installation's own organization is moved to Free or Business. Both
    /// are refused, so it is never capped at a tier nobody there bought.
    #[test]
    fn a_self_hosted_organization_cannot_move_to_a_sold_tier() {
        assert!(!OrganizationPlan::SelfHosted.can_change_to(OrganizationPlan::Free));
        assert!(!OrganizationPlan::SelfHosted.can_change_to(OrganizationPlan::Business));
    }

    /// Free costs nothing, Starter and Business are bought, and Custom and
    /// self-hosted are arranged by the platform.
    #[test]
    fn each_plan_is_sold_its_own_way() {
        assert_eq!(OrganizationPlan::Free.sale(), PlanSale::NoCost);
        assert_eq!(OrganizationPlan::Starter.sale(), PlanSale::SelfServed);
        assert_eq!(OrganizationPlan::Business.sale(), PlanSale::SelfServed);
        assert_eq!(OrganizationPlan::Custom.sale(), PlanSale::Arranged);
        assert_eq!(OrganizationPlan::SelfHosted.sale(), PlanSale::Arranged);
    }

    /// Acme uses two routes and fifty users. The free tier allows three
    /// routes and a hundred users, so Acme fits it.
    #[test]
    fn usage_inside_the_limits_fits() {
        let usage = PlanUsage {
            users: 50,
            routes: 2,
            ..PlanUsage::default()
        };

        assert!(PlanLimits::free().ensure_fits(&usage).is_ok());
    }

    /// Forty routes exceed Free's allowance, so the usage check refuses
    /// that plan.
    #[test]
    fn a_count_past_the_limit_does_not_fit() {
        let usage = PlanUsage {
            routes: 40,
            ..PlanUsage::default()
        };

        let refused = PlanLimits::free().ensure_fits(&usage);

        assert!(
            matches!(refused, Err(DomainError::Conflict(_))),
            "{refused:?}"
        );
    }

    /// Free's usage check refuses an organization with 5,000 users.
    #[test]
    fn more_users_than_allowed_do_not_fit() {
        let usage = PlanUsage {
            users: 5_000,
            ..PlanUsage::default()
        };

        assert!(matches!(
            PlanLimits::free().ensure_fits(&usage),
            Err(DomainError::Conflict(_))
        ));
    }

    /// A year of audit retention exceeds Free's allowance, so that usage
    /// is refused.
    #[test]
    fn a_longer_audit_retention_does_not_fit() {
        let usage = PlanUsage {
            audit_retention_days: 365,
            ..PlanUsage::default()
        };

        assert!(matches!(
            PlanLimits::free().ensure_fits(&usage),
            Err(DomainError::Conflict(_))
        ));
    }

    /// Starter refuses usage that includes a dedicated cluster.
    #[test]
    fn an_isolation_level_in_use_must_stay_included() {
        let usage = PlanUsage {
            isolation_in_use: vec![IsolationLevel::DedicatedCluster],
            ..PlanUsage::default()
        };

        assert!(matches!(
            PlanLimits::starter().ensure_fits(&usage),
            Err(DomainError::Conflict(_))
        ));
    }
}

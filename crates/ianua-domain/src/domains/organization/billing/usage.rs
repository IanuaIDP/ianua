//! What an organization uses now, for checking a plan against before it
//! moves there.

use crate::domains::organization::billing::plan::PlanLimits;
use crate::domains::tenant::provisioning::infrastructure::IsolationLevel;

/// What an organization uses now, counted across its tenants, for checking
/// a plan against before it moves there.
///
/// The organization-wide counts are its users and tenants. Every other count
/// is the most any one tenant uses, since those limits apply per tenant.
/// The application counts it fresh, just before the change.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlanUsage {
    /// Registered users across all tenants.
    pub users: u64,
    /// Tenants the organization has.
    pub tenants: u32,
    /// Proxy routes in the busiest tenant.
    pub routes: u32,
    /// DNS record sets in the busiest tenant.
    pub dns_record_sets: u32,
    /// Domains in the busiest tenant.
    pub domains: u32,
    /// API keys in the busiest tenant.
    pub api_keys: u32,
    /// OAuth clients in the busiest tenant.
    pub oauth_clients: u32,
    /// Roles in the busiest tenant.
    pub roles: u32,
    /// Groups in the busiest tenant.
    pub groups: u32,
    /// Webhook subscriptions in the busiest tenant.
    pub webhooks: u32,
    /// Federation connections in the busiest tenant.
    pub federation_connections: u32,
    /// Consumers in the busiest tenant.
    pub consumers: u32,
    /// Services in the busiest tenant.
    pub services: u32,
    /// Stream routes in the busiest tenant.
    pub stream_routes: u32,
    /// Egress policies in the busiest tenant.
    pub egress_policies: u32,
    /// Resource types in the busiest tenant.
    pub resource_types: u32,
    /// Custom user attributes in the busiest tenant.
    pub user_attributes: u32,
    /// Agent identities in the busiest tenant.
    pub agents: u32,
    /// Registered agent tools in the busiest tenant.
    pub agent_tools: u32,
    /// Connected model providers in the busiest tenant.
    pub model_providers: u32,
    /// Workflows in the busiest tenant.
    pub workflows: u32,
    /// Sandboxes in the busiest tenant.
    pub sandboxes: u32,
    /// The most SAML apps the tenant signs people in to as their identity provider any one tenant has.
    pub saml_service_providers: u32,
    /// The most accounts applications bind to the tenant's LDAP directory as any one tenant has.
    pub directory_service_accounts: u32,
    /// The most message subscriptions on the tenant's topics any one tenant has.
    pub message_subscriptions: u32,
    /// The most private network connectors any one tenant has.
    pub connectors: u32,
    /// The most places the gateway ships request records to any one tenant has.
    pub log_targets: u32,
    /// The most places the audit trail streams to any one tenant has.
    pub audit_streams: u32,
    /// The channels the organization posts its notifications to.
    pub notification_destinations: u32,
    /// The longest audit retention any tenant keeps, in days.
    pub audit_retention_days: u32,
    /// Every isolation level a tenant of the organization is placed on.
    pub isolation_in_use: Vec<IsolationLevel>,
}

impl PlanUsage {
    /// The first count this usage goes past under `limits`, with what they
    /// allow.
    pub(super) fn first_overage_under(&self, limits: &PlanLimits) -> Option<(&'static str, u64)> {
        if self.users > limits.max_users {
            return Some(("users", limits.max_users));
        }
        self.gateway_counts(limits)
            .into_iter()
            .chain(self.account_counts(limits))
            .chain(self.automation_counts(limits))
            .chain(self.connection_counts(limits))
            .find(|(_, used, allowed)| used > allowed)
            .map(|(what, _, allowed)| (what, u64::from(allowed)))
    }

    /// What this usage counts of tenants, domains and the gateway, beside what
    /// `limits` allow.
    fn gateway_counts(&self, limits: &PlanLimits) -> [(&'static str, u32, u32); 8] {
        [
            ("tenants", self.tenants, limits.max_tenants_per_org),
            ("routes", self.routes, limits.max_routes),
            (
                "DNS record sets",
                self.dns_record_sets,
                limits.max_dns_record_sets,
            ),
            ("domains", self.domains, limits.max_domains),
            ("consumers", self.consumers, limits.max_consumers),
            ("services", self.services, limits.max_services),
            (
                "stream routes",
                self.stream_routes,
                limits.max_stream_routes,
            ),
            (
                "egress policies",
                self.egress_policies,
                limits.max_egress_policies,
            ),
        ]
    }

    /// What this usage counts of keys, clients, access and directory data,
    /// beside what `limits` allow.
    fn account_counts(&self, limits: &PlanLimits) -> [(&'static str, u32, u32); 8] {
        [
            ("API keys", self.api_keys, limits.max_api_keys),
            (
                "OAuth clients",
                self.oauth_clients,
                limits.max_oauth_clients,
            ),
            ("roles", self.roles, limits.max_roles),
            ("groups", self.groups, limits.max_groups),
            ("webhooks", self.webhooks, limits.max_webhooks),
            (
                "federation connections",
                self.federation_connections,
                limits.max_federation_connections,
            ),
            (
                "resource types",
                self.resource_types,
                limits.max_resource_types,
            ),
            (
                "user attributes",
                self.user_attributes,
                limits.max_user_attributes,
            ),
        ]
    }

    /// What this usage counts of agents and workflows, and the audit retention
    /// it keeps, beside what `limits` allow.
    fn automation_counts(&self, limits: &PlanLimits) -> [(&'static str, u32, u32); 6] {
        [
            ("agents", self.agents, limits.max_agents),
            ("agent tools", self.agent_tools, limits.max_agent_tools),
            (
                "model providers",
                self.model_providers,
                limits.max_model_providers,
            ),
            ("workflows", self.workflows, limits.max_workflows),
            ("sandboxes", self.sandboxes, limits.max_sandboxes),
            (
                "days of audit retention",
                self.audit_retention_days,
                limits.audit_retention_days,
            ),
        ]
    }

    /// What this usage counts of the tenant's links to other systems, beside
    /// what `limits` allow.
    fn connection_counts(&self, limits: &PlanLimits) -> [(&'static str, u32, u32); 7] {
        [
            (
                "SAML apps",
                self.saml_service_providers,
                limits.max_saml_service_providers,
            ),
            (
                "directory service accounts",
                self.directory_service_accounts,
                limits.max_directory_service_accounts,
            ),
            (
                "message subscriptions",
                self.message_subscriptions,
                limits.max_message_subscriptions,
            ),
            ("connectors", self.connectors, limits.max_connectors),
            ("log targets", self.log_targets, limits.max_log_targets),
            (
                "audit streams",
                self.audit_streams,
                limits.max_audit_streams,
            ),
            (
                "notification destinations",
                self.notification_destinations,
                limits.max_notification_destinations,
            ),
        ]
    }
}

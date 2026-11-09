//! What one database answers of an organization's usage, and the whole
//! usage folded from every database's answer.

use ianua_domain::domains::organization::billing::usage::PlanUsage;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::domains::tenant::provisioning::infrastructure::IsolationLevel;
use ianua_domain::shared::errors::DomainError;

/// The counts one database holds for the organization's tenants in it: the
/// accounts of all of them, and for every other kind the most any one of
/// them holds. The usage query fills it.
pub(super) struct UsageRecord {
    pub(super) users: i64,
    pub(super) routes: i64,
    pub(super) domains: i64,
    pub(super) api_keys: i64,
    pub(super) oauth_clients: i64,
    pub(super) roles: i64,
    pub(super) groups: i64,
    pub(super) webhooks: i64,
    pub(super) federation_connections: i64,
    pub(super) consumers: i64,
    pub(super) services: i64,
    pub(super) stream_routes: i64,
    pub(super) egress_policies: i64,
    pub(super) resource_types: i64,
    pub(super) user_attributes: i64,
    pub(super) agents: i64,
    pub(super) agent_tools: i64,
    pub(super) model_providers: i64,
    pub(super) workflows: i64,
    pub(super) sandboxes: i64,
    pub(super) saml_service_providers: i64,
    pub(super) directory_service_accounts: i64,
    pub(super) message_subscriptions: i64,
    pub(super) connectors: i64,
    pub(super) log_targets: i64,
    pub(super) audit_streams: i64,
}

/// Everything an organization's usage is folded from.
pub(super) struct Counted<'a> {
    /// The organization's tenants not deleted.
    pub(super) tenants: &'a [&'a Tenant],
    /// Each database's counts for the tenants in it.
    pub(super) databases: Vec<UsageRecord>,
    /// The most record sets any one tenant holds.
    pub(super) dns_record_sets: i64,
    /// The channels the organization posts notifications to.
    pub(super) notification_destinations: i64,
}

/// A count read back, as the usage holds it.
fn held(count: i64) -> Result<u32, DomainError> {
    u32::try_from(count).map_err(DomainError::infra)
}

/// The usage `counted` adds up to: accounts summed over every database,
/// every other count the most any database answered.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a count read back is below
/// zero or past what the usage holds.
pub(super) fn into_usage(counted: Counted<'_>) -> Result<PlanUsage, DomainError> {
    let tenants = counted.tenants;
    let mut usage = PlanUsage {
        tenants: u32::try_from(tenants.len()).map_err(DomainError::infra)?,
        dns_record_sets: held(counted.dns_record_sets)?,
        notification_destinations: held(counted.notification_destinations)?,
        audit_retention_days: longest_retention(tenants),
        isolation_in_use: isolation_in_use(tenants),
        ..PlanUsage::default()
    };
    for record in counted.databases {
        usage = record.added_to(usage)?;
    }
    Ok(usage)
}

/// The longest audit retention any of `tenants` keeps, in days.
fn longest_retention(tenants: &[&Tenant]) -> u32 {
    tenants
        .iter()
        .map(|tenant| tenant.compliance().audit_retention_days())
        .max()
        .unwrap_or(0)
}

/// Every isolation level one of `tenants` is placed on, each once.
fn isolation_in_use(tenants: &[&Tenant]) -> Vec<IsolationLevel> {
    let mut levels: Vec<IsolationLevel> = Vec::new();
    for level in tenants.iter().map(|tenant| tenant.residency().isolation()) {
        if !levels.contains(&level) {
            levels.push(level);
        }
    }
    levels
}

impl UsageRecord {
    /// `usage` with this database's counts added: its accounts summed in,
    /// every other count the larger of the two.
    fn added_to(self, usage: PlanUsage) -> Result<PlanUsage, DomainError> {
        let usage = self.add_access_counts(usage)?;
        Ok(PlanUsage {
            consumers: usage.consumers.max(held(self.consumers)?),
            services: usage.services.max(held(self.services)?),
            stream_routes: usage.stream_routes.max(held(self.stream_routes)?),
            egress_policies: usage.egress_policies.max(held(self.egress_policies)?),
            resource_types: usage.resource_types.max(held(self.resource_types)?),
            user_attributes: usage.user_attributes.max(held(self.user_attributes)?),
            agents: usage.agents.max(held(self.agents)?),
            agent_tools: usage.agent_tools.max(held(self.agent_tools)?),
            model_providers: usage.model_providers.max(held(self.model_providers)?),
            workflows: usage.workflows.max(held(self.workflows)?),
            sandboxes: usage.sandboxes.max(held(self.sandboxes)?),
            saml_service_providers: usage
                .saml_service_providers
                .max(held(self.saml_service_providers)?),
            directory_service_accounts: usage
                .directory_service_accounts
                .max(held(self.directory_service_accounts)?),
            message_subscriptions: usage
                .message_subscriptions
                .max(held(self.message_subscriptions)?),
            connectors: usage.connectors.max(held(self.connectors)?),
            log_targets: usage.log_targets.max(held(self.log_targets)?),
            audit_streams: usage.audit_streams.max(held(self.audit_streams)?),
            ..usage
        })
    }

    /// Adds accounts and takes maxima for access resources before the remaining products.
    fn add_access_counts(&self, usage: PlanUsage) -> Result<PlanUsage, DomainError> {
        let users = u64::try_from(self.users).map_err(DomainError::infra)?;
        Ok(PlanUsage {
            users: usage
                .users
                .checked_add(users)
                .ok_or_else(|| DomainError::infra_msg("an organization's accounts overflow"))?,
            routes: usage.routes.max(held(self.routes)?),
            domains: usage.domains.max(held(self.domains)?),
            api_keys: usage.api_keys.max(held(self.api_keys)?),
            oauth_clients: usage.oauth_clients.max(held(self.oauth_clients)?),
            roles: usage.roles.max(held(self.roles)?),
            groups: usage.groups.max(held(self.groups)?),
            webhooks: usage.webhooks.max(held(self.webhooks)?),
            federation_connections: usage
                .federation_connections
                .max(held(self.federation_connections)?),
            ..usage
        })
    }
}

//! Plan limit enforcement ports.

use async_trait::async_trait;
use ianua_domain::domains::organization::billing::plan::PlanLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, OperatorId, OrganizationId, TenantId};

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Resource types that have plan-enforced limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    /// Registered users in a tenant.
    Users,
    /// Tenants in an organization.
    Tenants,
    /// Proxy routes.
    Routes,
    /// Record sets across every zone a tenant has delegated to us.
    DnsRecordSets,
    /// Domains a tenant has registered.
    ///
    /// Bounded because a hostname is claimed globally: registering one stops
    /// every other tenant from registering it, whether or not the claimant
    /// ever proves they own it. Without a ceiling, one tenant can take names
    /// out of circulation by the thousand.
    Domains,
    /// Credentials counted against the tenant's issuance allowance.
    ApiKeys,
    /// OAuth clients.
    OAuthClients,
    /// Permission bundles counted before another can be created.
    Roles,
    /// Membership containers counted before another can be created.
    Groups,
    /// Webhook subscriptions.
    Webhooks,
    /// Federation connections (SAML/OIDC).
    FederationConnections,
    /// SAML apps the tenant signs people in to as their identity provider.
    SamlServiceProviders,
    /// Accounts applications bind to the tenant's LDAP directory as.
    DirectoryServiceAccounts,
    /// Subscriptions on the tenant's message topics.
    MessageSubscriptions,
    /// Private network connectors.
    Connectors,
    /// Places the gateway ships request records to.
    LogTargets,
    /// Places the audit trail streams to.
    AuditStreams,
    /// Channels an organization posts notifications to.
    NotificationDestinations,
    /// Consumers: the non-human callers a tenant lets through.
    Consumers,
    /// Services: the backends routes forward to.
    Services,
    /// Stream routes: the ports the proxy listens on below HTTP.
    StreamRoutes,
    /// Egress policies: services given a way out through the gateway.
    EgressPolicies,
    /// Resource types: the entries in a tenant's permission catalogue.
    ResourceTypes,
    /// Custom user attributes a tenant has declared.
    ///
    /// Bounded because every declared attribute is a column a directory may be
    /// asked to carry, filter or order by, and each one adds work to a listing
    /// that every administrator runs.
    UserAttributes,
    /// Agent identities.
    Agents,
    /// Registered agent tools.
    AgentTools,
    /// Connected model providers.
    ModelProviders,
    /// Workflows, counting each workflow once whatever its versions.
    Workflows,
    /// Sandboxes, counting each sandbox once whatever its versions.
    Sandboxes,
    /// Trials of sandbox versions still running, not trials ever started.
    RunningTrials,
    /// Evaluations of workflows still running, not evaluations ever started.
    RunningEvaluations,
    /// Sandboxes of the company's own image, counting each once whatever
    /// its versions.
    OwnImages,
    /// Memories, those waiting to be deleted among them.
    Memories,
    /// Runs in flight (running or awaiting approval), not runs ever started.
    ActiveAgentRuns,
    /// Approval requests awaiting a decision.
    PendingApprovals,
}

/// Dyn-safe port for counting current resource usage.
///
/// The infra layer implements this with COUNT queries against
/// the appropriate tables, inside the tenant asked about.
#[async_trait]
pub trait ResourceCounter: Send + Sync + TenantScoped {
    /// Counts tenant-scoped resources.
    ///
    /// The count holds what the tenant holds against its plan until the
    /// running unit of work settles: another count of the tenant waits for
    /// it. So a check at the ceiling and the creation it allows, in one
    /// unit, are never raced by a second creation counted at the same
    /// moment, which then counts the first. Outside a unit the hold ends
    /// with the count.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the count cannot be read.
    async fn count_for_tenant(
        &self,
        tenant_id: &ScopedTenant,
        kind: ResourceKind,
    ) -> Result<u64, DomainError>;
}

/// Dyn-safe port for counting an organization's own resources, such as its
/// tenants.
///
/// Kept apart from [`ResourceCounter`], whose every method reads inside one
/// tenant: an organization's count reads across its tenants.
#[async_trait]
pub trait OrgResourceCounter: Send + Sync {
    /// Counts `kind` across the organization.
    ///
    /// Like [`ResourceCounter::count_for_tenant`], the count holds what the
    /// organization holds until the running unit of work settles, so two
    /// creations at its ceiling at once are counted one after the other.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the count cannot be read.
    async fn count_for_org(
        &self,
        organization_id: &OrganizationId,
        kind: ResourceKind,
    ) -> Result<u64, DomainError>;
}

/// Whose allowance a signed-in request is counted against.
///
/// Every caller has one. Without that, an organization member or an
/// operator, who belongs to no tenant, would call the API as often as they
/// liked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateBudget {
    /// A tenant's: its users, keys and directory binds.
    Tenant(TenantId),
    /// An organization's: its members, in whichever tenant they act.
    Organization(OrganizationId),
    /// One operator's.
    Operator(OperatorId),
}

/// Dyn-safe port for API rate limiting per budget.
///
/// Checked by the rate limit middleware on every API request.
/// The adapter counts requests per budget in a fixed one-minute window,
/// held in the process.
#[async_trait]
pub trait RateLimiter: Send + Sync {
    /// Records a request against `budget` and checks whether the rate
    /// limit is exceeded.
    ///
    /// Returns the number of requests remaining in the current window.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Forbidden` if the limit is exceeded.
    async fn check_and_increment(
        &self,
        budget: &RateBudget,
        limit_per_minute: u32,
    ) -> Result<u32, DomainError>;
}

/// What an emailed link is for. Each purpose has its own allowance, so asking
/// for a sign-in link does not hold back a password reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MailPurpose {
    /// A tenant user's password reset link.
    PasswordReset,
    /// A tenant user's sign-in link.
    MagicLink,
    /// An org user's password reset link.
    OrgPasswordReset,
    /// An invitation to a tenant, sent or sent again by an admin.
    Invitation,
    /// An invitation to an organization, sent or sent again by an owner.
    OrgInvitation,
    /// The link confirming an address an admin gave a tenant user.
    AddressConfirmation,
    /// The link confirming an address an owner gave a member, or a new
    /// member's first one.
    OrgAddressConfirmation,
    /// A sign-up's link, or the notice to an address that has an account.
    Signup,
}

/// Dyn-safe port letting one emailed link through per address, per purpose,
/// per minute.
///
/// The per-IP rate limit stops one source asking too often; this stops many
/// sources filling one inbox. A request by address held back still answers
/// as though the mail went, so the answer says nothing about the address.
/// One an admin or owner made is told to wait, as they named the address
/// themselves.
#[async_trait]
pub trait MailThrottle: Send + Sync {
    /// Whether a `purpose` link may be mailed to `recipient` now. Admitting
    /// counts as the minute's mail.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the allowance cannot be read.
    async fn admit(&self, purpose: MailPurpose, recipient: &Email) -> Result<bool, DomainError>;
}

/// Dyn-safe port for enforcing plan limits before creating resources.
///
/// Use cases call this before creating any countable resource.
/// The implementation counts current usage and compares against the
/// pre-resolved `PlanLimits` from the `CallerContext`.
///
/// `check_tenant_limit` counts resources within a single tenant;
/// `check_org_limit` counts across all tenants in the org.
///
/// A check holds the count it made until the running unit of work settles
/// (see [`ResourceCounter::count_for_tenant`]), so a use case checks and
/// creates in the one unit a request runs in, and concurrent creations at
/// the ceiling cannot both pass.
#[async_trait]
pub trait LimitEnforcer: Send + Sync {
    /// Checks whether creating one more resource of the given kind
    /// within a tenant is allowed by the plan limits.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Forbidden` with a descriptive message
    /// if the limit would be exceeded.
    async fn check_tenant_limit(
        &self,
        limits: &PlanLimits,
        tenant_id: &ScopedTenant,
        kind: ResourceKind,
    ) -> Result<(), DomainError>;

    /// Checks whether `wanted` more resources of the given kind fit within
    /// the tenant's plan limits at once.
    ///
    /// For a batch that must land whole or not at all, such as every run of a
    /// flow stage: checking one at a time would create the first few before
    /// refusing the rest.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Forbidden` if the batch would exceed the limit.
    async fn check_tenant_room(
        &self,
        limits: &PlanLimits,
        tenant_id: &ScopedTenant,
        kind: ResourceKind,
        wanted: u64,
    ) -> Result<(), DomainError>;

    /// How many more of `kind` the tenant's plan has room for now: its
    /// ceiling less what the tenant holds, never below zero.
    ///
    /// For work that fills what room is left and sets the rest aside, such
    /// as a chunk of an import, which asks again each time it runs rather
    /// than trusting a count made when the work was started.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when what the tenant holds cannot be counted.
    async fn tenant_room(
        &self,
        limits: &PlanLimits,
        tenant_id: &ScopedTenant,
        kind: ResourceKind,
    ) -> Result<u64, DomainError>;

    /// Checks whether creating one more org-scoped resource
    /// (e.g. a new tenant) is allowed by the plan limits.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Forbidden` if the limit would be exceeded.
    async fn check_org_limit(
        &self,
        limits: &PlanLimits,
        organization_id: &OrganizationId,
        kind: ResourceKind,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port for looking up a tenant's plan limits when no caller brought
/// them.
///
/// A request carries its plan limits in the `CallerContext`. Work the worker
/// does on a tenant's behalf, such as launching a flow's next stage, has no
/// request, and must still be held to the same plan.
#[async_trait]
pub trait PlanLimitsSource: Send + Sync {
    /// The plan limits that apply to `tenant_id`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::NotFound` if the tenant or its organization is
    /// gone, and `DomainError::Infrastructure` if the lookup fails. Callers
    /// refuse the work either way: a tenant whose plan cannot be read gets no
    /// allowance.
    async fn for_tenant(&self, tenant_id: &TenantId) -> Result<PlanLimits, DomainError>;
}

//! Keeping watch over agents: what they touched, their standing and
//! exposure, reviews, approvals and their activity.

use async_trait::async_trait;
use ianua_domain::domains::agents::execution::convergence::Touch;
use ianua_domain::domains::agents::identity::exposure_reset::ExposureReset;
use ianua_domain::domains::agents::identity::standing::AgentStanding;
use ianua_domain::domains::agents::oversight::approval::{ApprovalAction, ApprovalRequest};
use ianua_domain::domains::agents::oversight::approval_status::ApprovalStatus;
use ianua_domain::domains::agents::oversight::review::ReviewAssignment;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentId, ApprovalId, DelegationId, PrincipalRef, ReviewAssignmentId};
use time::OffsetDateTime;

use crate::listing::Listing;
use crate::ports::TenantScoped;
use crate::ports::audit::{AuditLogFilter, AuditLogPage, AuditLogSortField};
use crate::tenancy::ScopedTenant;

/// One touch to record on a path, and how far back the path's ledger keeps
/// touches.
#[derive(Debug, Clone, Copy)]
pub struct TouchEntry<'a> {
    /// The path the agent touched.
    pub path: &'a str,
    /// Who touched it and how.
    pub touch: &'a Touch,
    /// When.
    pub at: OffsetDateTime,
    /// Touches older than this are dropped from the path's ledger.
    pub forget_before: OffsetDateTime,
}

/// Dyn-safe port for the recent agent touches on each path: what the
/// convergence detector looks back over.
#[async_trait]
pub trait TouchLedger: Send + Sync + TenantScoped {
    /// The touches on `path` at or after `since`, oldest first.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn since(
        &self,
        tenant_id: &ScopedTenant,
        path: &str,
        since: OffsetDateTime,
    ) -> Result<Vec<Touch>, DomainError>;

    /// Records a touch on `path` at `at`, and forgets the path's touches from
    /// before `forget_before`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn record(
        &self,
        tenant_id: &ScopedTenant,
        entry: &TouchEntry<'_>,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port for the review assignments people make between agents.
#[async_trait]
pub trait ReviewAssignmentStore: Send + Sync + TenantScoped {
    /// Inserts or updates an assignment.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        assignment: &ReviewAssignment<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Finds an assignment by id.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ReviewAssignmentId,
    ) -> Result<Option<ReviewAssignment<ResolvedTenant>>, DomainError>;

    /// The assignments touching `agent`, as reviewer or reviewed, newest
    /// first, ended ones included.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_for_agent(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentId,
    ) -> Result<Vec<ReviewAssignment<ResolvedTenant>>, DomainError>;
}

/// Dyn-safe port for checking whether a delegation has been revoked.
///
/// Consulted by the proxy on every agent request (keyed by the token's `jti`,
/// which is the delegation id) so revocation takes effect on the next request
/// rather than only when the token expires. A missing delegation is treated as
/// revoked (deny-by-default), and so is one drawing its authority from a
/// revoked delegation, or minted with a key since revoked.
#[async_trait]
pub trait DelegationRevocationCheck: Send + Sync + TenantScoped {
    /// Whether the delegation is revoked or no longer exists, or anything
    /// it stands on is: a delegation above it, or the key it was minted with.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read.
    async fn is_revoked(
        &self,
        tenant_id: &ScopedTenant,
        delegation_id: &DelegationId,
    ) -> Result<bool, DomainError>;
}

/// Dyn-safe port for reading whether an agent may act right now.
///
/// Consulted by the proxy on every agent request (keyed by the token's `act`,
/// the agent id) so a suspension, revocation, or forced re-attestation takes
/// effect on the next request rather than only when the token expires. A
/// missing agent is [`AgentStanding::Revoked`] (deny-by-default).
#[async_trait]
pub trait AgentStandingCheck: Send + Sync + TenantScoped {
    /// The agent's current standing.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read.
    async fn standing(
        &self,
        tenant_id: &ScopedTenant,
        agent_id: &AgentId,
    ) -> Result<AgentStanding, DomainError>;
}

/// Dyn-safe port for the most sensitive data an agent has touched, its
/// high-water mark, which decides where it may send anything next.
///
/// An agent may reach a route only if the route is cleared at least as high as
/// the agent's mark, and reaching it raises the mark to the route's class. Data
/// therefore only ever moves to places cleared for it, however many agents it
/// passes through: whatever agent A could write to a route, the route's class
/// is at least A's mark, and anyone who reads it there takes that class on.
#[async_trait]
pub trait AgentExposureGate: Send + Sync + TenantScoped {
    /// Admits a request to a route of `class` if the agent's mark does not
    /// exceed it, raising the mark to `class` in the same step. Returns
    /// whether the request was admitted.
    ///
    /// Atomic: the check and the raise cannot be separated by a concurrent
    /// request.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the mark cannot be read or
    /// written.
    async fn admit(
        &self,
        tenant_id: &ScopedTenant,
        agent_id: &AgentId,
        class: DataClassLevel,
    ) -> Result<bool, DomainError>;

    /// The agent's current mark. An agent that has touched nothing is
    /// [`DataClassLevel::Public`].
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the mark cannot be read.
    async fn current(
        &self,
        tenant_id: &ScopedTenant,
        agent_id: &AgentId,
    ) -> Result<DataClassLevel, DomainError>;

    /// Lowers the mark of the agent `reset` names, only if it is still the
    /// mark the person saw and the agent is still stopped, returning whether
    /// it was lowered.
    ///
    /// Conditional so that an agent resumed, and reading something sensitive,
    /// between the person's check and this write is not given a lower mark
    /// than what it now holds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the mark cannot be read or
    /// written.
    async fn reset(
        &self,
        tenant_id: &ScopedTenant,
        reset: &ExposureReset<ResolvedTenant>,
    ) -> Result<bool, DomainError>;
}

/// Dyn-safe port for reading an agent's activity timeline from the audit log.
///
/// Returns the individual audit records the agent produced, filtered to
/// `actor = agent:{id}` within the tenant, for the "what did this agent do,
/// for whom, allowed or denied" view. Reuses the audit-log query types; an
/// actor the filter names gives way to the agent, so the view never reads
/// someone else's records.
#[async_trait]
pub trait AgentActivityStore: Send + Sync + TenantScoped {
    /// One page of the audit records produced by an agent, in the
    /// listing's order.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the audit log cannot be
    /// read, or a validation error when the page's cursor was made for
    /// another sort.
    async fn query(
        &self,
        tenant_id: &ScopedTenant,
        agent_id: &AgentId,
        listing: Listing<'_, &AuditLogFilter, AuditLogSortField>,
    ) -> Result<AuditLogPage, DomainError>;

    /// How many audit records the agent produced that `filter` admits, in
    /// one count query.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the audit log cannot be read.
    async fn count(
        &self,
        tenant_id: &ScopedTenant,
        agent_id: &AgentId,
        filter: &AuditLogFilter,
    ) -> Result<u64, DomainError>;
}

/// Dyn-safe port for persisting human-in-the-loop action approval requests.
#[async_trait]
pub trait ApprovalStore: Send + Sync + TenantScoped {
    /// Finds an approval request by ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ApprovalId,
    ) -> Result<Option<ApprovalRequest<ResolvedTenant>>, DomainError>;

    /// Lists an agent's approval requests, newest first.
    ///
    /// `status` narrows to one lifecycle state; `None` returns the full
    /// history, resolved requests included.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_for_agent(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentId,
        status: Option<ApprovalStatus>,
    ) -> Result<Vec<ApprovalRequest<ResolvedTenant>>, DomainError>;

    /// Lists every approval request of the tenant, whatever its agent,
    /// newest first, narrowed to `status` when one is given.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_in_tenant(
        &self,
        tenant_id: &ScopedTenant,
        status: Option<ApprovalStatus>,
    ) -> Result<Vec<ApprovalRequest<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated approval request.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        approval: &ApprovalRequest<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// The request still awaiting a decision on exactly `action` under
    /// `delegation`, if one is open and inside its window.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_pending_for_action(
        &self,
        tenant_id: &ScopedTenant,
        delegation: &DelegationId,
        action: &ApprovalAction,
        now: OffsetDateTime,
    ) -> Result<Option<ApprovalRequest<ResolvedTenant>>, DomainError>;

    /// Spends one approved, unexpired approval for exactly `action` under
    /// `delegation`, returning whether one was spent.
    ///
    /// Atomic: two requests racing for the same approval cannot both spend
    /// it. Like revocation this is a monotonic flag written without loading
    /// the aggregate, because a load-then-save would be the race itself.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn consume_for_action(
        &self,
        tenant_id: &ScopedTenant,
        delegation: &DelegationId,
        action: &ApprovalAction,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError>;

    /// How many requests are awaiting a decision under `delegation`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn count_pending_for_delegation(
        &self,
        tenant_id: &ScopedTenant,
        delegation: &DelegationId,
        now: OffsetDateTime,
    ) -> Result<u32, DomainError>;

    /// How many approvals `approver` has given in the tenant since `since`,
    /// first signatures of two-person approvals included. Denials are not
    /// counted: refusing is never what a cap guards against.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn count_signed_by(
        &self,
        tenant_id: &ScopedTenant,
        approver: &PrincipalRef,
        since: OffsetDateTime,
    ) -> Result<u32, DomainError>;
}

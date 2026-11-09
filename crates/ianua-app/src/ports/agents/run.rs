//! Running an agent: the run, its lease and cancellation, the task token it
//! acts with, and the budget it spends.

use async_trait::async_trait;
pub use ianua_domain::domains::agents::authority::capability::BudgetKey;
use ianua_domain::domains::agents::authority::delegation::Delegation;
use ianua_domain::domains::agents::authority::intent::IntentEnvelope;
use ianua_domain::domains::agents::execution::run::{AgentRun, CancelOrder, RunGoal, RunStatus};
use ianua_domain::domains::agents::execution::tool::ToolName;
use ianua_domain::domains::agents::execution::usage::Spend;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    ActionClass, AgentId, AgentRunId, DelegationId, Issuer, ModelProviderId, Seconds, TenantId,
};
use time::OffsetDateTime;

use crate::listing::{Page, PageRequest};
use crate::ports::TenantScoped;
use crate::ports::agents::RunSummary;
use crate::tenancy::ScopedTenant;

/// Request to run an agent toward a goal: the command a run launch carries.
///
/// Owned by the port layer, so nothing inside depends outward on a use case.
pub struct RunAgentRequest {
    /// The acting agent.
    pub agent_id: AgentId,
    /// The model provider to reason with.
    pub provider_id: ModelProviderId,
    /// The goal to pursue.
    pub goal: RunGoal,
    /// The purpose envelope bounding which tool actions are permitted.
    pub purpose: IntentEnvelope,
    /// The tools granted to this run; empty means every in-purpose tool.
    pub tool_names: Vec<ToolName>,
    /// Action classes whose tool calls require human approval before running.
    pub approval_classes: Vec<ActionClass>,
    /// The delegation the run acts under. Tool calls route through the proxy
    /// bearing a task token minted from it. Left out, the agent's own is
    /// derived; with none at all, the run may not call tools.
    pub delegation_id: Option<DelegationId>,
    /// The maximum number of loop iterations asked for; zero asks for the
    /// deployment's default, and more than its maximum gets the maximum.
    pub max_steps: u32,
    /// The most the run may spend on its model before it stops, or that it
    /// has no spend limit.
    pub spend_limit: Restriction<Spend>,
    /// What the run may spend before it pauses for a person to let it go
    /// on, or that it never pauses over spend.
    pub ask_past: Restriction<Spend>,
}

/// The version of a run as it was read: the time it last changed.
///
/// A run is changed by the worker driving it and by people steering it. A
/// change saved over a version that moved on would undo the other's: a
/// pause saved while the worker takes a step is overwritten by the step.
/// So those writes go through [`RunStore::save_unchanged_since`] with the
/// version they read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunVersion(OffsetDateTime);

impl RunVersion {
    /// The version `run` is at. Only a run read back from the store, or
    /// the version a save gave back, names a version the store can compare:
    /// a run changed in memory carries a time the store has not kept.
    #[must_use]
    pub fn of(run: &AgentRun<ResolvedTenant>) -> Self {
        Self(run.updated_at())
    }

    /// The version a store kept a run at: `changed_at`, the time the run
    /// last changed as the store wrote it. Only a store names a version
    /// this way, from the time it gave back on writing.
    #[must_use]
    pub fn stored(changed_at: OffsetDateTime) -> Self {
        Self(changed_at)
    }

    /// The time the run last changed at this version.
    #[must_use]
    pub fn changed_at(self) -> OffsetDateTime {
        self.0
    }
}

/// A signed task token an agent presents to the proxy as a bearer credential.
///
/// A secret: its `Debug` is redacted and the raw value is reachable only through
/// [`reveal`](Self::reveal), so a token can't leak into a log or a span by way of
/// a derived `Debug` on a struct that carries it.
#[derive(Clone)]
pub struct TaskToken(Secret);

impl TaskToken {
    /// Wraps a signed token string.
    #[must_use]
    pub fn new(token: impl Into<String>) -> Self {
        Self(Secret::new(token))
    }

    /// The raw token, for presenting as a bearer credential. Handle as a secret:
    /// never log it, never put it in an error or a span.
    #[must_use]
    pub fn reveal(&self) -> &str {
        self.0.expose()
    }
}

impl std::fmt::Debug for TaskToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TaskToken(***)")
    }
}

/// Dyn-safe port for persisting agent runs.
#[async_trait]
pub trait RunStore: Send + Sync + TenantScoped {
    /// Saves a new or updated run.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        run: &AgentRun<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Saves `run` only when the stored run is still at `read`, the version
    /// the caller read before changing it, and gives back the version it is
    /// stored at now.
    ///
    /// The check and the write are one statement: the adapter writes where
    /// the stored version still equals `read`, and returns the version as
    /// it stored it, at the precision it keeps times in. The run must
    /// already be stored.
    ///
    /// # Errors
    ///
    /// - `DomainError::Conflict` when the stored run changed since `read`,
    ///   or is gone.
    /// - `DomainError::Infrastructure` on persistence failure.
    async fn save_unchanged_since(
        &self,
        tenant_id: &ScopedTenant,
        run: &AgentRun<ResolvedTenant>,
        read: RunVersion,
    ) -> Result<RunVersion, DomainError>;

    /// Finds a run by ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AgentRunId,
    ) -> Result<Option<AgentRun<ResolvedTenant>>, DomainError>;

    /// Lists one page of an agent's run summaries, newest first, without steps.
    ///
    /// `status` narrows to one lifecycle state. `AwaitingApproval` is how a
    /// caller finds the runs paused on a tool call needing sign-off; `None`
    /// includes every lifecycle state.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_for_agent(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentId,
        status: Option<RunStatus>,
        page: &PageRequest,
    ) -> Result<Page<RunSummary>, DomainError>;

    /// Lists one page of the tenant's run summaries, newest first, without
    /// steps and narrowed to `status` when one is given.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_in_tenant(
        &self,
        tenant_id: &ScopedTenant,
        status: Option<RunStatus>,
        page: &PageRequest,
    ) -> Result<Page<RunSummary>, DomainError>;
}

/// Dyn-safe port for the cross-node run kill-switch. The loop checks
/// cancellation between steps; a run's owner requests it from any node.
///
/// An order is kept beside the run it stops, in the run's tenant, so one
/// tenant can never stop or read the orders of another's runs.
///
/// Separate from [`RunLease`] on purpose: cancellation is a signal, the lease is
/// a distributed lock: different concerns with different lifecycles.
#[async_trait]
pub trait RunCancellation: Send + Sync + TenantScoped {
    /// Stores a person's order to stop a run of `tenant_id`, so the worker
    /// driving it applies the order between steps. A later order for the
    /// same run takes the place of the earlier one.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the order cannot be
    /// stored, or the tenant keeps no such run. The caller reports the stop
    /// as failed: a stop that was not recorded must not be answered as done.
    async fn request_cancel(
        &self,
        tenant_id: &ScopedTenant,
        order: &CancelOrder,
    ) -> Result<(), DomainError>;

    /// The order to stop a run of `tenant_id`, when one was given.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the orders cannot be read.
    /// A caller stops the run then: a kill switch that cannot be read must
    /// not read as "keep going".
    async fn order_for(
        &self,
        tenant_id: &ScopedTenant,
        run_id: &AgentRunId,
    ) -> Result<Option<CancelOrder>, DomainError>;

    /// Forgets the order for a finished run of `tenant_id`.
    async fn clear(&self, tenant_id: &ScopedTenant, run_id: &AgentRunId);
}

/// Dyn-safe port for the single-driver lease that makes at-least-once event
/// delivery drive a run at most once concurrently.
#[async_trait]
pub trait RunLease: Send + Sync {
    /// Attempts to claim a run for execution on this node, returning `true` if
    /// the claim was won and `false` if another node holds a live lease. The
    /// claim is a time-bounded lease: a claim whose lease has expired (its
    /// holder crashed without releasing it) is reclaimable. The driver must
    /// [`renew`](Self::renew) it while working.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the claim cannot be made or
    /// read. A caller does not drive the run then, since two drivers at once
    /// is worse than a delay, and leaves it to be tried again.
    async fn try_claim(&self, run_id: &AgentRunId) -> Result<bool, DomainError>;

    /// Extends the lease on a held claim, called between steps so a long run
    /// keeps its claim while a crashed driver's lease is left to expire.
    /// Returns `false` when this driver no longer holds the claim: its lease
    /// lapsed and another driver took the run.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the lease cannot be renewed
    /// or read. The caller stops driving then.
    async fn renew(&self, run_id: &AgentRunId) -> Result<bool, DomainError>;

    /// Releases the claim for a finished run.
    async fn release(&self, run_id: &AgentRunId);
}

/// The audience every task token for `tenant_id` names, and every verifier
/// of one requires: ianua's own agent surfaces for that tenant, and nothing
/// else. A token minted for one tenant is refused by another, and no other
/// system checking `aud` takes it for its own.
#[must_use]
pub fn task_token_audience(tenant_id: &TenantId) -> String {
    format!("ianua:{tenant_id}")
}

/// Dyn-safe port for minting a signed task token from a delegation.
///
/// The token is the credential an agent presents to the proxy. The
/// infrastructure adapter signs it with the tenant's active signing key.
#[async_trait]
pub trait TaskTokenIssuer: Send + Sync {
    /// Mints a signed task token for a delegation, naming `issuer`, the
    /// tenant's own token issuer, as its `iss`, which every reader checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when no signing key is available
    /// or signing fails.
    async fn issue(
        &self,
        tenant_id: &ScopedTenant,
        issuer: &Issuer,
        delegation: &Delegation<ResolvedTenant>,
    ) -> Result<TaskToken, DomainError>;
}

/// Reads a delegation's live request-budget usage from the counter the
/// gateway's instances share, for reporting.
///
/// `GET .../delegations` uses this to show a usage count. Enforcement never
/// reads through it: the gateway counts through [`BudgetCounter`], so this
/// being unreachable only leaves the count out of the listing.
#[async_trait]
pub trait BudgetUsageReader: Send + Sync {
    /// Requests consumed by `delegation_id` in its current window, or
    /// `None` when it has never been used or the counter isn't reachable.
    async fn current_usage(&self, delegation_id: &DelegationId) -> Option<u32>;
}

/// A per-delegation request counter every proxy instance shares.
///
/// A budget counted in one proxy's memory is really a budget *per proxy*: run
/// four and a cap of a hundred lets four hundred requests through. This is the
/// counter that makes the cap mean one thing across the fleet.
///
/// `None` means the shared counter could not answer: unreachable, slow, or
/// not configured. The gateway then refuses the agent's request with a
/// `503`: a budget it cannot count is not enforced by counting on one
/// instance, which would let a fleet of four spend four budgets.
#[async_trait]
pub trait BudgetCounter: Send + Sync {
    /// Records one use and returns the running count for the current window.
    ///
    /// The window starts at the first use and lasts `window_seconds`, matching
    /// the proxy's own fixed-window semantics. Implementations must count and
    /// set that expiry atomically: an increment whose expiry never lands
    /// leaves the delegation permanently over budget.
    async fn record_use(&self, key: &BudgetKey, window_seconds: Seconds) -> Option<u32>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A task token's debug representation contains a fixed mask instead of its value.
    #[test]
    fn debug_does_not_print_the_task_token() {
        let rendered = format!("{:?}", TaskToken::new("header.payload.signature"));

        assert_eq!(rendered, "TaskToken(***)");
    }
}

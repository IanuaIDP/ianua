//! Asking for a person's approval of an agent's action from the gateway.
//!
//! The gateway never writes approvals. It asks the API, over the sealed
//! internal channel app sign-in uses, to hold an action for a person or to
//! spend an approval a person gave, and the API does both through its own
//! use cases and records what it opened.

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentId, ApprovalId, DeclaredAction, DelegationId, HttpMethod};

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// One agent action that waits on a person's approval, as the gateway
/// judged it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatedAction {
    /// The agent attempting the action.
    pub agent_id: AgentId,
    /// The delegation it acts under: the one that requires approval.
    pub delegation_id: DelegationId,
    /// The method of the call.
    pub method: HttpMethod,
    /// The normalized path, with its query, that policy decided on.
    pub target: String,
    /// The kind of action the route declares it takes, if it declares one.
    pub declared: DeclaredAction,
}

/// What came of holding an action for a person's decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Held {
    /// The action awaits a person's decision on the named request.
    AwaitingDecision {
        /// The request a person decides.
        approval_id: ApprovalId,
        /// Whether this attempt opened the request, as opposed to finding
        /// one already open. Only a newly opened request is announced.
        opened: RequestOpened,
    },
    /// Too many requests are already open under the delegation, so none
    /// was opened.
    TooManyOpen,
}

/// Whether an attempt opened the request it waits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestOpened {
    /// This attempt opened it.
    Now,
    /// An earlier attempt did.
    Before,
}

/// What came of trying to spend an approval of an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spending {
    /// A person approved exactly this action, and the approval is now used
    /// up on it.
    Spent,
    /// No approval of exactly this action was there to spend.
    NoneGranted,
}

/// Dyn-safe port the gateway asks about approvals through. The adapter
/// relays each question to the API over the sealed internal channel.
///
/// Deny by default: whatever does not come back as an answer, an API that
/// cannot be reached in time, a refusal, an answer that does not read, is
/// an error, and the gateway refuses the action on it.
#[async_trait]
pub trait ApprovalBroker: Send + Sync + TenantScoped {
    /// Finds the request awaiting a person's decision on exactly `action`,
    /// or opens one, unless too many are open under its delegation.
    ///
    /// # Errors
    ///
    /// - `DomainError::Forbidden` when the API refused: the delegation is
    ///   not the agent's, or no longer live.
    /// - `DomainError::Infrastructure` when the API cannot be reached in
    ///   time or its answer does not read.
    async fn hold(
        &self,
        tenant_id: &ScopedTenant,
        action: &GatedAction,
    ) -> Result<Held, DomainError>;

    /// Spends an approval a person gave of exactly `action`, once: two
    /// attempts racing for it cannot both spend it.
    ///
    /// # Errors
    ///
    /// As [`hold`](Self::hold).
    async fn spend(
        &self,
        tenant_id: &ScopedTenant,
        action: &GatedAction,
    ) -> Result<Spending, DomainError>;
}

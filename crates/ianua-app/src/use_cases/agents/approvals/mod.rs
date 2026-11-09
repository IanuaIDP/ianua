//! Calls held for a person to approve.
//!
//! The gateway asks about the actions it gates through the
//! [`ApprovalBroker`](crate::ports::agents::ApprovalBroker) and writes no
//! approval itself: [`GateActionUseCase`] runs in the gateway, and the API
//! answers it through [`RelayUseCase`], [`HoldActionUseCase`] and
//! [`SpendUseCase`].

pub(in crate::use_cases::agents) mod action_authority;
pub(crate) mod approve_action;
mod decided;
pub(crate) mod deny_action;
pub(crate) mod gate_action;
mod gated;
pub(crate) mod get_facts;
pub(crate) mod hold_action;
pub(crate) mod list_pending;
pub(crate) mod list_tenant;
pub mod parties;
pub(crate) mod relay;
pub(crate) mod request;
pub(crate) mod spend;

/// How long approvals asked for by hand stay open, and how many one person
/// may give.
#[derive(Debug, Clone, Copy)]
pub struct ApprovalLimits {
    /// The longest a request opened by hand stays decidable: an approval left
    /// open for good is a standing permission nobody remembers granting.
    pub max_ttl: time::Duration,
    /// The most approvals one person may give in an hour. A person approving
    /// faster than they could have read what they approved is
    /// rubber-stamping.
    pub per_person_per_hour: u32,
}

pub use approve_action::{ApproveActionPorts, ApproveActionRequest, ApproveActionUseCase};
pub use decided::DecisionPorts;
pub use deny_action::{DenyActionPorts, DenyActionRequest, DenyActionUseCase};
pub use gate_action::{ApprovalGate, GateActionPorts, GateActionUseCase};
pub use get_facts::{
    Facts, GetFactsPorts, GetFactsRequest, GetFactsUseCase, HeldCall, RecentRecord,
};
pub use hold_action::{GatePolicy, HoldActionPorts, HoldActionUseCase};
pub use list_pending::{ListPendingPorts, ListPendingRequest, ListPendingUseCase};
pub use list_tenant::{ListTenantPorts, ListTenantUseCase};
pub use relay::{RelayPorts, RelayRequest, RelayUseCase};
pub use request::{RequestPorts, RequestRequest, RequestUseCase};
pub use spend::{SpendPorts, SpendUseCase};

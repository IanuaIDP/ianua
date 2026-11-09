//! An agent's call held for a person: opening the request and reading how
//! it was decided.

use serde::{Deserialize, Serialize};

use super::Principal;

/// `POST …/agents/{id}/approvals`: the exact call that waits, under the
/// delegation it would use, and how long a person has to decide.
#[derive(Debug, Clone, Serialize)]
pub struct OpenApproval {
    /// The delegation the call would use.
    pub delegation_id: String,
    /// Its method, such as `GET`.
    pub method: String,
    /// Its path, with its query.
    pub target: String,
    /// How long a person has to decide, in seconds.
    pub ttl_seconds: u32,
}

/// An approval request and how it stands.
#[derive(Debug, Clone, Deserialize)]
pub struct Approval {
    /// The handle used to decide or inspect the held call.
    pub id: String,
    /// The agent whose call waits.
    pub agent_id: String,
    /// The call held, as the platform names it.
    pub action: String,
    /// `pending`, `approved`, `denied`, `expired`, `consumed` or
    /// `withdrawn`.
    pub status: String,
    /// Who opened it.
    pub requested_by: Principal,
    /// Who decided it, once someone did.
    #[serde(default)]
    pub decided_by: Option<Principal>,
    /// How many different people must approve it.
    pub approvers_needed: u8,
    /// The class of action held, such as `financial`, when one was
    /// declared.
    #[serde(default)]
    pub purpose: Option<String>,
    /// Who gave the first of two approvals, while the second is awaited.
    #[serde(default)]
    pub first_approved_by: Option<Principal>,
}

/// The second factor an approver answers right then for a call two people
/// must approve. Holds a code, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct FreshCode {
    /// The code their authenticator app shows.
    pub mfa_code: String,
}

/// What an approver reads before deciding: the platform's facts about the
/// agent first, and the agent's own word about its call last.
#[derive(Debug, Clone, Deserialize)]
pub struct ApprovalFacts {
    /// The request being decided.
    pub approval: Approval,
    /// Whom the agent acts for, nearest first.
    pub on_behalf_of: Vec<Principal>,
    /// Requests and messages refused to the agent lately.
    pub recent_refusals: u64,
    /// The agent's own summary: a claim, not a fact.
    pub agent_claim: String,
}

impl Approval {
    /// Whether it still waits for a decision.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.status == "pending"
    }
}

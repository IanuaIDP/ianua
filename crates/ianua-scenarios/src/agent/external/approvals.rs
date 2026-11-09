//! An agent waiting on a person: its developer's backend opens the
//! approval for the call it means to make, and it waits for the decision.
//!
//! The API opens an approval for a person only: an agent's own call is
//! paused for one by the gateway, which waits for its start-up (gateway
//! wave 3). Until then the backend that runs the agent, signed in as the
//! person who owns it, asks in its place, as an SDK's approval hook would.

use super::ExternalAgent;
use crate::api::agents::approvals;
use crate::expect::eventually_within;
use crate::net::Client;
use crate::wire::agents::approvals::{Approval, OpenApproval};

/// How long a decision is waited for.
const DECISION_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// The call an agent means to make and wants approved: its method and
/// target, under the delegation it would use, and how long a person has.
#[derive(Debug, Clone)]
pub struct ApprovalAsk {
    /// The method, such as `GET`.
    pub method: String,
    /// The path, with its query.
    pub target: String,
    /// The delegation the call would use.
    pub delegation_id: String,
    /// How long a person has to decide, in seconds.
    pub ttl_seconds: u32,
}

impl ExternalAgent {
    /// Asks, through `backend`, for a person's approval of `ask`.
    ///
    /// # Panics
    ///
    /// When the request cannot be opened.
    pub async fn ask_approval(&self, backend: &Client, ask: &ApprovalAsk) -> Approval {
        let open = OpenApproval {
            delegation_id: ask.delegation_id.clone(),
            method: ask.method.clone(),
            target: ask.target.clone(),
            ttl_seconds: ask.ttl_seconds,
        };
        approvals::open(&self.tenant, &self.id, &open)
            .send(backend)
            .await
            .ok()
    }

    /// The approval `approval_id`, read through `backend`, once it no
    /// longer waits: approved, denied, or lapsed.
    ///
    /// # Panics
    ///
    /// When no decision comes within thirty seconds.
    pub async fn decision_on(&self, backend: &Client, approval_id: &str) -> Approval {
        let what = format!("a decision on the approval {approval_id}");
        let request = approvals::list(&self.tenant, &self.id, None);
        eventually_within(&what, DECISION_WAIT, || {
            let request = request.clone();
            async move {
                request
                    .send(backend)
                    .await
                    .ok()
                    .into_iter()
                    .find(|approval| approval.id == approval_id && !approval.is_pending())
            }
        })
        .await
    }
}

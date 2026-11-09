//! Agents watching agents: a person setting a watcher on an agent, reading
//! and ending the assignment, and the watcher at its review desk, signed
//! in by an assertion its own key signed.

use super::{ASSERTION_HEADER, of_agent};
use crate::api::{Request, TenantPath};
use crate::net::Call;
use crate::wire::agents::reviews::{AssignReviewer, EvidencePage, ReviewAssignment, Verdict};

/// The header a watcher names itself in at the review desk.
pub const AGENT_ID_HEADER: &str = "ianua-agent-id";

/// `POST …/agents/{id}/reviewers`: sets `reviewer` to watch the agent
/// `agent_id`.
#[must_use]
pub fn assign(
    tenant: &TenantPath,
    agent_id: &str,
    reviewer: &AssignReviewer,
) -> Request<ReviewAssignment> {
    Request::of(Call::post(of_agent(tenant, agent_id, "/reviewers")).json(reviewer))
}

/// `GET …/agents/{id}/reviews`: who watches the agent, ended watches
/// included.
#[must_use]
pub fn list(tenant: &TenantPath, agent_id: &str) -> Request<Vec<ReviewAssignment>> {
    Request::of(Call::get(of_agent(tenant, agent_id, "/reviews")))
}

/// `POST …/agents/{id}/reviews/{assignment}/end`: the watcher reads
/// nothing of the agent from now on.
#[must_use]
pub fn end(tenant: &TenantPath, agent_id: &str, assignment_id: &str) -> Request<()> {
    let path = of_agent(tenant, agent_id, &format!("/reviews/{assignment_id}/end"));
    Request::of(Call::post(path))
}

/// `GET …/agents/{id}/evidence`: the agent's records with their place in
/// the chain, as a person reads them.
#[must_use]
pub fn evidence(tenant: &TenantPath, agent_id: &str) -> Request<EvidencePage> {
    Request::of(Call::get(of_agent(tenant, agent_id, "/evidence")))
}

/// Who signs in at the review desk: the watcher's id and a fresh
/// assertion its key signed.
#[derive(Clone, Copy)]
pub struct Desk<'a> {
    /// The watcher's id.
    pub reviewer_id: &'a str,
    /// The assertion, spent on use.
    pub assertion: &'a str,
}

/// `GET …/agents/review-desk/{id}/evidence`: the watched agent's records,
/// read by the watcher at `desk`.
#[must_use]
pub fn desk_evidence(
    tenant: &TenantPath,
    reviewed_id: &str,
    desk: Desk<'_>,
) -> Request<EvidencePage> {
    let call = Call::get(tenant.at(&format!("/agents/review-desk/{reviewed_id}/evidence")));
    Request::of(signed_at(call, desk))
}

/// `POST …/agents/review-desk/{id}/verdicts`: the watcher at `desk`
/// gives `verdict` about the watched agent.
#[must_use]
pub fn desk_verdict(
    tenant: &TenantPath,
    reviewed_id: &str,
    desk: Desk<'_>,
    verdict: &Verdict,
) -> Request<()> {
    let call =
        Call::post(tenant.at(&format!("/agents/review-desk/{reviewed_id}/verdicts"))).json(verdict);
    Request::of(signed_at(call, desk))
}

/// `call` carrying the watcher's id and its assertion.
fn signed_at(call: Call, desk: Desk<'_>) -> Call {
    call.header(AGENT_ID_HEADER, desk.reviewer_id)
        .header(ASSERTION_HEADER, desk.assertion)
}

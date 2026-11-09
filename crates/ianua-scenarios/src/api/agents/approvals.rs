//! An agent's calls held for a person: opening a request, reading it, and
//! deciding it.

use super::of_agent;
use crate::api::{Request, TenantPath, with_query};
use crate::net::Call;
use crate::wire::agents::approvals::{Approval, ApprovalFacts, FreshCode, OpenApproval};

/// `POST …/agents/{id}/approvals`: opens a request for the call; whoever
/// opens it may not decide it.
#[must_use]
pub fn open(tenant: &TenantPath, agent_id: &str, approval: &OpenApproval) -> Request<Approval> {
    Request::of(Call::post(of_agent(tenant, agent_id, "/approvals")).json(approval))
}

/// `GET …/agents/{id}/approvals`, those in `status` when one is named.
#[must_use]
pub fn list(tenant: &TenantPath, agent_id: &str, status: Option<&str>) -> Request<Vec<Approval>> {
    let pairs: Vec<(&str, &str)> = status
        .map(|status| ("status", status))
        .into_iter()
        .collect();
    let path = with_query(&of_agent(tenant, agent_id, "/approvals"), &pairs);
    Request::of(Call::get(path))
}

/// `POST …/agents/{id}/approvals/{approval}/approve`, with no second
/// factor: enough for a call that is not high-risk.
#[must_use]
pub fn approve(tenant: &TenantPath, agent_id: &str, approval_id: &str) -> Request<Approval> {
    let path = of_agent(
        tenant,
        agent_id,
        &format!("/approvals/{approval_id}/approve"),
    );
    Request::of(Call::post(path))
}

/// The same approval answering the approver's second factor with `code`:
/// what a call two people must approve takes from each.
#[must_use]
pub fn approve_with_code(
    tenant: &TenantPath,
    agent_id: &str,
    approval_id: &str,
    code: &FreshCode,
) -> Request<Approval> {
    let path = of_agent(
        tenant,
        agent_id,
        &format!("/approvals/{approval_id}/approve"),
    );
    Request::of(Call::post(path).json(code))
}

/// `GET …/agents/{id}/approvals/{approval}/facts`: what an approver reads
/// before deciding.
#[must_use]
pub fn facts(tenant: &TenantPath, agent_id: &str, approval_id: &str) -> Request<ApprovalFacts> {
    let path = of_agent(tenant, agent_id, &format!("/approvals/{approval_id}/facts"));
    Request::of(Call::get(path))
}

/// `POST …/agents/{id}/approvals/{approval}/deny`.
#[must_use]
pub fn deny(tenant: &TenantPath, agent_id: &str, approval_id: &str) -> Request<Approval> {
    let path = of_agent(tenant, agent_id, &format!("/approvals/{approval_id}/deny"));
    Request::of(Call::post(path))
}

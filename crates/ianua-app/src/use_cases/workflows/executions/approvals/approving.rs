//! What deciding a workflow's approval step shares: finding the step, and
//! the person deciding it as the domain takes them.

use ianua_domain::domains::agents::oversight::approval::PresenceProof;
use ianua_domain::domains::authentication::mfa::enrollment::AnsweredCode;
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::workflows::control::{StepApprover, WorkflowControl};
use ianua_domain::domains::workflows::design::node::{NodeKey, NodeKind, WorkflowApprovalStep};
use ianua_domain::domains::workflows::execution::WorkflowExecution;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;

use crate::error::{AppError, OrNotFound};

/// The approval step called `key` in `execution`'s graph.
///
/// # Errors
///
/// - `AppError::NotFound` when the graph has no step called `key`, or it
///   asks for no approval.
pub(in crate::use_cases::workflows::executions) fn approval_step_of<'a>(
    execution: &'a WorkflowExecution<ResolvedTenant>,
    key: &NodeKey,
) -> Result<&'a WorkflowApprovalStep, AppError> {
    execution
        .graph()
        .node(key)
        .and_then(|node| match node.kind() {
            NodeKind::Approval(step) => Some(step),
            NodeKind::AgentRun(_)
            | NodeKind::Action(_)
            | NodeKind::Condition(_)
            | NodeKind::Transform(_)
            | NodeKind::Wait(_)
            | NodeKind::Loop(_)
            | NodeKind::Code(_)
            | NodeKind::Guardrail(_) => None,
        })
        .or_not_found(message!("workflows-approval-step", "approval step"))
}

/// The person `authority` names deciding a step, present when `answered`
/// proves it, not present otherwise.
///
/// # Errors
///
/// - `AppError::Forbidden` when `answered` is not a code from the
///   approver's own second factor.
pub(in crate::use_cases::workflows::executions) fn step_approver<'a>(
    authority: &'a TenantAuthority,
    answered: Option<&AnsweredCode>,
) -> Result<StepApprover<'a>, AppError> {
    let control = WorkflowControl::new(authority);
    let Some(code) = answered else {
        return Ok(StepApprover::of(control));
    };
    StepApprover::present(control, PresenceProof::Code(code)).map_err(AppError::from_domain)
}

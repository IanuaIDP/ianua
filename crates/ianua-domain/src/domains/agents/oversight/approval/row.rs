//! What a request is opened with and how storage keeps it, and the rules
//! it keeps when it is opened, checked again on a stored row.

use time::OffsetDateTime;

use crate::domains::agents::authority::delegation::ActingUnder;
use crate::domains::agents::oversight::approval::{
    ActionParties, ApprovalAction, ApprovalOrigin, ApprovalState, RunOrigin, StoredApprovalOrigin,
};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::types::{AgentId, ApprovalId, DeclaredAction, Seconds};

/// Parameters for opening an approval request.
pub struct RequestApprovalParams {
    /// The agent whose action is paused.
    pub agent_id: AgentId,
    /// The delegation whose authority the action uses, if any. A run calling
    /// tools directly has none.
    pub delegation_id: ActingUnder,
    /// Where the request comes from: opened by hand, or raised by a run.
    ///
    /// It is recorded so a second person must decide. Ann starts a run that
    /// pauses on a delete. If Ann could approve it, through any of her
    /// accounts, the approval would check nothing. A run's origin also names
    /// the exact call it holds. So the decision applies to the call the
    /// approver saw, not to a later one.
    pub origin: ApprovalOrigin,
    /// The agent's owner and the people behind the delegation the action
    /// uses. None of them may approve it.
    pub parties: ActionParties,
    /// The class of the action waiting for approval, when it is known. A run
    /// knows the class of the tool it paused on. A request opened by hand
    /// does not.
    pub action_class: DeclaredAction,
    /// A summary of the paused action.
    pub action: ApprovalAction,
    /// How long a person has to decide, in seconds.
    pub ttl_seconds: Seconds,
}

/// Persisted state for reconstitution.
pub struct ApprovalRequestRow {
    /// Unique identifier.
    pub id: ApprovalId,
    /// The agent whose action is paused.
    pub agent_id: AgentId,
    /// The delegation supplying the authority, if any.
    pub delegation_id: ActingUnder,
    /// Where the request came from.
    pub origin: StoredApprovalOrigin,
    /// The agent's owner and the people behind the delegation it uses.
    pub parties: ActionParties,
    /// The class of the action waiting for approval, if known.
    pub action_class: DeclaredAction,
    /// A summary of the paused action.
    pub action: ApprovalAction,
    /// Where it stands. See [`ApprovalState::from_stored`].
    pub state: ApprovalState,
    /// When it was requested.
    pub created_at: OffsetDateTime,
    /// When the time to decide runs out.
    pub expires_at: OffsetDateTime,
    /// When it was last modified.
    pub updated_at: OffsetDateTime,
}

/// Refuses a stored row that breaks a rule a request keeps.
pub(super) fn ensure_consistent(row: &ApprovalRequestRow) -> Result<(), DomainError> {
    RowCheck::of("approval request")
        .holds(
            names_its_runs_agent(row),
            "names another agent than the run that raised it",
        )
        .holds(
            row.created_at < row.expires_at,
            "closes before it was raised",
        )
        .in_order(
            row.created_at,
            row.updated_at,
            "changed before it was raised",
        )
        .holds(decided_in_order(row), "approved or decided out of order")
        .finish()?;
    ensure_parties_consistent(row)
}

/// Refuses a stored row whose approvers or parties break a rule a request
/// keeps.
fn ensure_parties_consistent(row: &ApprovalRequestRow) -> Result<(), DomainError> {
    RowCheck::of("approval request")
        .holds(
            approved_by_two(row),
            "a grant that needed two approvals without them, or both from one person",
        )
        .holds(
            not_approved_by_its_requester(row),
            "approved by its requester, the agent's owner or a delegator",
        )
        .holds(
            row.parties.fit(&row.delegation_id),
            "delegators that do not match the delegation it uses",
        )
        .holds(
            withdrawn_only_with_its_run(row),
            "withdrawn though no run raised it",
        )
        .finish()
}

/// Whether a stored request that was withdrawn was raised by a run. Only
/// stopping its run withdraws one.
fn withdrawn_only_with_its_run(row: &ApprovalRequestRow) -> bool {
    !matches!(row.state, ApprovalState::Withdrawn { .. })
        || matches!(row.origin, StoredApprovalOrigin::Run(_))
}

/// Refuses a request that names another agent than the run that raised it,
/// or another class than the tool it paused on.
///
/// The class decides how many people must approve. So the caller never
/// chooses it.
///
/// # Errors
///
/// - [`DomainError::Validation`] when the agent or the class differs from
///   the run's.
pub(super) fn ensure_fits_run(
    run: &RunOrigin,
    params: &RequestApprovalParams,
) -> Result<(), DomainError> {
    if *run.agent_id() != params.agent_id {
        return Err(DomainError::invalid(message!(
            "agents-an-approval-request-names-the-agent",
            "an approval request names the agent of the run that raised it"
        )));
    }
    if params.action_class != DeclaredAction::Declared(run.class()) {
        return Err(DomainError::invalid(message!(
            "agents-an-approval-request-takes-the-class",
            "an approval request takes the class of the call the run paused on"
        )));
    }
    Ok(())
}

/// Refuses parties that name no delegator for an action using a delegation,
/// or any for one using none.
///
/// # Errors
///
/// - [`DomainError::Validation`] when the delegators do not match the
///   delegation the action uses.
pub(super) fn ensure_parties_fit(params: &RequestApprovalParams) -> Result<(), DomainError> {
    if params.parties.fit(&params.delegation_id) {
        return Ok(());
    }
    Err(DomainError::invalid(message!(
        "agents-a-request-names-the-people-behind",
        "a request names the people behind its delegation exactly when it uses one"
    )))
}

/// Whether a stored request raised by a run names that run's agent.
fn names_its_runs_agent(row: &ApprovalRequestRow) -> bool {
    match &row.origin {
        StoredApprovalOrigin::Opened(_) => true,
        StoredApprovalOrigin::Run(run) => run.agent_id == row.agent_id,
    }
}

/// Whether a stored request's first approval came after it was raised, and
/// its decision after both.
fn decided_in_order(row: &ApprovalRequestRow) -> bool {
    let first_at = row.state.first().approval().map(|first| first.at);
    let decided_at = row.state.decision().map(|decision| decision.at());
    let last_before_decision = first_at.unwrap_or(row.created_at);
    row.created_at <= last_before_decision && decided_at.is_none_or(|at| last_before_decision <= at)
}

/// Whether a stored grant holds the approvals its class needs. One that may
/// be high-risk needs two from two people. None may have two from one
/// person, through any of their accounts.
fn approved_by_two(row: &ApprovalRequestRow) -> bool {
    let Some(granting) = row.state.approval() else {
        return true;
    };
    match row.state.first().approval() {
        Some(first) => !first.by.is_same_person_as(&granting.by),
        None => !row.action_class.may_be_high_risk(),
    }
}

/// Whether a stored request holds no approval from the person who opened it
/// or started its run, nor from the agent's owner or a delegator, through
/// any of their accounts.
fn not_approved_by_its_requester(row: &ApprovalRequestRow) -> bool {
    let requester = match &row.origin {
        StoredApprovalOrigin::Opened(opener) => opener,
        StoredApprovalOrigin::Run(run) => &run.started_by,
    };
    [row.state.first().approval(), row.state.approval()]
        .into_iter()
        .flatten()
        .all(|approval| !requester.is(&approval.by) && !row.parties.include(&approval.by))
}
